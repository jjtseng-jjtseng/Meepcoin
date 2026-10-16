"""Finite actual-native faults. --scratch must be a private <=32 MiB filesystem.

Run in a service-private 16 MiB tmpfs, never against a host data filesystem.
All wallets, chain data, filler and corrupted copies are disposable test data.
"""
import argparse,errno,hashlib,json,os,secrets,shutil,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
import companion as c
import guarded

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--release',type=Path,required=True);p.add_argument('--run-dir',type=Path,required=True)
 p.add_argument('--scratch',type=Path,required=True);a=p.parse_args();os.umask(0o077)
 run=a.run_dir.resolve();run.mkdir(mode=0o700,exist_ok=False)
 scratch=a.scratch.resolve();scratch.mkdir(mode=0o700,exist_ok=False)
 fs=os.statvfs(scratch);assert 8*1024**2<=fs.f_blocks*fs.f_frsize<=32*1024**2
 assert os.stat(scratch).st_dev!=os.stat(run).st_dev,'Private capped filesystem required'
 children=[];logs=[];rows=[];ports=[c.free_port(),c.free_port()];assert len(set(ports))==2
 empty=run/'empty.conf';empty.write_text('');wallet_dir=scratch/'wallets';wallet_dir.mkdir(mode=0o700)
 def start(name,argv):
  out=(run/(name+'.log')).open('xb');logs.append(out)
  child=guarded.Child(argv,output=out,receipt=run/(name+'-GUARD_STOPPED.json'),seconds=600)
  children.append(child);return child
 def until(fn,seconds=45):
  end=time.monotonic()+seconds
  while time.monotonic()<end:
   assert all(child.poll() is None for child in children),'Owned child exited'
   try:return fn()
   except c.WalletError:time.sleep(.2)
  raise AssertionError('Native checkpoint expired')
 node=c.RPC(ports[0]);native_wallet=c.RPC(ports[1]);filler=scratch/'owned-filler'
 def fill():
  assert not filler.exists();count=0
  with filler.open('xb') as out:
   while True:
    try:out.write(bytes(65536));out.flush();os.fsync(out.fileno());count+=65536
    except OSError as error:
     assert error.errno==errno.ENOSPC;break
  assert os.statvfs(scratch).f_bavail*fs.f_frsize<65536
  return count
 def unfill():
  assert filler.parent==scratch and not filler.is_symlink();filler.unlink()
 def node_argv(data):return [str(a.release/'bin/meepcoind'),'--config-file',str(empty),'--data-dir',str(data),
  '--regtest','--keep-fakechain','--fixed-difficulty','20','--offline','--no-zmq','--no-igd','--disable-dns-checkpoints',
  '--check-updates','disabled','--out-peers','0','--in-peers','0','--rpc-bind-ip','127.0.0.1','--rpc-bind-port',str(ports[0]),
  '--rpc-ssl','disabled','--max-concurrency','1','--non-interactive','--log-file',str(run/'native.log'),'--log-level','0']
 try:
  node_child=start('node',node_argv(run/'chain'));until(lambda:node('get_info'))
  genesis=node('get_block_header_by_height',{'height':0})['block_header']['hash']
  wallet_child=start('wallet',[str(a.release/'bin/meepcoin-wallet-rpc'),'--config-file',str(empty),'--wallet-dir',str(wallet_dir),
   '--shared-ringdb-dir',str(run/'ringdb'),'--daemon-address','127.0.0.1:'+str(ports[0]),'--daemon-ssl','disabled',
   '--trusted-daemon','--rpc-bind-ip','127.0.0.1','--rpc-bind-port',str(ports[1]),'--rpc-ssl','disabled','--disable-rpc-login',
   '--no-dns','--non-interactive','--max-concurrency','1','--log-file',str(run/'wallet.log'),'--log-level','0'])
  until(lambda:native_wallet('get_version'));password=secrets.token_urlsafe(32)
  wallet=c.Wallet(native_wallet,node,wallet_dir,genesis,'regtest')
  native_wallet('create_wallet',{'filename':'receiver','password':password,'language':'English'})
  recipient=native_wallet('get_address')['address'];native_wallet('close_wallet')
  native_wallet('create_wallet',{'filename':'sender','password':password,'language':'English'})
  sender=native_wallet('get_address')['address']
  node('generateblocks',{'amount_of_blocks':63,'wallet_address':sender});native_wallet('refresh')
  wallet.open_name='sender';wallet.backed_up=True
  quote=wallet.operate('prepare',{'address':recipient,'amount':'1'});filled=fill()
  try:wallet.operate('confirm',{'id':quote['id']});raise AssertionError('Full journal permitted relay')
  except OSError as error:assert error.errno==errno.ENOSPC
  assert node('get_transactions',{'txs_hashes':[quote['txHash']],'prune':True}).get('missed_tx')==[quote['txHash']]
  rows.append({'case':'real_ENOSPC_before_relay','fillerBytes':filled,'transactionAbsentFromNode':True,'relayAttempted':False})
  unfill()
  quote=wallet.operate('prepare',{'address':recipient,'amount':'1'});calls=[]
  def lost_response(method,params=None):
   result=native_wallet(method,params)
   if method=='relay_tx':calls.append(result['tx_hash']);raise c.WalletError('Injected lost response after actual native relay',503)
   return result
  wallet.rpc=lost_response;assert wallet.operate('confirm',{'id':quote['id']})['status']=='unknown'
  # Recreate the companion state machine using the same encrypted files and a
  # durable pre-relay journal. No signed metadata is retained or retried.
  restarted=c.Wallet(native_wallet,node,wallet_dir,genesis,'regtest');restarted.open_name='sender';restarted.backed_up=True
  assert restarted.send_record()['observed'] is False
  try:restarted.operate('prepare',{'address':recipient,'amount':'1'});raise AssertionError('Unknown send was repeatable')
  except c.WalletError as error:assert error.status==409
  restarted.operate('refresh',{});assert restarted.send_record()['observed'] is True
  assert restarted.send_record()['txHash']==quote['txHash'] and calls==[quote['txHash']]
  node('generateblocks',{'amount_of_blocks':12,'wallet_address':sender});restarted.operate('refresh',{})
  lookup=node('get_transactions',{'txs_hashes':[quote['txHash']],'prune':True})['txs'][0]
  assert lookup['in_pool'] is False
  block=node('get_block',{'height':lookup['block_height']});assert quote['txHash'] in json.loads(block['json'])['tx_hashes']
  rows.append({'case':'actual_relay_lost_response_and_companion_reconstruction','txHash':quote['txHash'],
               'relayCalls':1,'repeatBeforeReconcileRefused':True,'exactPoolThenCanonicalEvidence':True})
  wallet_child.terminate();wallet_child.wait(timeout=45);node_child.terminate();node_child.wait(timeout=45)
  original=next((run/'chain').rglob('data.mdb'));original_hash=hashlib.sha256(original.read_bytes()).hexdigest()
  corrupt=run/'corrupt-chain';shutil.copytree(run/'chain',corrupt);copy=corrupt/original.relative_to(run/'chain')
  with copy.open('r+b') as stream:stream.truncate(256)
  changed=hashlib.sha256(copy.read_bytes()).hexdigest();bad=start('corrupt-node',node_argv(corrupt))
  assert bad.wait(timeout=30)!=0,'Truncated copied LMDB was accepted'
  assert hashlib.sha256(original.read_bytes()).hexdigest()==original_hash
  assert copy.stat().st_size==256 and hashlib.sha256(copy.read_bytes()).hexdigest()==changed
  rows.append({'case':'truncated_copied_LMDB_refused','originalDatabaseSha256':original_hash,'originalUnchanged':True,'corruptCopyUnchanged':True})
  (run/'RESULT.json').write_text(json.dumps({'status':'ACTUAL_NATIVE_STORAGE_AND_SEND_FAULT_PASS','scope':'private capped tmpfs; offline fixed20 fixture only','cases':rows},indent=2)+'\n')
  print('ACTUAL_NATIVE_STORAGE_AND_SEND_FAULT_PASS',flush=True)
 finally:
  for child in reversed(children):
   if child.poll() is None:child.terminate()
   child.wait(timeout=45)
  for out in logs:out.close()
  (run/'CLEANUP.json').write_text(json.dumps({'ownedControllersExited':all(child.poll() is not None for child in children),
   'guardReceipts':[json.loads(path.read_text()) for path in run.glob('*GUARD_STOPPED.json')]},indent=2)+'\n')
if __name__=='__main__':main()
