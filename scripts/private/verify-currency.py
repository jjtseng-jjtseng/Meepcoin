"""Owned, bounded private regtest; fresh disposable wallets, no existing user keys."""
from pathlib import Path
import argparse,hashlib,json,os,resource,shutil,signal,socket,subprocess,time,urllib.request,uuid
parser=argparse.ArgumentParser(description='Bounded real private reward/transfer/restart smoke test; fresh disposable wallets only')
parser.add_argument('--binaries',type=Path,required=True);parser.add_argument('--run-dir',type=Path,required=True)
parser.add_argument('--library-dir',type=Path)
parser.add_argument('--adversarial',action='store_true')
parser.add_argument('--crash-restore',action='store_true')
args=parser.parse_args()
runroot=args.run_dir.resolve();runroot.mkdir(mode=0o700,parents=True,exist_ok=False)
bins=args.binaries.resolve(strict=True)
for name in ['meepcoind','meepcoin-wallet-rpc']:assert (bins/name).is_file()
env=dict(os.environ,LC_ALL='C')
if args.library_dir:env['LD_LIBRARY_PATH']=str(args.library_dir.resolve(strict=True))
children=[];logs=[];receipts=[];expected_stopped=set();started=time.monotonic();deadline=started+600
def free_port():
 with socket.socket() as sock:
  sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
daemon_port,wallet_a_port,wallet_b_port=free_port(),free_port(),free_port()
assert len({daemon_port,wallet_a_port,wallet_b_port})==3
password=uuid.uuid4().hex
os.umask(0o077)
def limits():
 os.nice(10);resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 resource.setrlimit(resource.RLIMIT_FSIZE,(128*1024**2,128*1024**2))
def stop(sig,frame):raise KeyboardInterrupt()
for sig in [signal.SIGINT,signal.SIGTERM,signal.SIGHUP,signal.SIGALRM]:signal.signal(sig,stop)
signal.alarm(600)
def rpc(port,method,params=None,timeout=120):
 body=json.dumps({'jsonrpc':'2.0','id':'private','method':method,'params':params or {}}).encode()
 req=urllib.request.Request('http://127.0.0.1:'+str(port)+'/json_rpc',data=body,headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=timeout) as r:
  raw=r.read(4*1024**2+1);assert len(raw)<=4*1024**2;result=json.loads(raw)
 if 'error' in result:raise RuntimeError(method+': '+str(result['error']))
 return result['result']
def launch(name,argv):
 log=(runroot/(name+'.log')).open('xb');logs.append(log)
 p=subprocess.Popen(argv,cwd=runroot,stdout=log,stderr=subprocess.STDOUT,env=env,start_new_session=True,preexec_fn=limits)
 children.append((name,p,argv));return p
def wait_rpc(port,method,params=None):
 until=min(deadline,time.monotonic()+60)
 while time.monotonic()<until:
  for name,p,argv in children:
   if p.poll() is not None and p.pid not in expected_stopped:raise RuntimeError(name+' exited early '+str(p.returncode))
  try:return rpc(port,method,params,timeout=3)
  except (OSError,RuntimeError):time.sleep(.5)
 raise RuntimeError('RPC not ready')
def mine(amount,address):
 assert 1<=amount<=80
 return rpc(daemon_port,'generateblocks',{'amount_of_blocks':amount,'wallet_address':address},timeout=600)

def daemon_http(path,payload):
 req=urllib.request.Request('http://127.0.0.1:'+str(daemon_port)+path,data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=30) as r:
  raw=r.read(4*1024**2+1);assert len(raw)<=4*1024**2;return json.loads(raw)

def pool_ids():return sorted(x['id_hash'] for x in daemon_http('/get_transaction_pool',{}).get('transactions',[]))
try:
 for port in [daemon_port,wallet_a_port,wallet_b_port]:
  with socket.socket() as sock:sock.bind(('127.0.0.1',port))
 cfg=runroot/'empty.conf';cfg.write_text('')
 data=runroot/'node';data.mkdir()
 argv=[str(bins/'meepcoind'),'--config-file',str(cfg),'--data-dir',str(data),
  '--regtest','--keep-fakechain','--fixed-difficulty','20','--offline','--no-zmq',
  '--disable-dns-checkpoints','--check-updates','disabled','--no-igd','--out-peers','0','--in-peers','0',
  '--rpc-bind-ip','127.0.0.1','--rpc-bind-port',str(daemon_port),'--rpc-ssl','disabled',
  '--max-concurrency','2','--prep-blocks-threads','1','--non-interactive',
  '--log-file',str(runroot/'daemon-internal.log'),'--log-level','0','--max-log-files','1','--max-log-file-size','8388608']
 launch('daemon',argv);wait_rpc(daemon_port,'get_info')
 for name,port in [('wallet-a',wallet_a_port),('wallet-b',wallet_b_port)]:
  d=runroot/name;d.mkdir()
  ring=runroot/(name+'-ringdb');ring.mkdir()
  launch(name,[str(bins/'meepcoin-wallet-rpc'),'--config-file',str(cfg),'--wallet-dir',str(d),
   '--shared-ringdb-dir',str(ring),'--daemon-address','127.0.0.1:'+str(daemon_port),'--trusted-daemon',
   '--no-dns','--daemon-ssl','disabled','--rpc-bind-ip','127.0.0.1','--rpc-bind-port',str(port),
   '--rpc-ssl','disabled','--disable-rpc-login','--non-interactive','--max-concurrency','1',
   '--log-file',str(runroot/(name+'-internal.log')),'--log-level','0'])
  wait_rpc(port,'get_version')
  rpc(port,'create_wallet',{'filename':'disposable','password':password,'language':'English'},timeout=90)
 a=rpc(wallet_a_port,'get_address')['address'];b=rpc(wallet_b_port,'get_address')['address']
 mine(4,a)
 info=rpc(daemon_port,'get_info')
 # Native-generated coinbase rewards must be visible while still immature.
 rpc(wallet_a_port,'refresh')
 before=rpc(wallet_a_port,'get_balance')
 transfers=rpc(wallet_a_port,'get_transfers',{'in':True})['in']
 assert any(t['height']>=3 and t['type']=='block' for t in transfers),'coinbase absent'
 coinbase_credit={'balance':before['balance'],'unlocked':before['unlocked_balance'],
  'immatureObserved':before['balance']>before['unlocked_balance']}
 assert coinbase_credit['immatureObserved']
 adversarial=[]
 def rejected(label,params):
  old=rpc(wallet_a_port,'get_balance')
  old_pool=pool_ids()
  try:rpc(wallet_a_port,'transfer',params);raise AssertionError(label+' unexpectedly accepted')
  except RuntimeError as error:reason=str(error)
  assert rpc(wallet_a_port,'get_balance')==old,'Rejected transfer altered wallet state'
  assert pool_ids()==old_pool,'Rejected transfer altered daemon pool'
  row={'label':label,'rejection':reason,'balanceUnchanged':True,'poolUnchanged':True};adversarial.append(row)
 if args.adversarial:
  rejected('immature-funds',{'destinations':[{'amount':100000000000,'address':b}]})
 mine(60,a)
 for port in [wallet_a_port,wallet_b_port]:rpc(port,'refresh')
 a0=rpc(wallet_a_port,'get_balance');b0=rpc(wallet_b_port,'get_balance')
 assert a0['unlocked_balance']>=100000000000
 if args.adversarial:
  for label,destination in [
   ('invalid-address',{'amount':1,'address':'not-a-meep-address'}),
   ('checksum-corruption',{'amount':1,'address':b[:-1]+('1' if b[-1]!='1' else '2')}),
   ('zero-amount',{'amount':0,'address':b}),
   ('insufficient-funds',{'amount':a0['balance']+100000000000,'address':b}),
   ('negative-amount',{'amount':-1,'address':b}),
   ('fractional-atomic',{'amount':0.5,'address':b}),
   ('overflow-amount',{'amount':18446744073709551616,'address':b})]:
   rejected(label,{'destinations':[destination],'ring_size':16})
  # Exercise native URI decimal parsing, which shares user-visible amount semantics.
  for amount,expected in [('0.00000000001',1),('1.00000000000',100000000000)]:
   uri=rpc(wallet_a_port,'make_uri',{'address':b,'amount':expected})['uri']
   assert uri.startswith('meepcoin:')
   assert rpc(wallet_a_port,'parse_uri',{'uri':uri})['uri']['amount']==expected
  for amount in ['1.000000000001','-1','184467440.73709551616']:
   uri='meepcoin:'+b+'?tx_amount='+amount
   try:rpc(wallet_a_port,'parse_uri',{'uri':uri});raise AssertionError('Invalid decimal URI accepted')
   except RuntimeError as error:adversarial.append({'label':'invalid-uri-'+amount,'rejection':str(error)})
 h0=rpc(daemon_port,'get_info')['height']
 tx=rpc(wallet_a_port,'transfer',{'destinations':[{'amount':100000000000,'address':b}],
  'account_index':0,'priority':0,'ring_size':16,'get_tx_key':False,'get_tx_hex':args.adversarial})
 assert tx['amount']==100000000000 and tx['fee']>0
 duplicate=[]
 if args.adversarial:
  assert pool_ids()==[tx['tx_hash']]
  for repeat in range(2):
   reply=daemon_http('/send_raw_transaction',{'tx_as_hex':tx['tx_blob'],'do_not_relay':False})
   assert pool_ids()==[tx['tx_hash']],'Duplicate relay changed pool cardinality'
   duplicate.append({'stage':'pool','reply':reply,'singlePoolEntry':True})
 mine(12,a)
 for port in [wallet_a_port,wallet_b_port]:rpc(port,'refresh')
 a1=rpc(wallet_a_port,'get_balance');b1=rpc(wallet_b_port,'get_balance')
 h1=rpc(daemon_port,'get_info')['height']
 rewards=sum(rpc(daemon_port,'get_block_header_by_height',{'height':h})['block_header']['reward'] for h in range(h0,h1))
 incoming=rpc(wallet_b_port,'get_transfer_by_txid',{'txid':tx['tx_hash']})['transfer']
 assert b1['balance']-b0['balance']==100000000000
 assert a1['balance']-a0['balance']==rewards-tx['amount']-tx['fee']
 assert incoming['confirmations']>=10
 if args.adversarial:
  assert pool_ids()==[]
  reply=daemon_http('/send_raw_transaction',{'tx_as_hex':tx['tx_blob'],'do_not_relay':False})
  rpc(wallet_b_port,'refresh');assert rpc(wallet_b_port,'get_balance')==b1
  assert pool_ids()==[],'Confirmed duplicate reentered pool'
  duplicate.append({'stage':'confirmed','reply':reply,'noDuplicateCredit':True,'emptyPool':True})
 # Wallet reopen plus rescan uses fresh test keys only; no seed material is exported.
 for port in [wallet_a_port,wallet_b_port]:
  rpc(port,'store');rpc(port,'close_wallet')
  rpc(port,'open_wallet',{'filename':'disposable','password':password});rpc(port,'refresh')
 assert rpc(wallet_a_port,'get_balance')['balance']==a1['balance']
 assert rpc(wallet_b_port,'get_balance')['balance']==b1['balance']
 rpc(wallet_b_port,'rescan_blockchain');rpc(wallet_b_port,'refresh')
 assert rpc(wallet_b_port,'get_balance')['balance']==b1['balance']
 # Restart the real daemon on the same database, not just a wallet cache.
 old_top=rpc(daemon_port,'get_last_block_header')['block_header']
 name,p,argv=children[0];os.killpg(p.pid,signal.SIGTERM);assert p.wait(timeout=20)==0
 expected_stopped.add(p.pid);launch('daemon-restarted',argv);wait_rpc(daemon_port,'get_info')
 new_top=rpc(daemon_port,'get_last_block_header')['block_header'];assert new_top['hash']==old_top['hash'] and new_top['height']==old_top['height']
 for port,expected in [(wallet_a_port,a1['balance']),(wallet_b_port,b1['balance'])]:
  rpc(port,'refresh');assert rpc(port,'get_balance')['balance']==expected
 recovery=None
 if args.crash_restore:
  # Only the newly created test daemon is killed. Existing machine services are not involved.
  name,p,daemon_argv=children[-1];assert name=='daemon-restarted'
  crash_top=rpc(daemon_port,'get_last_block_header')['block_header']
  os.killpg(p.pid,signal.SIGKILL);assert p.wait(timeout=10)==-signal.SIGKILL;expected_stopped.add(p.pid)
  launch('daemon-after-crash',daemon_argv);wait_rpc(daemon_port,'get_info')
  assert rpc(daemon_port,'get_last_block_header')['block_header']['hash']==crash_top['hash']
  for port,expected in [(wallet_a_port,a1['balance']),(wallet_b_port,b1['balance'])]:
   rpc(port,'refresh');assert rpc(port,'get_balance')['balance']==expected
  _,p,_=children[-1];os.killpg(p.pid,signal.SIGTERM);assert p.wait(timeout=20)==0;expected_stopped.add(p.pid)
  # Consistent cold database copy and an actual restart from its separate restored directory.
  backup=runroot/'database-backup';restored=runroot/'database-restored'
  shutil.copytree(data,backup);shutil.copytree(backup,restored)
  restore_argv=list(daemon_argv);restore_argv[restore_argv.index('--data-dir')+1]=str(restored)
  launch('daemon-from-restored-backup',restore_argv);wait_rpc(daemon_port,'get_info')
  assert rpc(daemon_port,'get_last_block_header')['block_header']['hash']==crash_top['hash']
  for port,expected in [(wallet_a_port,a1['balance']),(wallet_b_port,b1['balance'])]:
   rpc(port,'rescan_blockchain');rpc(port,'refresh');assert rpc(port,'get_balance')['balance']==expected
  recovery={'ownedDaemonSigkillRestart':True,'coldDatabaseCopyRestore':True,'canonicalHash':crash_top['hash'],'walletRescansExact':True}
 result={'status':'PRIVATE_NATIVE_CURRENCY_PASS','coinbaseCredit':coinbase_credit,
  'height':h1,'amountAtomic':tx['amount'],'feeAtomic':tx['fee'],'txHash':tx['tx_hash'],
  'confirmations':incoming['confirmations'],'senderBefore':a0['balance'],'senderAfter':a1['balance'],
  'recipientBefore':b0['balance'],'recipientAfter':b1['balance'],'confirmationRewards':rewards,
  'exactSenderAccounting':True,'exactRecipientAccounting':True,'walletReopen':True,'recipientRescan':True,'daemonRestartPreservedChainAndBalances':True,
  'adversarialCases':adversarial,'duplicateRelay':duplicate,'crashRestore':recovery,
  'limits':['Private fixed difficulty 20','No fresh-genesis or natural-difficulty launch policy claim','Fresh disposable wallet keys remain in the private run directory; no keys exported']}
 (runroot/'RESULT.json').open('x').write(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
finally:
 signal.alarm(0)
 for name,p,argv in reversed(children):
  if p.poll() is None:
   os.killpg(p.pid,signal.SIGTERM)
   try:p.wait(timeout=20)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
  try:os.killpg(p.pid,0);empty=False
  except ProcessLookupError:empty=True
  receipts.append({'name':name,'pid':p.pid,'exitCode':p.returncode,'ownedGroupEmpty':empty})
 for log in logs:log.close()
 (runroot/'CLEANUP.json').open('x').write(json.dumps({'processes':receipts,'elapsedSeconds':time.monotonic()-started},indent=2)+'\n')
 assert all(x['ownedGroupEmpty'] for x in receipts),'owned process cleanup incomplete'
