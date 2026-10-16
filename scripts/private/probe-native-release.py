"""Read a freshly compiled identity using a disposable offline native database."""
import argparse,hashlib,json,os,platform,socket,sys,time,urllib.request
from pathlib import Path
sys.dont_write_bytecode=True
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary',type=Path,required=True);p.add_argument('--genesis',type=int,required=True)
p.add_argument('--output',type=Path,required=True);p.add_argument('--guardian-dir',type=Path,required=True)
p.add_argument('--library-path');a=p.parse_args();os.umask(0o077)
sys.path.insert(0,str(a.guardian_dir.resolve(strict=True)));import guarded
run=a.output.resolve();run.mkdir(mode=0o700,exist_ok=False)
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
rpc,peer=port(),port();assert rpc!=peer
(run/'empty.conf').write_text('');env=dict(os.environ)
if a.library_path:env['LD_LIBRARY_PATH']=a.library_path
argv=[str(a.binary.resolve(strict=True)),'--config-file',str(run/'empty.conf'),'--testnet','--data-dir',str(run/'chain'),
 '--offline','--no-zmq','--no-igd','--disable-dns-checkpoints','--check-updates','disabled','--in-peers','0','--out-peers','0',
 '--hide-my-port','--p2p-bind-ip','127.0.0.1','--p2p-bind-port',str(peer),'--rpc-bind-ip','127.0.0.1','--rpc-bind-port',str(rpc),
 '--rpc-ssl','disabled','--max-concurrency','1','--prep-blocks-threads','1','--non-interactive','--log-file',str(run/'native.log'),
 '--log-level','0','--max-log-files','1','--max-log-file-size','1048576']
def call(method,params=None):
 req=urllib.request.Request(f'http://127.0.0.1:{rpc}/json_rpc',data=json.dumps({'jsonrpc':'2.0','id':'identity','method':method,'params':params or {}}).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=2) as response:return json.load(response)['result']
with (run/'process.log').open('xb') as out:
 child=guarded.Child(argv,output=out,receipt=run/'GUARD_STOPPED.json',seconds=90,env=env)
 try:
  end=time.monotonic()+45
  while True:
   assert child.poll() is None,'Native exited before identity'
   try:info=call('get_info');header=call('get_block_header_by_height',{'height':0})['block_header'];break
   except (OSError,KeyError):assert time.monotonic()<end;time.sleep(.2)
  assert info['nettype']=='testnet' and info['height']==1 and header['timestamp']==a.genesis
  result={'status':'COMPILED_V17_NATIVE_IDENTITY_PASS','genesisHash':header['hash'],'genesisUtcUnix':a.genesis,
   'nativeVersion':info['version'],'nativeSha256':hashlib.sha256(a.binary.read_bytes()).hexdigest(),
   'platform':platform.platform(),'publicLaunchApproved':False}
  (run/'NETWORK.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
 finally:
  if child.poll() is None:child.terminate()
  assert child.wait(timeout=45)==0
