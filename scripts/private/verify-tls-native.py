"""Fresh owned native daemon/wallet and TLS service end-to-end qualification."""
import argparse,json,os,resource,signal,socket,subprocess,threading,time,urllib.request,uuid
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--binaries',type=Path,required=True);p.add_argument('--source',type=Path,required=True)
p.add_argument('--run-dir',type=Path,required=True);a=p.parse_args()
root=a.run_dir.resolve();root.mkdir(mode=0o700,parents=True,exist_ok=False);os.umask(0o077)
bins=a.binaries.resolve(strict=True);source=a.source.resolve(strict=True);children=[];logs=[];receipts=[];started=time.monotonic()
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
daemon,wallet=port(),port();assert daemon!=wallet
password=uuid.uuid4().hex
def limits(node=False):
 os.nice(10);cap=(128 if node else 2)*1024**3
 resource.setrlimit(resource.RLIMIT_AS,(cap,cap));resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(128*1024**2,128*1024**2))
def launch(name,argv,node=False):
 log=(root/(name+'.log')).open('xb');logs.append(log)
 proc=subprocess.Popen(argv,cwd=root,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,preexec_fn=lambda:limits(node))
 children.append((name,proc));return proc
def rpc(port,method,params=None):
 body=json.dumps({'jsonrpc':'2.0','id':'tls','method':method,'params':params or {}}).encode()
 with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:'+str(port)+'/json_rpc',data=body,headers={'Content-Type':'application/json'}),timeout=10) as r:
  raw=r.read(1024**2+1);assert len(raw)<=1024**2;data=json.loads(raw)
 assert 'error' not in data,(method,data);return data['result']
def ready(port,method):
 end=time.monotonic()+45
 while time.monotonic()<end:
  assert all(proc.poll() is None for _,proc in children),'Owned child exited early'
  try:return rpc(port,method)
  except (OSError,AssertionError):time.sleep(.2)
 raise AssertionError('RPC deadline')
def stop(sig,frame):raise KeyboardInterrupt()
for sig in [signal.SIGINT,signal.SIGTERM,signal.SIGHUP,signal.SIGALRM]:signal.signal(sig,stop)
signal.alarm(300)
try:
 cfg=root/'empty.conf';cfg.write_text('');data=root/'node';data.mkdir();wallets=root/'wallets';wallets.mkdir()
 launch('daemon',[str(bins/'meepcoind'),'--config-file',str(cfg),'--data-dir',str(data),'--regtest','--keep-fakechain',
  '--fixed-difficulty','20','--offline','--no-zmq','--disable-dns-checkpoints','--check-updates','disabled','--no-igd',
  '--out-peers','0','--in-peers','0','--rpc-bind-ip','127.0.0.1','--rpc-bind-port',str(daemon),'--rpc-ssl','disabled',
  '--max-concurrency','2','--prep-blocks-threads','1','--non-interactive','--log-file',str(root/'daemon-internal.log'),'--log-level','0'])
 info=ready(daemon,'get_info');genesis=rpc(daemon,'get_block_header_by_height',{'height':0})['block_header']['hash']
 launch('wallet',[str(bins/'meepcoin-wallet-rpc'),'--config-file',str(cfg),'--wallet-dir',str(wallets),
  '--shared-ringdb-dir',str(root/'ringdb'),'--daemon-address','127.0.0.1:'+str(daemon),'--trusted-daemon',
  '--no-dns','--daemon-ssl','disabled','--rpc-bind-ip','127.0.0.1','--rpc-bind-port',str(wallet),'--rpc-ssl','disabled',
  '--disable-rpc-login','--non-interactive','--max-concurrency','1','--log-file',str(root/'wallet-internal.log'),'--log-level','0'])
 ready(wallet,'get_version');addresses=[]
 for name in ['a','b']:
  rpc(wallet,'create_wallet',{'filename':name,'password':password,'language':'English'});addresses.append(rpc(wallet,'get_address')['address']);rpc(wallet,'close_wallet')
 key=root/'key.pem';cert=root/'cert.pem'
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],
  check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
 config={'endpoint':'http://127.0.0.1:'+str(daemon)+'/json_rpc','nativeHash':str(bins/'meepow-v2-hash'),
  'dataDirectory':str(data),'genesisHash':genesis,'version':info['version'],'keyFile':str(key),'certFile':str(cert),'addresses':addresses,'output':str(root/'TLS.json')}
 configpath=root/'tls-config.json';configpath.write_text(json.dumps(config))
 node=launch('tls-service',[str(bins/'node'),'--max-old-space-size=256',str(source/'scripts/private/verify-tls-native.mjs'),str(configpath)],True)
 end=time.monotonic()+180;peak=0
 while node.poll() is None and time.monotonic()<end:
  rss=0
  for path in Path('/proc').iterdir():
   if not path.name.isdigit():continue
   try:
    text=(path/'stat').read_text();fields=text[text.rfind(')')+2:].split()
    if int(fields[2])==node.pid:rss+=next((int(x.split()[1])*1024 for x in (path/'status').read_text().splitlines() if x.startswith('VmRSS:')),0)
   except (OSError,ValueError):pass
  peak=max(peak,rss);assert rss<=768*1024**2,'Owned Node group RSS budget exceeded';time.sleep(.1)
 assert node.poll()==0,'TLS end-to-end failed or deadline'
 headers=[rpc(daemon,'get_block_header_by_height',{'height':h,'fill_pow_hash':True})['block_header'] for h in [1,2]]
 tlsresult=json.loads((root/'TLS.json').read_text());assert rpc(daemon,'get_info')['height']==3
 balances=[]
 for i,name in enumerate(['a','b']):
  rpc(wallet,'open_wallet',{'filename':name,'password':password});rpc(wallet,'refresh');balance=rpc(wallet,'get_balance')
  assert balance['balance']==headers[i]['reward'] and balance['unlocked_balance']==0
  rpc(wallet,'close_wallet');balances.append({'session':i,'balanceAtomic':balance['balance'],'unlockedAtomic':0})
 for h,row in zip(headers,tlsresult['rows']):
  assert h['pow_hash']==row['hash'] and h['difficulty']==20 and not h['orphan_status']
  assert int.from_bytes(bytes.fromhex(h['pow_hash']),'little')*20<2**256
 result={**tlsresult,'headers':headers,'walletBalances':balances,'exactDirectRewardAccounting':True,'peakOwnedNodeGroupRssBytes':peak,'virtualAddressLimitGiB':128,'rssLimitMiB':768}
 (root/'RESULT.json').open('x').write(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'blocks':2}),flush=True)
finally:
 signal.alarm(0)
 for name,proc in reversed(children):
  if proc.poll() is None:
   os.killpg(proc.pid,signal.SIGTERM)
   try:proc.wait(timeout=20)
   except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=10)
  try:os.killpg(proc.pid,0);empty=False
  except ProcessLookupError:empty=True
  receipts.append({'name':name,'pid':proc.pid,'exitCode':proc.returncode,'ownedGroupEmpty':empty})
 for log in logs:log.close()
 (root/'CLEANUP.json').open('x').write(json.dumps({'processes':receipts,'elapsedSeconds':time.monotonic()-started},indent=2)+'\n')
 assert all(x['ownedGroupEmpty'] for x in receipts),'Owned group cleanup failed'
