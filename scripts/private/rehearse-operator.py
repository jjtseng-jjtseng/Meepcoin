#!/usr/bin/env python3
"""Real operator CLI rehearsal on fresh loopback v17 peers; no public exposure."""
import argparse,base64,hashlib,json,os,resource,shutil,signal,socket,ssl,subprocess,time,urllib.error,urllib.request,uuid
from pathlib import Path

p=argparse.ArgumentParser(description=__doc__)
for name in ['build','source','node','run-dir']:p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--duration-seconds',type=int,default=180)
a=p.parse_args();assert 60<=a.duration_seconds<=3600
root=a.run_dir.resolve();root.mkdir(mode=0o700,parents=True,exist_ok=False);os.umask(0o077)
build=a.build.resolve(strict=True);source=a.source.resolve(strict=True);bins=build/'build/bin'
children=[];logs=[];stopped=set();observations=[];began=time.monotonic();service=None;peak=0

def save(name,value):
 (root/name).write_text(json.dumps(value,indent=2)+'\n')

def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

ports=[port() for _ in range(6)];assert len(set(ports))==6
rpcports=ports[:2];p2p=ports[2:4];walletport,tlsport=ports[4:];origin='https://localhost:'+str(tlsport)

def limits(node=False):
 os.nice(10);resource.setrlimit(resource.RLIMIT_AS,((128 if node else 2)*1024**3,)*2)
 resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(128*1024**2,)*2)

def launch(name,argv,node=False):
 log=(root/(name+'.log')).open('xb');logs.append(log)
 child=subprocess.Popen(argv,cwd=root,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,preexec_fn=lambda:limits(node))
 children.append((name,child,argv));return child

def stop(child):
 if child.poll() is None:
  os.killpg(child.pid,signal.SIGTERM)
  try:child.wait(timeout=20)
  except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=10)
 stopped.add(child.pid)

def rpc(port,method,params=None):
 body=json.dumps({'jsonrpc':'2.0','id':'operator','method':method,'params':params or {}}).encode()
 with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:'+str(port)+'/json_rpc',data=body,headers={'Content-Type':'application/json'}),timeout=15) as response:
  data=json.loads(response.read(1024**2))
 if 'error' in data:raise RuntimeError(str(data['error']))
 return data['result']

def until(fn,seconds=60):
 deadline=time.monotonic()+seconds;last=None
 while time.monotonic()<deadline:
  assert all(c.poll() is None or c.pid in stopped for _,c,_ in children),'Owned child exited unexpectedly'
  try:
   result=fn()
   if result:return result
  except (OSError,RuntimeError) as error:last=error
  sample();time.sleep(.2)
 raise AssertionError('Checkpoint deadline: '+str(last))

def sample():
 global peak
 if not service or service.poll() is not None:return
 rss=0
 for entry in Path('/proc').iterdir():
  if not entry.name.isdigit():continue
  try:
   text=(entry/'stat').read_text();fields=text[text.rfind(')')+2:].split()
   if int(fields[2])==service.pid:rss+=next((int(x.split()[1])*1024 for x in (entry/'status').read_text().splitlines() if x.startswith('VmRSS:')),0)
  except (OSError,ValueError):pass
 peak=max(peak,rss);assert rss<1024**3,'Owned service group exceeded 1GiB RSS'

def interrupt(*_):raise KeyboardInterrupt()
for sig in [signal.SIGTERM,signal.SIGINT,signal.SIGHUP,signal.SIGALRM]:signal.signal(sig,interrupt)
signal.alarm(a.duration_seconds+240)
try:
 clock=subprocess.check_output(['timedatectl','show','-p','NTPSynchronized','--value'],text=True,timeout=5).strip()
 assert clock=='yes','Synchronized wall clock required'
 cfg=root/'empty.conf';cfg.write_text('');nodes=[];node_args=[]
 for i in range(2):
  data=root/('node-'+str(i));data.mkdir()
  argv=[str(bins/'meepcoind'),'--config-file',str(cfg),'--testnet','--data-dir',str(data),'--no-zmq','--disable-dns-checkpoints','--check-updates','disabled','--no-igd','--out-peers','1','--in-peers','2','--allow-local-ip','--hide-my-port','--p2p-bind-ip','127.0.0.1','--p2p-bind-port',str(p2p[i]),'--add-exclusive-node','127.0.0.1:'+str(p2p[1-i]),'--rpc-bind-ip','127.0.0.1','--rpc-bind-port',str(rpcports[i]),'--rpc-ssl','disabled','--max-concurrency','1','--prep-blocks-threads','1','--non-interactive','--log-file',str(root/('node-'+str(i)+'-internal.log')),'--log-level','0']
  node_args.append(argv);nodes.append(launch('node-'+str(i),argv));until(lambda:rpc(rpcports[i],'get_info').get('status')=='OK')
 info=rpc(rpcports[0],'get_info');genesis=rpc(rpcports[0],'get_block_header_by_height',{'height':0})['block_header']
 pinned=json.loads((build/'CANDIDATE_NETWORK.json').read_text());assert genesis['timestamp']==pinned['genesisUtcUnix']
 assert info['nettype']=='testnet' and rpc(rpcports[1],'get_block_header_by_height',{'height':0})['block_header']['hash']==genesis['hash']
 walletdir=root/'wallet';walletdir.mkdir()
 wallet=launch('wallet',[str(bins/'meepcoin-wallet-rpc'),'--config-file',str(cfg),'--testnet','--wallet-dir',str(walletdir),'--shared-ringdb-dir',str(root/'rings'),'--daemon-address','127.0.0.1:'+str(rpcports[0]),'--trusted-daemon','--no-dns','--daemon-ssl','disabled','--rpc-bind-ip','127.0.0.1','--rpc-bind-port',str(walletport),'--rpc-ssl','disabled','--disable-rpc-login','--non-interactive','--max-concurrency','1','--log-file',str(root/'wallet-internal.log'),'--log-level','0'])
 until(lambda:rpc(walletport,'get_version'))
 rpc(walletport,'create_wallet',{'filename':'disposable','password':uuid.uuid4().hex,'language':'English'})
 address=rpc(walletport,'get_address')['address']
 key=root/'tls.key';cert=root/'tls.crt'
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
 public=subprocess.check_output(['openssl','x509','-in',str(cert),'-pubkey','-noout'])
 der=subprocess.check_output(['openssl','pkey','-pubin','-outform','DER'],input=public)
 spki=base64.b64encode(hashlib.sha256(der).digest()).decode()
 config=root/'service.json'
 generated=subprocess.run([str(a.node),str(source/'pool/private/configure_testnet.mjs'),'--out',str(config),'--origin',origin,'--endpoint','http://127.0.0.1:'+str(rpcports[0])+'/json_rpc','--genesis',genesis['hash'],'--genesis-utc',str(genesis['timestamp']),'--duration-seconds',str(a.duration_seconds),'--version',info['version'],'--key',str(key),'--cert',str(cert),'--data',str(root/'node-0'),'--native',str(build/'pow-build/meepow-v2-hash'),'--port',str(tlsport),'--contact','Local rehearsal only: isolated operator fixture','--address',address],check=True,capture_output=True,text=True,timeout=15)
 saved=json.loads(config.read_text());epoch=dict(saved['experiment']);token=saved['sessions'][0]['token'];assert token not in generated.stdout
 assert config.stat().st_mode&0o077==0 and Path(str(config)+'.invitations.json').stat().st_mode&0o077==0
 context=ssl.create_default_context(cafile=str(cert))
 def request(path,method='GET',data=None,capability=None):
  body=None if data is None else json.dumps(data).encode()
  req=urllib.request.Request(origin+path,data=body,method=method,headers={'Origin':origin,'X-Meep-Session':capability or token,**({'Content-Type':'application/json'} if body is not None else {})})
  try:
   with urllib.request.urlopen(req,context=context,timeout=20) as response:return response.status,json.loads(response.read(1024**2))
  except urllib.error.HTTPError as error:return error.code,json.loads(error.read(1024**2))
 service=launch('service',[str(a.node),'--max-old-space-size=256',str(source/'pool/private/testnet_service.mjs'),str(config)],True)
 until(lambda:request('/readyz')[0]==200)
 stop(nodes[0]);assert nodes[0].returncode==0
 outage=request('/readyz');refused=request('/api/start','POST',{})
 assert outage[0]==503 and refused[0]==503 and refused[1]['error']=='daemon_unavailable'
 nodes[0]=launch('node-recovered',node_args[0]);until(lambda:request('/readyz')[0]==200)
 assert json.loads(config.read_text())['experiment']==epoch
 old=token;os.killpg(service.pid,signal.SIGHUP)
 until(lambda:json.loads(config.read_text())['sessions'][0]['token']!=old)
 saved=json.loads(config.read_text());token=saved['sessions'][0]['token'];assert saved['experiment']==epoch
 assert request('/api/status',capability=old)[0]==403
 assert request('/api/status')[1]['running'] is False
 save('PRE_BROWSER.json',{'status':'ACTUAL_OPERATOR_CLI_OUTAGE_RECOVERY_ROTATION_PASS','experiment':epoch,'clockSynchronized':True,'tlsCertificateValidated':True,'oldCapabilityRejected':True,'outage':outage,'startRefused':refused,'ownerOnlyFiles':True,'publicExposure':False})
 # This handoff is owner-only and must never be included in the evidence archive.
 save('BROWSER_READY.json',{'origin':origin,'port':tlsport,'token':token,'certificateSpkiSha256':spki,'endsUtcUnix':epoch['endsUtcUnix']})
 print('BROWSER_READY '+str(root/'BROWSER_READY.json'),flush=True)
 until(lambda:(root/'BROWSER_DONE.json').is_file(),100)
 browser=json.loads((root/'BROWSER_DONE.json').read_text());assert browser['blocks']==1
 until(lambda:all(rpc(x,'get_info')['height']==2 for x in rpcports),60)
 headers=[rpc(x,'get_block_header_by_height',{'height':1,'fill_pow_hash':True})['block_header'] for x in rpcports]
 assert headers[0]['hash']==headers[1]['hash'] and headers[0]['major_version']==17
 h=headers[0];assert int.from_bytes(bytes.fromhex(h['pow_hash']),'little')*int(h['wide_difficulty'],16)<2**256
 rpc(walletport,'refresh');balance=rpc(walletport,'get_balance');assert balance['balance']==h['reward'] and balance['unlocked_balance']==0
 # Service exits itself at the saved end; no shutdown signal is used here.
 while service.poll() is None and time.time()<epoch['endsUtcUnix']+12:sample();time.sleep(.2)
 assert service.poll()==0,'Persisted expiry did not close the actual CLI';stopped.add(service.pid)
 expired=subprocess.run([str(a.node),str(source/'pool/private/testnet_service.mjs'),str(config)],capture_output=True,text=True,timeout=10)
 assert expired.returncode!=0 and 'experiment not active' in expired.stderr and '"listening"' not in expired.stdout
 stop(wallet);stop(nodes[0]);stop(nodes[1]);assert all(c.returncode==0 for c in [wallet,*nodes])
 backup=root/'cold-backup';shutil.copytree(root/'node-0',backup)
 db=backup/'testnet/lmdb/data.mdb';sha=hashlib.sha256(db.read_bytes()).hexdigest()
 restored=root/'restored';shutil.copytree(backup,restored);assert hashlib.sha256((restored/'testnet/lmdb/data.mdb').read_bytes()).hexdigest()==sha
 restoreargs=list(node_args[0]);restoreargs[restoreargs.index('--data-dir')+1]=str(restored)
 # Both peers are deliberately stopped for a cold restore. Offline mode makes
 # core readback available without waiting for a nonexistent synchronization peer.
 restoreargs.append('--offline')
 restore=launch('restored-node',restoreargs)
 def restored_tip():
  result=rpc(rpcports[0],'get_last_block_header');header=result.get('block_header',{})
  observations.append({'status':result.get('status'),'height':header.get('height'),'hash':header.get('hash')})
  save('RESTORE_OBSERVATIONS.json',observations)
  return result.get('status')=='OK' and header.get('hash')==h['hash']
 until(restored_tip);stop(restore);assert restore.returncode==0
 assert hashlib.sha256(db.read_bytes()).hexdigest()==sha,'Cold backup changed'
 save('RESTORE_OBSERVATIONS.json',observations)
 save('RESULT.json',{'status':'REAL_OPERATOR_CLI_BROWSER_EPOCH_OUTAGE_ROTATION_COLD_RESTORE_PASS','sourceCommit':subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip(),'genesis':genesis,'version':info['version'],'experiment':epoch,'browserBlocks':1,'canonicalHeaders':headers,'exactRewardAtomic':balance['balance'],'immatureRewardLocked':True,'expiredRestartRefused':True,'automaticServiceExpiry':True,'coldBackupSha256':sha,'restoredCanonicalTip':h['hash'],'peakObservedOwnedServiceRssBytes':peak,'elapsedSeconds':time.monotonic()-began,'publicExposure':False,'limits':['Isolated private peers and localhost certificate; public CA issuance and domain/hosting untested','Browser pins this disposable certificate; Python TLS client validates certificate and hostname','One current-build canonical block here; prior qualified currency campaign covers maturity and transfers']})
 print('REAL_OPERATOR_REHEARSAL_PASS',flush=True)
finally:
 signal.alarm(0);receipts=[]
 for name,child,_ in reversed(children):
  stop(child)
  try:os.killpg(child.pid,0);empty=False
  except ProcessLookupError:empty=True
  receipts.append({'name':name,'pid':child.pid,'exitCode':child.returncode,'ownedGroupEmpty':empty})
 for log in logs:log.close()
 save('CLEANUP.json',{'processes':receipts,'elapsedSeconds':time.monotonic()-began})
 assert all(x['ownedGroupEmpty'] for x in receipts)
