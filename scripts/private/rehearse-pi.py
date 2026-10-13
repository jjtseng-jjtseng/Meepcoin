#!/usr/bin/env python3
"""One finite real-unit rehearsal of the pinned invitation release on the Pi.

Run as root after activate-pi.py. Never reads an existing wallet. The browser
handoff is private; RESULT/CLEANUP contain no invitation or spend credentials.
"""
import argparse,hashlib,json,os,pwd,shutil,signal,ssl,subprocess,time,urllib.request,urllib.error,uuid
from pathlib import Path

ROOT=Path('/home/jjtseng/meepcoin-deployment-20261012')
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run-name',default='deployed-rehearsal')
p.add_argument('--initial-height',type=int,default=1);p.add_argument('--duration-seconds',type=int,default=900)
p.add_argument('--skip-safari',action='store_true');a=p.parse_args()
assert a.run_name in ['deployed-rehearsal','deployed-rehearsal-v2','deployed-rehearsal-v3','deployed-rehearsal-v4','deployed-hardened-rehearsal','deployed-hardened-rehearsal-v2']
assert 1<=a.initial_height<=4 and 180<=a.duration_seconds<=900
RUN=ROOT/a.run_name;RUN.mkdir(mode=0o700,exist_ok=False)
os.umask(0o077);assert os.geteuid()==0
OWNER=pwd.getpwnam('jjtseng');IDENTITY=pwd.getpwnam('meepcoin')
os.chown(RUN,0,OWNER.pw_gid);RUN.chmod(0o710)
RELEASE=Path('/opt/meepcoin/current').resolve(strict=True);BINS=RELEASE/'bin'
MANIFEST=json.loads((RELEASE/'MANIFEST.json').read_text())
ORIGIN='https://mine.meepcoin.me';UNITS=['meepcoin-tunnel.service','meepcoin-gateway.service','meepcoin-rehearsal-wallet.service','meepcoin-node.service']
CONFIG=Path('/var/lib/meepcoin/operator/service.json');EPOCH=None;BROWSERS=[]
BEGAN=time.monotonic();PEAK={};OBSERVATIONS=[]

def run(args,**kwargs):return subprocess.run(args,check=True,timeout=kwargs.pop('timeout',30),**kwargs)
def save(name,obj,private=False):
 p=RUN/name;p.write_text(json.dumps(obj,indent=2)+'\n');p.chmod(0o600)
 if private:os.chown(p,OWNER.pw_uid,OWNER.pw_gid)
def active(unit):return subprocess.run(['systemctl','is-active','--quiet',unit]).returncode==0
def show(unit,*properties):
 out=subprocess.check_output(['systemctl','show',unit,*['-p'+x for x in properties]],text=True,timeout=10)
 return dict(x.split('=',1) for x in out.splitlines() if '=' in x)
def sample():
 for unit in UNITS:
  props=show(unit,'ControlGroup','ActiveState','TasksCurrent','CPUUsageNSec')
  cg=props.get('ControlGroup');rss=0
  if cg:
   for pid in (Path('/sys/fs/cgroup')/cg.lstrip('/')/'cgroup.procs').read_text().split():
    try:rss+=next((int(x.split()[1])*1024 for x in Path('/proc',pid,'status').read_text().splitlines() if x.startswith('VmRSS:')),0)
    except FileNotFoundError:pass
  PEAK[unit]=max(PEAK.get(unit,0),rss)
  assert rss<2*1024**3,'unit RSS exceeded rehearsal budget: '+unit
def until(fn,seconds=60):
 end=time.monotonic()+seconds;last=None
 while time.monotonic()<end:
  try:
   value=fn()
   if value:return value
  except (OSError,RuntimeError) as error:last=repr(error)
  sample();time.sleep(.4)
 raise RuntimeError('checkpoint deadline: '+str(last))
def rpc(port,method,params=None):
 data=json.dumps({'jsonrpc':'2.0','id':'deployed-rehearsal','method':method,'params':params or {}}).encode()
 with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:'+str(port)+'/json_rpc',data=data,headers={'Content-Type':'application/json'}),timeout=90 if method=='create_wallet' else 15) as response:reply=json.load(response)
 if 'error' in reply:raise RuntimeError(str(reply['error']))
 return reply['result']
def request(path,method='GET',data=None,token=None,origin=ORIGIN,host=None,public=False):
 headers={'User-Agent':'MeepCoin-Deployment-Check/1.0','Host':host or 'mine.meepcoin.me','Origin':origin}
 if token:headers['X-Meep-Session']=token
 body=None if data is None else json.dumps(data).encode()
 if body is not None:headers['Content-Type']='application/json'
 if public:
  target=ORIGIN;context=ssl.create_default_context()
 else:
  # Connect to loopback but validate the certificate against its DNS identity.
  target='https://mine.meepcoin.me:8443';context=ssl.create_default_context(cafile='/etc/meepcoin/origin-ca.pem')
  import http.client
  conn=http.client.HTTPSConnection('127.0.0.1',8443,context=context,timeout=20)
  conn.connect=lambda:None
  import socket
  conn.sock=context.wrap_socket(socket.create_connection(('127.0.0.1',8443),timeout=20),server_hostname='mine.meepcoin.me')
  try:
   conn.request(method,path,body=body,headers=headers);reply=conn.getresponse();raw=reply.read(1024**2)
   try:obj=json.loads(raw)
   except ValueError:obj={'textBytes':len(raw)}
   return reply.status,obj
  finally:conn.close()
 req=urllib.request.Request(target+path,data=body,headers=headers,method=method)
 try:
  with urllib.request.urlopen(req,context=context,timeout=20) as response:return response.status,json.loads(response.read(1024**2))
 except urllib.error.HTTPError as error:
  raw=error.read(1024**2)
  try:obj=json.loads(raw)
  except ValueError:obj={'textBytes':len(raw)}
  return error.code,obj
def interrupted(*_):raise KeyboardInterrupt()
for sig in [signal.SIGTERM,signal.SIGINT,signal.SIGALRM]:signal.signal(sig,interrupted)
signal.alarm(1500)
before=set(subprocess.check_output(['systemctl','list-units','--type=service','--state=running','--no-legend','--plain'],text=True).splitlines())
try:
 assert subprocess.check_output(['timedatectl','show','-p','NTPSynchronized','--value'],text=True).strip()=='yes'
 assert all(not active(unit) for unit in UNITS),'owned units must be stopped'
 assert not CONFIG.exists(),'existing epoch refused'
 assert time.time()-MANIFEST['genesisUtcUnix']<3600,'fresh first start required'
 run(['systemctl','start','meepcoin-node.service'])
 info=until(lambda:rpc(49081,'get_info'))
 genesis=rpc(49081,'get_block_header_by_height',{'height':0})['block_header']
 assert info['height']==a.initial_height and info['nettype']=='testnet' and info['version']==MANIFEST['nativeVersion']
 assert genesis['hash']==MANIFEST['genesisHash'] and genesis['timestamp']==MANIFEST['genesisUtcUnix']
 walletdir=Path('/var/lib/meepcoin')/('wallet-'+a.run_name);walletdir.mkdir(mode=0o700,exist_ok=False);os.chown(walletdir,IDENTITY.pw_uid,IDENTITY.pw_gid)
 walletargs=[str(BINS/'meepcoin-wallet-rpc'),'--config-file','/etc/meepcoin/empty.conf','--testnet','--wallet-dir',str(walletdir),'--shared-ringdb-dir',str(walletdir/'rings'),'--daemon-address','127.0.0.1:49081','--trusted-daemon','--no-dns','--daemon-ssl','disabled','--rpc-bind-ip','127.0.0.1','--rpc-bind-port','49082','--rpc-ssl','disabled','--disable-rpc-login','--non-interactive','--max-concurrency','1','--log-file','/var/log/meepcoin/wallet-internal.log','--log-level','0']
 props={'User':'meepcoin','Group':'meepcoin','Slice':'meepcoin.slice','CPUQuota':'20%','TasksMax':'48','Nice':'10','KillMode':'control-group','RuntimeMaxSec':'1300','TimeoutStopSec':'20','LimitAS':str(2*1024**3),'LimitDATA':str(1536*1024**2),'LimitFSIZE':str(128*1024**2),'LimitCORE':'0','NoNewPrivileges':'yes','ProtectSystem':'strict','ProtectHome':'yes','PrivateTmp':'no','PrivateDevices':'yes','IPAddressDeny':'any','IPAddressAllow':'localhost','ReadWritePaths':'/var/lib/meepcoin /var/log/meepcoin','StandardOutput':'append:/var/log/meepcoin/wallet.log','StandardError':'append:/var/log/meepcoin/wallet.log','UMask':'0077','TemporaryFileSystem':'/tmp:rw,nosuid,nodev,noexec,size=16M,mode=1777 /var/tmp:rw,nosuid,nodev,noexec,size=16M,mode=1777','InaccessiblePaths':'/dev/shm','ReadOnlyPaths':'/run'}
 run(['systemd-run','--quiet','--unit=meepcoin-rehearsal-wallet.service',*['--property='+k+'='+v for k,v in props.items()],*walletargs])
 until(lambda:rpc(49082,'get_version'))
 rpc(49082,'create_wallet',{'filename':'disposable-deployment','password':uuid.uuid4().hex,'language':'English'})
 address=rpc(49082,'get_address')['address']
 configure=[str(BINS/'node'),str(RELEASE/'source/pool/private/configure_testnet.mjs'),'--out',str(CONFIG),'--origin',ORIGIN,'--endpoint','http://127.0.0.1:49081/json_rpc','--genesis',genesis['hash'],'--genesis-utc',str(genesis['timestamp']),'--duration-seconds',str(a.duration_seconds),'--version',info['version'],'--key','/var/lib/meepcoin/operator/origin.key','--cert','/var/lib/meepcoin/operator/origin.crt','--data','/var/lib/meepcoin/chain','--native',str(BINS/'meepow-v2-hash'),'--port','8443','--contact','https://github.com/jjtseng-jjtseng/Meepcoin/issues/new/choose','--address',address]
 run(['runuser','-u','meepcoin','--',*configure],capture_output=True,text=True)
 config=json.loads(CONFIG.read_text());EPOCH=dict(config['experiment']);token=config['sessions'][0]['token']
 run(['systemctl','start','meepcoin-gateway.service'])
 until(lambda:request('/readyz',token=token)[0]==200)
 assert request('/api/status')[0]==403
 assert request('/api/start','POST',{},token,origin='https://wrong.example')[0]==403
 assert request('/healthz',host='wrong.example')[0]==403
 assert request('/json_rpc')[0]==404
 # Real node outage while the TLS gateway remains installed/running.
 run(['systemctl','stop','meepcoin-node.service']);assert not active('meepcoin-node.service')
 assert request('/readyz',token=token)[0]==503
 refused=request('/api/start','POST',{},token);assert refused[0]==503 and refused[1]['error']=='daemon_unavailable'
 run(['systemctl','start','meepcoin-node.service']);until(lambda:request('/readyz',token=token)[0]==200)
 assert json.loads(CONFIG.read_text())['experiment']==EPOCH
 # Rotate only the Node child, not the watchdog's shutdown signal handler.
 cg=show('meepcoin-gateway.service','ControlGroup')['ControlGroup']
 children=[int(pid) for pid in (Path('/sys/fs/cgroup')/cg.lstrip('/')/'cgroup.procs').read_text().split() if Path('/proc',pid,'comm').read_text().strip()=='node']
 assert len(children)==1;os.kill(children[0],signal.SIGHUP)
 old=token;until(lambda:json.loads(CONFIG.read_text())['sessions'][0]['token']!=old)
 token=json.loads(CONFIG.read_text())['sessions'][0]['token'];assert request('/api/status',token=old)[0]==403
 assert json.loads(CONFIG.read_text())['experiment']==EPOCH
 run(['systemctl','start','meepcoin-tunnel.service'])
 until(lambda:request('/readyz',token=token,public=True)[0]==200,120)
 assert active('meepcoin-tunnel.service')
 assert request('/api/status',public=True)[0]==403
 assert request('/json_rpc',public=True)[0]==404
 assert request('/api/start','POST',{},token,origin='https://wrong.example',public=True)[0]==403
 save('PRE_BROWSER.json',{'status':'REAL_INSTALLED_UNITS_PUBLIC_TLS_IDENTITY_OUTAGE_ROTATION_PASS','genesis':genesis,'experiment':EPOCH,'publicCaAndHostnameValidated':True,'originTlsValidated':True,'oldTokenRejected':True,'rpcNotPubliclyRouted':True,'badOriginRejected':True,'badHostRejectedAtOrigin':True,'unauthedStatusRejected':True,'units':{u:show(u,'ControlGroup','ActiveState','CPUQuotaPerSecUSec','TasksMax','IPAddressDeny','IPAddressAllow','KillMode') for u in UNITS}})
 save('BROWSER_READY.json',{'origin':ORIGIN,'token':token,'url':ORIGIN+'/#session='+token,'endsUtcUnix':EPOCH['endsUtcUnix']},private=True)
 print('PUBLIC_BROWSER_READY',flush=True)
 until(lambda:(RUN/'CHROME_DONE.json').is_file(),180)
 chrome=json.loads((RUN/'CHROME_DONE.json').read_text());assert chrome['blocks']==1;BROWSERS.append('Chrome')
 first=rpc(49081,'get_block_header_by_height',{'height':a.initial_height,'fill_pow_hash':True})['block_header']
 assert first['major_version']==17 and int.from_bytes(bytes.fromhex(first['pow_hash']),'little')*int(first['wide_difficulty'],16)<2**256
 rpc(49082,'refresh');balance=rpc(49082,'get_balance');assert balance['balance']==first['reward'] and balance['unlocked_balance']==0
 save('CHROME_CANONICAL.json',{'header':first,'balance':balance,'exactReward':True,'publicEndpoint':ORIGIN})
 # A genuinely visible Safari run is optional for this desktop-Chrome epoch.
 if a.skip_safari:safari={'blocks':0,'status':'EXCLUDED_ALREADY_RECORDED_VISIBILITY_PRECONDITION_FAILURE'}
 else:
  save('SAFARI_READY.json',{'url':ORIGIN+'/#session='+token},private=True)
  print('SAFARI_BROWSER_READY',flush=True)
  until(lambda:(RUN/'SAFARI_DONE.json').is_file(),180)
  safari=json.loads((RUN/'SAFARI_DONE.json').read_text())
 if safari.get('blocks')==1:BROWSERS.append('Safari')
 expected=1+(safari.get('blocks')==1)
 assert rpc(49081,'get_info')['height']==expected+a.initial_height
 headers=[rpc(49081,'get_block_header_by_height',{'height':height,'fill_pow_hash':True})['block_header'] for height in range(a.initial_height,expected+a.initial_height)]
 for header in headers:assert header['major_version']==17 and int.from_bytes(bytes.fromhex(header['pow_hash']),'little')*int(header['wide_difficulty'],16)<2**256
 rpc(49082,'refresh');balance=rpc(49082,'get_balance');assert balance['balance']==sum(h['reward'] for h in headers) and balance['unlocked_balance']==0
 save('CANONICAL_REWARDS.json',{'headers':headers,'balance':balance,'exactRewards':True,'browserPlatforms':BROWSERS,'safari':safari})
 # Actual persistent epoch expiry. No stop signal closes the gateway here.
 while time.time()<EPOCH['endsUtcUnix']+20 and active('meepcoin-gateway.service'):sample();time.sleep(1)
 assert not active('meepcoin-gateway.service') and not active('meepcoin-tunnel.service'),'gateway expiry must stop connector'
 exitstate=show('meepcoin-gateway.service','ExecMainStatus','Result');assert exitstate['ExecMainStatus']=='0' and exitstate['Result']=='success',exitstate
 expired=subprocess.run(['runuser','-u','meepcoin','--',str(BINS/'node'),str(RELEASE/'source/pool/private/testnet_service.mjs'),str(CONFIG)],capture_output=True,text=True,timeout=15)
 assert expired.returncode!=0 and 'experiment not active' in expired.stderr and '"listening"' not in expired.stdout
 run(['systemctl','stop','meepcoin-rehearsal-wallet.service','meepcoin-node.service'])
 backup=Path('/var/lib/meepcoin/backups')/(a.run_name+'-cold');assert not backup.exists();shutil.copytree('/var/lib/meepcoin/chain',backup)
 db=backup/'testnet/lmdb/data.mdb';coldhash=hashlib.sha256(db.read_bytes()).hexdigest()
 restored=Path('/var/lib/meepcoin')/('restored-'+a.run_name);shutil.copytree(backup,restored)
 for path in [restored,*restored.rglob('*')]:os.chown(path,IDENTITY.pw_uid,IDENTITY.pw_gid)
 assert hashlib.sha256((restored/'testnet/lmdb/data.mdb').read_bytes()).hexdigest()==coldhash
 original=Path('/etc/meepcoin/node.json').read_bytes();restoredcfg=json.loads(original);restoredcfg['argv'][restoredcfg['argv'].index('--data-dir')+1]=str(restored)
 restoreconfig=Path('/etc/meepcoin')/('node-restore-'+a.run_name+'.json');assert not restoreconfig.exists();restoreconfig.write_text(json.dumps(restoredcfg)+'\n');restoreconfig.chmod(0o640);os.chown(restoreconfig,0,IDENTITY.pw_gid)
 restoreunit='meepcoin-restore-'+a.run_name+'.service';UNITS.append(restoreunit)
 restoreprops={k:v for k,v in props.items() if k not in ['LimitAS','LimitDATA']};restoreprops['RuntimeMaxSec']='120';restoreprops['CPUQuota']='50%'
 run(['systemd-run','--quiet','--unit='+restoreunit,*['--property='+k+'='+v for k,v in restoreprops.items()],'/usr/bin/python3','/opt/meepcoin/supervise-pi.py',str(restoreconfig)])
 until(lambda:rpc(49081,'get_last_block_header')['block_header']['hash']==headers[-1]['hash'])
 run(['systemctl','stop',restoreunit]);assert hashlib.sha256(db.read_bytes()).hexdigest()==coldhash
 save('RESULT.json',{'status':'REAL_DEPLOYED_PUBLIC_BROWSER_REWARDS_OUTAGE_EXPIRY_COLD_RESTORE_PASS','release':MANIFEST,'publicOrigin':ORIGIN,'experiment':EPOCH,'canonicalHeaders':headers,'exactRewardAtomic':balance['balance'],'immatureRewardsLocked':True,'browserPlatforms':BROWSERS,'safari':safari,'automaticExpiry':exitstate,'expiredRestartRefused':True,'connectorStoppedWithGateway':True,'coldBackupSha256':coldhash,'restoredCanonicalTip':headers[-1]['hash'],'peakSampledUnitRssBytes':PEAK,'elapsedSeconds':time.monotonic()-BEGAN,'scope':['One actual installed ARM64 node and dedicated disposable wallet','Actual public Cloudflare hostname and public CA certificate; origin certificate validated','Desktop invitation experiment only; no mobile or sustained battery/heat qualification','Memory cgroup controller disabled on host; sampled RSS plus RLIMIT_DATA/AS and CPU/pid cgroups']})
 print('REAL_DEPLOYED_REHEARSAL_PASS',flush=True)
except BaseException as error:
 save('FAILURE.json',{'error':repr(error),'elapsedSeconds':time.monotonic()-BEGAN,'experiment':EPOCH});raise
finally:
 signal.alarm(0)
 for unit in UNITS:subprocess.run(['systemctl','stop',unit],timeout=30,capture_output=True)
 after=set(subprocess.check_output(['systemctl','list-units','--type=service','--state=running','--no-legend','--plain'],text=True).splitlines())
 # Compare service names, because the runtime descriptions may contain counters.
 missing=sorted({x.split()[0] for x in before if x.strip()}-{x.split()[0] for x in after if x.strip()})
 cleanup={u:show(u,'ActiveState','ControlGroup','ExecMainStatus','Result') for u in UNITS}
 save('CLEANUP.json',{'units':cleanup,'allOwnedUnitsStopped':all(not active(u) for u in UNITS),'allOwnedCgroupsEmpty':all(not v.get('ControlGroup') for v in cleanup.values()),'previouslyRunningServicesNoLongerRunning':missing,'elapsedSeconds':time.monotonic()-BEGAN})
 assert all(not active(u) and not cleanup[u].get('ControlGroup') for u in UNITS)
 assert not missing,'a previously running service is no longer running'
