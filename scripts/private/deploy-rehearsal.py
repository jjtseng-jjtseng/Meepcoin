#!/usr/bin/env python3
"""Finite, separate Pi deployment. Run as root; never replaces an old network.

Only exact recorded systemd cgroups authorize process cleanup. Existing operator
services, chains, wallet files and unrelated services are left in place.
"""
import argparse,datetime,hashlib,json,math,os,pwd,re,shutil,signal,socket,ssl,subprocess,time,urllib.error,urllib.request
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('action',choices=('setup','node','gateway','tunnel','peers','telemetry','status','stop','backup','restore','expire'))
p.add_argument('--genesis',required=True,type=int);p.add_argument('--package',type=Path);p.add_argument('--source',type=Path)
p.add_argument('--network',type=Path);p.add_argument('--addresses',nargs=2);p.add_argument('--role');p.add_argument('--seconds',type=int,default=3600)
a=p.parse_args();assert os.geteuid()==0,'Dedicated-account deployment setup requires administrator';os.umask(0o077)
assert 1785283200<a.genesis<=2999999999
name='six-'+str(a.genesis);base=Path('/var/lib/meepcoin')/name;release=Path('/opt/meepcoin')/name
logroot=Path('/var/log/meepcoin')/name;userroot=Path('/home/jjtseng/meepcoin-readiness-six-20261015')/name
operator=pwd.getpwnam('meepcoin');participant=pwd.getpwnam('jjtseng')
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value):
 with path.open('x') as stream:json.dump(value,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
def owned(path,account=operator,mode=0o700):
 path.mkdir(mode=mode,parents=True,exist_ok=False);os.chown(path,account.pw_uid,account.pw_gid);path.chmod(mode)
def call(method,params=None):
 request=urllib.request.Request('http://127.0.0.1:49281/json_rpc',data=json.dumps({'jsonrpc':'2.0','id':'rehearsal','method':method,'params':params or {}}).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(request,timeout=2) as response:
  result=json.load(response);assert 'error' not in result,result.get('error');return result['result']
def unit(role):
 assert role in ('node','gateway','tunnel','pi-peer','mac-peer','telemetry','restore','expiry')
 return 'meepcoin-'+name+'-'+role+'.service'
def show(role):
 result=subprocess.run(['systemctl','show',unit(role),'-p','ActiveState','-p','SubState','-p','ControlGroup','-p','Result'],capture_output=True,text=True,timeout=5)
 return dict(row.split('=',1) for row in result.stdout.splitlines() if '=' in row)
def group_empty(group):
 assert group.startswith('/meepcoin.slice/') and '..' not in group
 path=Path('/sys/fs/cgroup')/group.lstrip('/')/'cgroup.events'
 return not path.exists() or 'populated 1' not in path.read_text().splitlines()
def stop(role):
 state=show(role);group=state.get('ControlGroup') or '/meepcoin.slice/'+unit(role)
 assert group=='/meepcoin.slice/'+unit(role),'Unexpected owned service cgroup'
 result=subprocess.run(['systemctl','stop',unit(role)],capture_output=True,text=True,timeout=50)
 assert group_empty(group),'Owned cgroup did not drain'
 assert show(role).get('ActiveState')!='active'
 return {'unit':unit(role),'ownedCgroupEmpty':True,'stopExitCode':result.returncode}
def require_cold(role):
 state=show(role);assert state.get('ActiveState') in ('inactive','failed')
 group=state.get('ControlGroup') or '/meepcoin.slice/'+unit(role)
 assert group=='/meepcoin.slice/'+unit(role) and group_empty(group),'Cold operation requires verified empty owned cgroup'
def remaining(default):
 epoch=base/'EPOCH.json'
 if not epoch.exists():return default
 seconds=math.floor(json.loads(epoch.read_text())['endsUtcUnix']-time.time());assert seconds>0,'Expired private services cannot restart'
 return seconds
def bind_epoch(experiment):
 epoch=base/'EPOCH.json'
 if epoch.exists():assert json.loads(epoch.read_text())==experiment
 else:save(epoch,experiment)
 assert experiment['endsUtcUnix']>time.time(),'Expired experiment cannot bind services'
 expiry=datetime.datetime.fromtimestamp(experiment['endsUtcUnix'],datetime.timezone.utc).strftime('%Y%m%d%H%M%SZ')
 for label in ('pi','mac'):
  authorized=userroot/label/'authorized_keys'
  if authorized.exists():authorized.write_text(re.sub(r'expiry-time="[^"]+"','expiry-time="'+expiry+'"',authorized.read_text()))
 # RuntimeMaxSec cannot be changed live on this systemd version. The verified
 # absolute one-shot timer closes all existing cgroups, including SSH children.
 # Original finite bootstrap caps remain as additional, possibly earlier stops.
 calendar=datetime.datetime.fromtimestamp(experiment['endsUtcUnix'],datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
 timer=unit('expiry').replace('.service','.timer')
 state=subprocess.check_output(['systemctl','show',timer,'-p','ActiveState','--value'],text=True,timeout=5).strip()
 if state!='active':
  subprocess.run(['systemd-run','--quiet','--unit='+unit('expiry'),'--on-calendar='+calendar,'--timer-property=AccuracySec=1s',
   '--timer-property=RandomizedDelaySec=0','--property=Slice=meepcoin.slice','--property=RuntimeMaxSec=60',
   '/usr/bin/python3','-B',str(release/'source/scripts/private/deploy-rehearsal.py'),'expire','--genesis',str(a.genesis)],check=True,timeout=10)
 assert subprocess.check_output(['systemctl','show',timer,'-p','ActiveState','--value'],text=True,timeout=5).strip()=='active'
 binding=base/'EPOCH_BINDING.json'
 if not binding.exists():save(binding,{'experiment':experiment,'absoluteExpiryTimer':timer,'calendar':calendar,
  'existingPeerSessionsClosedBy':'exact owned cgroups at timer expiry','bootstrapRuntimeCapsRetained':True})
 else:assert json.loads(binding.read_text())['experiment']==experiment
def start(role,argv,seconds,peer=False):
 assert show(role).get('ActiveState') not in ('active','activating','deactivating')
 properties={'User':'jjtseng' if peer else 'meepcoin','Group':'jjtseng' if peer else 'meepcoin','Slice':'meepcoin.slice',
  'Restart':'no','KillMode':'control-group','TimeoutStopSec':'40','RuntimeMaxSec':str(seconds),'UMask':'0077','Nice':'10',
  'TasksMax':'32' if peer else '64','NoNewPrivileges':'yes','ProtectSystem':'strict','ProtectHome':'no' if peer else 'yes',
  'PrivateDevices':'yes','ProtectKernelTunables':'yes','ProtectKernelModules':'yes','ProtectControlGroups':'yes','ProtectClock':'yes',
  'RestrictSUIDSGID':'yes','RestrictRealtime':'yes','LockPersonality':'yes','LimitCORE':'0','LimitNOFILE':'512',
  'LimitFSIZE':'16777216','ReadWritePaths':str(base)+' '+str(logroot)+(' '+str(userroot) if peer else ''),
  'TemporaryFileSystem':'/tmp:rw,nosuid,nodev,noexec,size=16M,mode=1777 /var/tmp:rw,nosuid,nodev,noexec,size=16M,mode=1777',
  'InaccessiblePaths':'/dev/shm','ReadOnlyPaths':'/run','StandardOutput':'append:'+str(logroot/(role+'.log')),
  'StandardError':'append:'+str(logroot/(role+'.log'))}
 if role=='tunnel':properties.update(CPUQuota='30%',Environment='GOMEMLIMIT=128MiB',BindsTo=unit('gateway'),After=unit('gateway'))
 elif peer:properties['CPUQuota']='20%'
 else:properties.update(IPAddressDeny='any',IPAddressAllow='localhost')
 command=['systemd-run','--quiet','--unit='+unit(role)]+['--property='+k+'='+v for k,v in properties.items()]+argv
 subprocess.run(command,check=True,timeout=15)
 end=time.monotonic()+10
 while show(role).get('ActiveState')!='active':
  assert time.monotonic()<end,'Service did not become active';time.sleep(.1)
 group=show(role)['ControlGroup'];assert group=='/meepcoin.slice/'+unit(role)
 return {'unit':unit(role),'cgroup':group,'seconds':seconds}
def native(data,rpc=49281,peer=49280,offline=False):
 argv=[str(release/'participant/bin/meepcoind'),'--config-file',str(base/'empty.conf'),'--testnet','--data-dir',str(data),
  '--no-zmq','--no-igd','--disable-dns-checkpoints','--check-updates','disabled','--in-peers','2' if not offline else '0',
  '--max-connections-per-ip','2','--out-peers','0','--hide-my-port','--allow-local-ip','--p2p-bind-ip','127.0.0.1','--p2p-bind-port',str(peer),
  '--rpc-bind-ip','127.0.0.1','--rpc-bind-port',str(rpc),'--rpc-ssl','disabled','--max-concurrency','1','--prep-blocks-threads','1',
  '--non-interactive','--log-file',str(logroot/('restore-native.log' if offline else 'native.log')),'--log-level','0','--max-log-files','1','--max-log-file-size','1048576']
 if offline:argv.append('--offline')
 return argv
if a.action=='setup':
 assert a.package and a.source and a.network
 for old in ('meepcoin-node','meepcoin-gateway','meepcoin-tunnel'):
  assert subprocess.run(['systemctl','is-active',old],capture_output=True,text=True).stdout.strip()!='active','An earlier deployment is active'
 for port in (49280,49281,49422,49423,49443,49300):
  with socket.socket() as s:s.bind(('192.168.68.72' if port in (49422,49423) else '127.0.0.1',port))
 network=json.loads(a.network.read_text());manifest=json.loads((a.package/'MANIFEST.json').read_text())
 assert manifest['genesisHash']==network['genesisHash'] and manifest['genesisUtcUnix']==a.genesis
 for row in (a.package/'SHA256SUMS').read_text().splitlines():
  digest,relative=row.split('  ',1);assert sha(a.package/relative)==digest
 release.mkdir(mode=0o755,exist_ok=False);shutil.copytree(a.package,release/'participant',symlinks=False)
 shutil.copytree(a.source,release/'source',symlinks=False)
 old=Path('/opt/meepcoin/current').resolve(strict=True)
 previousHashes={row.split('  ',1)[1]:row.split('  ',1)[0] for row in (old/'SHA256SUMS').read_text().splitlines()}
 runtime=release/'runtime';(runtime/'bin').mkdir(parents=True);(runtime/'libexec').mkdir()
 for label in ('node','meepow-v2-hash','meepow-kat-v2-api'):
  for directory in ('bin','libexec'):
   relative=directory+'/'+label
   assert sha(old/relative)==previousHashes[relative],'Prior pinned runtime or verifier changed'
   shutil.copyfile(old/relative,runtime/relative)
 for library in (old/'lib').rglob('*'):
  if library.is_file():assert sha(library)==previousHashes[library.relative_to(old).as_posix()]
 shutil.copytree(old/'lib',runtime/'lib',symlinks=False)
 for item in release.rglob('*'):
  assert not item.is_symlink();item.chmod(0o755 if item.is_dir() or item.parent in (runtime/'bin',runtime/'libexec') or item.stat().st_mode&0o111 else 0o644)
 release.chmod(0o755)  # umask 0077 also applies to mkdir(mode=0755).
 owned(base);owned(logroot);owned(userroot,participant)
 (base/'empty.conf').write_text('');os.chown(base/'empty.conf',operator.pw_uid,operator.pw_gid)
 save(base/'NETWORK.json',network);os.chown(base/'NETWORK.json',operator.pw_uid,operator.pw_gid)
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(base/'origin-key.pem'),'-out',str(base/'origin-cert.pem'),
  '-days','3','-subj','/CN=mine.meepcoin.me','-addext','subjectAltName=DNS:mine.meepcoin.me'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
 for label in ('origin-key.pem','origin-cert.pem'):os.chown(base/label,operator.pw_uid,operator.pw_gid)
 oldTunnel=Path('/etc/meepcoin/tunnel.yml').read_text()
 tunnel=re.search(r'^tunnel:\s*(.+)$',oldTunnel,re.M).group(1);credentials=re.search(r'^credentials-file:\s*(.+)$',oldTunnel,re.M).group(1)
 assert Path(credentials).resolve(strict=True).is_relative_to(Path('/etc/meepcoin'))
 (base/'tunnel.yml').write_text(f'tunnel: {tunnel}\ncredentials-file: {credentials}\nprotocol: http2\nmetrics: 127.0.0.1:49300\nno-autoupdate: true\ningress:\n  - hostname: mine.meepcoin.me\n    service: https://127.0.0.1:49443\n    originRequest:\n      originServerName: mine.meepcoin.me\n      caPool: {base}/origin-cert.pem\n  - service: http_status:404\n')
 os.chown(base/'tunnel.yml',operator.pw_uid,operator.pw_gid)
 save(base/'SETUP.json',{'status':'SEPARATE_DEPLOYMENT_STAGED','genesis':network['genesisHash'],'operatorUid':operator.pw_uid,
  'nativeRpcAndPeer':'loopback','sourceReceipt':json.loads((a.source/'SOURCE_RECORD.json').read_text()),'oldNetworkRetained':True})
 print(json.dumps({'status':'SEPARATE_DEPLOYMENT_STAGED','base':str(base),'release':str(release)}))
else:
 assert base.is_dir() and release.is_dir();network=json.loads((base/'NETWORK.json').read_text())
 if a.action=='node':
  result=start('node',native(base/'chain'),remaining(4500));end=time.monotonic()+45
  while True:
   try:info=call('get_info');header=call('get_block_header_by_height',{'height':0})['block_header'];break
   except OSError:assert time.monotonic()<end;time.sleep(.2)
  assert header['hash']==network['genesisHash'] and header['timestamp']==a.genesis and info['version']==network['nativeVersion'];print(json.dumps(result))
 elif a.action=='peers':
  lifetime=remaining(4200);expires=int(time.time())+lifetime
  for label,port,pub in [('pi',49422,'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMgO9TkyHvxIgCJ5aio8ZTRPyFt0UkoEFOcClrW5XOrG'),('mac',49423,'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHK64zbrAfc5voKUvKMKDbvVaI6FY1GRzgKZnP/ZHplg')]:
   directory=userroot/label;owned(directory,participant);key=directory/'host-ed25519'
   subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True,timeout=10)
   expiry=datetime.datetime.fromtimestamp(expires,datetime.timezone.utc).strftime('%Y%m%d%H%M%SZ')
   (directory/'authorized_keys').write_text('restrict,port-forwarding,permitopen="127.0.0.1:49280",expiry-time="'+expiry+'" '+pub+'\n')
   config=directory/'sshd.conf';config.write_text(f'Port {port}\nListenAddress 192.168.68.72\nHostKey {key}\nPidFile {directory}/sshd.pid\nAuthorizedKeysFile {directory}/authorized_keys\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nAuthenticationMethods publickey\nUsePAM no\nAllowUsers jjtseng\nMaxSessions 0\nMaxStartups 2:30:4\nLoginGraceTime 10\nMaxAuthTries 2\nAllowTcpForwarding local\nPermitOpen 127.0.0.1:49280\nPermitListen none\nAllowStreamLocalForwarding no\nAllowAgentForwarding no\nPermitTTY no\nX11Forwarding no\nPermitUserRC no\nGatewayPorts no\nLogLevel VERBOSE\n')
   for item in directory.iterdir():os.chown(item,participant.pw_uid,participant.pw_gid);item.chmod(0o600)
   subprocess.run(['/usr/sbin/sshd','-t','-f',str(config)],check=True,timeout=10)
   start(label+'-peer',['/usr/sbin/sshd','-D','-e','-f',str(config)],lifetime,peer=True)
   descriptor={'schema':'meepcoin-private-peer/1','participant':label,'host':'192.168.68.72','port':port,'user':'jjtseng','target':'127.0.0.1:49280',
    'hostPublicKey':key.with_suffix('.pub').read_text().strip(),'genesis':network['genesisHash'],'expiresUtc':expires,'exposure':'private home LAN only'}
   save(userroot/(label+'-peer.json'),descriptor);os.chown(userroot/(label+'-peer.json'),participant.pw_uid,participant.pw_gid)
  print('INDIVIDUAL_PRIVATE_PEERS_READY')
 elif a.action=='gateway':
  config=base/'service.json'
  if not config.exists():
   assert a.addresses and 1800<=a.seconds<=3600 and 0<=time.time()-a.genesis<=1800,'Fresh scheduled launch and two addresses required'
   args=[str(release/'runtime/bin/node'),str(release/'source/pool/private/configure_testnet.mjs'),'--out',str(config),'--origin','https://mine.meepcoin.me',
    '--endpoint','http://127.0.0.1:49281/json_rpc','--genesis',network['genesisHash'],'--genesis-utc',str(a.genesis),'--version',network['nativeVersion'],
    '--key',str(base/'origin-key.pem'),'--cert',str(base/'origin-cert.pem'),'--data',str(base/'chain'),'--native',str(release/'runtime/bin/meepow-v2-hash'),
    '--contact','https://github.com/jjtseng-jjtseng/Meepcoin/issues/new/choose','--host','127.0.0.1','--port','49443','--duration-seconds',str(a.seconds)]
   for address in a.addresses:args+=['--address',address]
   subprocess.run(['runuser','-u','meepcoin','--']+args,check=True,timeout=20,stdout=subprocess.DEVNULL)
  persistent=json.loads(config.read_text());bind_epoch(persistent['experiment']);seconds=remaining(0)
  result=start('gateway',[str(release/'runtime/bin/node'),str(release/'source/pool/private/testnet_service.mjs'),str(config)],seconds+1)
  private=json.loads((base/'service.json.invitations.json').read_text());private['experiment']=persistent['experiment']
  path=userroot/'MINING_PRIVATE.json'
  if not path.exists():save(path,private);os.chown(path,participant.pw_uid,participant.pw_gid)
  print(json.dumps({**result,'experiment':persistent['experiment']}))
 elif a.action=='tunnel':
  print(json.dumps(start('tunnel',['/opt/meepcoin/bin/cloudflared','tunnel','--config',str(base/'tunnel.yml'),'run'],remaining(0)+1)))
 elif a.action=='status':
  result={'services':{role:show(role) for role in ('node','gateway','tunnel','pi-peer','mac-peer','telemetry','restore')}}
  try:result['native']=call('get_info')
  except OSError:result['nativeUnavailable']=True
  progress=base/'service.json.progress.json'
  if progress.exists():result['progress']=json.loads(progress.read_text())
  print(json.dumps(result))
 elif a.action=='stop':
  roles=[a.role] if a.role else ['tunnel','gateway','pi-peer','mac-peer','node','restore','telemetry']
  if not a.role:
   subprocess.run(['systemctl','stop',unit('expiry').replace('.service','.timer')],capture_output=True,timeout=10)
  print(json.dumps({'stopped':[stop(role) for role in roles]}))
 elif a.action=='expire':
  epoch=json.loads((base/'EPOCH.json').read_text());assert time.time()>=epoch['endsUtcUnix']
  roles=['tunnel','gateway','pi-peer','mac-peer','node']
  batch=subprocess.run(['systemctl','stop']+[unit(role) for role in roles],capture_output=True,text=True,timeout=50)
  # A previously revoked transient unit can already be unloaded. Verify every
  # exact owned cgroup below; a missing unit must not skip the other closures.
  result={'status':'ABSOLUTE_EPOCH_ENTRY_POINTS_CLOSED','scheduledEndUtc':epoch['endsUtcUnix'],'observedUtc':time.time(),
   'initialBatchExitCode':batch.returncode,'initialBatchStderr':batch.stderr,
   'stopped':[stop(role) for role in roles]}
  save(base/'EXPIRY_STOPPED.json',result)
 elif a.action=='telemetry':
  stopRequested=False
  def interrupted(*_):
   global stopRequested;stopRequested=True
  signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
  end=time.monotonic()+4200;previous=None;peak=0;maxGap=0;samples=0
  target=base/'TELEMETRY.jsonl';assert not target.exists()
  with target.open('x') as stream:
   while time.monotonic()<end and not stopRequested:
    started=time.monotonic();wall=time.time();gap=0 if previous is None else started-previous;previous=started;maxGap=max(maxGap,gap)
    rss=0;processes=0;services={};resources={}
    for role in ('node','gateway','tunnel','pi-peer','mac-peer'):
     state=show(role);services[role]=state.get('ActiveState');group=state.get('ControlGroup')
     if group:
      assert group=='/meepcoin.slice/'+unit(role)
      cg=Path('/sys/fs/cgroup')/group.lstrip('/');unitRss=0
      try:rows=(cg/'cgroup.procs').read_text().splitlines()
      except FileNotFoundError:rows=[]
      for row in rows:
       try:
        values=Path('/proc')/row/'status';memory=re.search(r'^VmRSS:\s*(\d+) kB$',values.read_text(),re.M);unitRss+=int(memory.group(1))*1024 if memory else 0;processes+=1
       except FileNotFoundError:pass
      try:cpu=dict(row.split() for row in (cg/'cpu.stat').read_text().splitlines())
      except FileNotFoundError:cpu={}
      rss+=unitRss;resources[role]={'rssBytes':unitRss,'cpuStat':cpu}
    free=shutil.disk_usage(base).free;logs=sum(x.stat().st_size for x in logroot.rglob('*') if x.is_file());peak=max(peak,rss)
    record={'utc':wall,'gapSeconds':gap,'rssBytes':rss,'processes':processes,'freeBytes':free,'logBytes':logs,'services':services,'resources':resources}
    try:info=call('get_info');record.update(height=info['height'],tip=info['top_block_hash'],difficulty=info['wide_difficulty'],incomingPeers=info['incoming_connections_count'],outgoingPeers=info['outgoing_connections_count'])
    except (OSError,KeyError):record['rpcUnavailable']=True
    config=base/'service.json'
    if config.exists():
     token=json.loads(config.read_text())['sessions'][0]['token']
     connection=None
     try:
      # Trust exactly the locally issued CA while verifying its advertised host.
      import http.client
      connection=http.client.HTTPSConnection('127.0.0.1',49443,timeout=2,context=ssl.create_default_context(cafile=str(base/'origin-cert.pem')))
      sock=socket.create_connection(('127.0.0.1',49443),timeout=2)
      connection.sock=ssl.create_default_context(cafile=str(base/'origin-cert.pem')).wrap_socket(sock,server_hostname='mine.meepcoin.me')
      connection.request('GET','/readyz',headers={'Host':'mine.meepcoin.me','X-Meep-Session':token});response=connection.getresponse()
      record['localReadiness']={'status':response.status,'body':json.loads(response.read(65536))}
     except (OSError,ValueError,http.client.HTTPException):record['localReadiness']={'unavailable':True}
     finally:
      if connection:connection.close()
    progress=base/'service.json.progress.json'
    if progress.exists():record['progress']=json.loads(progress.read_text())
    stream.write(json.dumps(record)+'\n');stream.flush();os.fsync(stream.fileno());samples+=1
    if rss>1536*1024**2 or free<1024**3 or logs>128*1024**2:
     for role in ('tunnel','gateway','pi-peer','mac-peer','node'):stop(role)
     raise RuntimeError('Measured resource limit exceeded; owned services stopped')
    time.sleep(max(.05,5-(time.monotonic()-started)))
  save(base/'TELEMETRY_STOPPED.json',{'samples':samples,'peakRssBytes':peak,'maxGapSeconds':maxGap,'continuousGapBoundSatisfied':maxGap<=15})
 elif a.action=='backup':
  require_cold('node');require_cold('restore');source=base/'chain';destination=base/'cold-backup';assert source.is_dir() and not destination.exists()
  shutil.copytree(source,destination,symlinks=False)
  hashes={str(x.relative_to(source)):sha(x) for x in source.rglob('*') if x.is_file()}
  assert hashes=={str(x.relative_to(destination)):sha(x) for x in destination.rglob('*') if x.is_file()}
  for item in [destination]+list(destination.rglob('*')):os.chown(item,operator.pw_uid,operator.pw_gid)
  save(base/'COLD_BACKUP.json',{'status':'COLD_COPY_HASHES_MATCH','files':hashes});print('COLD_COPY_HASHES_MATCH')
 elif a.action=='restore':
  require_cold('node');require_cold('restore');backup=base/'cold-backup';destination=base/'restored-chain';assert not destination.exists()
  shutil.copytree(backup,destination,symlinks=False)
  for item in [destination]+list(destination.rglob('*')):os.chown(item,operator.pw_uid,operator.pw_gid)
  print(json.dumps(start('restore',native(destination,offline=True),180)))
