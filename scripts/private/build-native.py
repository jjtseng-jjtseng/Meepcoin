#!/usr/bin/env python3
"""Build a committed checkout in a NEW isolated directory; no sudo or service changes."""
import argparse,hashlib,json,os,platform,resource,signal,subprocess,sys,tarfile,time,urllib.request,shutil
from pathlib import Path
repo=Path(__file__).resolve().parents[2]
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def clean_source():
 subprocess.run(['git','-C',str(repo),'diff','--exit-code','HEAD','--','native/core','meepow','scripts/private'],check=True,stdout=subprocess.DEVNULL)
 return subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
def extract_dependency(archive,destination):
 destination.mkdir(parents=True,exist_ok=False)
 with tarfile.open(archive) as tar:
  members=tar.getmembers();prefix=members[0].name.split('/')[0]+'/'
  for m in members:
   if m.name.rstrip('/')==prefix.rstrip('/'):continue
   if not m.name.startswith(prefix):raise ValueError('multiple archive roots')
   m.name=m.name[len(prefix):]
   tar.extract(m,destination,filter='data')
def prepare(output,dependency_cache=None):
 commit=clean_source();output=output.resolve()
 if output==repo or repo in output.parents or output in repo.parents:raise ValueError('output must be outside checkout')
 output.mkdir(parents=True,exist_ok=False)
 archive=output/'source.tar'
 with archive.open('xb') as f:subprocess.run(['git','-C',str(repo),'archive','HEAD','native/core','meepow'],stdout=f,check=True)
 source=output/'source';source.mkdir()
 with tarfile.open(archive) as tar:tar.extractall(source,filter='data')
 manifest=json.loads((repo/'scripts/private/native-dependencies.json').read_text())
 receipts=[];downloads=output/'downloads';downloads.mkdir()
 for item in manifest['dependencies']:
  path=downloads/(item['commit']+'.tar.gz')
  cached=dependency_cache/path.name if dependency_cache else None
  if cached and cached.is_file():shutil.copyfile(cached,path)
  else:
   with urllib.request.urlopen(item['url'],timeout=30) as r:path.write_bytes(r.read(manifest['archiveLimitBytes']+1))
  if path.stat().st_size!=item['bytes'] or digest(path)!=item['sha256']:raise ValueError('dependency integrity failure: '+item['destination'])
  extract_dependency(path,source/'native/core'/item['destination']);receipts.append(item)
 (output/'INPUTS.json').write_text(json.dumps({'commit':commit,'sourceArchiveSha256':digest(archive),'dependencies':receipts,'host':platform.platform()},indent=2)+'\n')
 return source

def limits():
 os.nice(10);resource.setrlimit(resource.RLIMIT_AS,(4*1024**3,4*1024**3));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 resource.setrlimit(resource.RLIMIT_FSIZE,(512*1024**2,512*1024**2))
def run(output,name,argv,seconds,env):
 started=time.monotonic();group_empty=False;timed_out=False;interrupted=None
 with (output/(name+'.log')).open('xb') as log:
  p=subprocess.Popen(argv,stdout=log,stderr=subprocess.STDOUT,env=env,start_new_session=True,preexec_fn=limits)
  try:code=p.wait(timeout=seconds)
  except subprocess.TimeoutExpired:timed_out=True;os.killpg(p.pid,signal.SIGKILL);code=p.wait()
  except BaseException as error:interrupted=error;os.killpg(p.pid,signal.SIGKILL);code=p.wait()
 try:os.killpg(p.pid,0)
 except ProcessLookupError:group_empty=True
 receipt={'argv':argv,'exitCode':code,'timeout':timed_out,'seconds':time.monotonic()-started,'ownedGroupEmpty':group_empty,'interrupted':interrupted is not None}
 (output/(name+'.json')).write_text(json.dumps(receipt,indent=2)+'\n')
 if interrupted is not None:raise interrupted
 if code or timed_out or not group_empty:
  print((output/(name+'.log')).read_bytes()[-32768:].decode('utf-8',errors='replace'),flush=True)
  print(json.dumps(receipt),flush=True)
  raise RuntimeError(name+' failed; see preserved log')
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('output',type=Path)
 parser.add_argument('--prepare-only',action='store_true');parser.add_argument('--sysroot',type=Path,help='existing private dependency prefix, e.g. sysroot/usr')
 parser.add_argument('--dependency-cache',type=Path,help='existing archive directory; every cached archive is still hash and size verified')
 parser.add_argument('--hardening-tests',action='store_true',help='Build and execute real LMDB alternate-storage regressions')
 parser.add_argument('--testnet17-genesis-utc',type=int,help='Opt into the NEW v17 testnet identity with this pinned Unix genesis timestamp')
 a=parser.parse_args()
 if a.testnet17_genesis_utc is not None and not 1000000000<=a.testnet17_genesis_utc<=2999999999:parser.error('v17 genesis timestamp must have ten decimal digits')
 if sys.version_info<(3,12) or sys.platform!='linux':parser.error('Linux with Python >=3.12 required')
 source=prepare(a.output,a.dependency_cache);output=a.output.resolve()
 if a.prepare_only:print('PREPARED '+str(output));return
 env=dict(os.environ,LC_ALL='C');opts=[]
 if a.hardening_tests:opts+=['-DMEEPCOIN_HARDENING_TESTS=ON']
 if a.testnet17_genesis_utc is not None:
  opts+=['-DMEEPCOIN_TESTNET17=ON','-DMEEPCOIN_TESTNET17_GENESIS_TIMESTAMP='+str(a.testnet17_genesis_utc)]
  (output/'CANDIDATE_NETWORK.json').write_text(json.dumps({'network':'testnet17-review','genesisUtcUnix':a.testnet17_genesis_utc,'defaultNetworkUnchanged':True,'publicExposure':False},indent=2)+'\n')
 if a.sysroot:
  prefix=a.sysroot.resolve(strict=True);triplet=subprocess.check_output(['gcc','-print-multiarch'],text=True).strip();lib=prefix/'lib'/triplet
  env.update(LD_LIBRARY_PATH=str(lib),PKG_CONFIG_PATH=str(lib/'pkgconfig'))
  opts+=['-DCMAKE_PREFIX_PATH='+str(prefix),'-DBOOST_ROOT='+str(prefix),'-DBoost_INCLUDE_DIR='+str(prefix/'include'),'-DBoost_LIBRARY_DIR_RELEASE='+str(lib),'-DOPENSSL_ROOT_DIR='+str(prefix),'-DOPENSSL_CRYPTO_LIBRARY='+str(lib/'libcrypto.so'),'-DOPENSSL_SSL_LIBRARY='+str(lib/'libssl.so'),'-DUNBOUND_INCLUDE_DIR='+str(prefix/'include'),'-DUNBOUND_LIBRARIES='+str(lib/'libunbound.so'),'-DCMAKE_CXX_FLAGS=-isystem '+str(prefix/'include'/triplet),'-DCMAKE_C_FLAGS=-isystem '+str(prefix/'include'/triplet)]
 build=output/'build';powbuild=output/'pow-build'
 run(output,'configure',['cmake','-S',str(source/'native/core'),'-B',str(build),'-DCMAKE_BUILD_TYPE=Release','-DOPT_FLAGS_RELEASE=-O1 -g0','-DSTATIC=OFF','-DMANUAL_SUBMODULES=ON','-DUSE_DEVICE_TREZOR=OFF','-DUSE_READLINE=OFF','-DBUILD_TESTS=OFF','-DBUILD_GUI_DEPS=OFF','-DUSE_CCACHE=OFF','-DMEEPCOIN_MEEPOW_DIR='+str(source/'meepow'),*opts],180,env)
 targets=['daemon','wallet_rpc_server','simplewallet']
 if a.hardening_tests:targets+=['meepcoin-alt-storage-test']
 run(output,'build',['cmake','--build',str(build),'--target',*targets,'--parallel','2'],2400,env)
 if a.hardening_tests:
  run(output,'alt-storage',[str(build/'bin/meepcoin-alt-storage-test'),str(output/'alt-storage-data')],300,env)
 run(output,'configure-pow',['cmake','-S',str(source/'meepow'),'-B',str(powbuild),'-DCMAKE_BUILD_TYPE=Release','-DMEEPOW_BLAKE3_PORTABLE=ON'],180,env)
 run(output,'build-pow',['cmake','--build',str(powbuild),'--target','meepow-v2-hash','meepow-kat-v2-api','--parallel','2'],300,env)
 run(output,'kat-v2',[str(powbuild/'meepow-kat-v2-api'),str(source/'meepow/vectors/vectors_v2.txt')],120,env)
 binaries=[build/'bin/meepcoind',build/'bin/meepcoin-wallet-rpc',build/'bin/meepcoin-wallet-cli',powbuild/'meepow-v2-hash']
 (output/'BUILD.json').write_text(json.dumps({'status':'PRIVATE_BUILD_AND_NATIVE_KAT_PASS','binaries':{str(p):digest(p) for p in binaries}},indent=2)+'\n')
 print('BUILT '+str(output))
if __name__=='__main__':
 for sig in [signal.SIGTERM,signal.SIGINT,signal.SIGHUP]:signal.signal(sig,lambda *_:sys.exit(130))
 main()
