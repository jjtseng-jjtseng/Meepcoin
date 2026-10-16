#!/usr/bin/env python3
"""Fresh isolated native build, then bounded identity-only incremental rebuild.

Reuses a successful prior configure command/toolchain and pinned dependency
archives. Never changes the prior source/build or installs host packages.
"""
import argparse,hashlib,json,os,platform,resource,shutil,subprocess,sys,tarfile,time
from pathlib import Path

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--output',type=Path,required=True);p.add_argument('--previous',type=Path,required=True)
 p.add_argument('--archive',type=Path,required=True);p.add_argument('--sha256',required=True)
 p.add_argument('--genesis',type=int,required=True);p.add_argument('--rebind',action='store_true')
 p.add_argument('--resume-initial',action='store_true',help='Preserve and resume the initial macOS guardian EPERM configure failure after its fix')
 p.add_argument('--guardian-dir',type=Path,required=True)
 a=p.parse_args();os.umask(0o077)
 if not 1785283200<a.genesis<=2999999999:raise ValueError('Invalid new genesis')
 sys.path.insert(0,str(a.guardian_dir.resolve(strict=True)));import guarded
 previous=a.previous.resolve(strict=True);root=a.output.resolve();mac=platform.system()=='Darwin'
 if root==previous or root.is_relative_to(previous) or previous.is_relative_to(root):raise ValueError('Separate output required')
 if sha(a.archive)!=a.sha256:raise ValueError('Source archive hash mismatch')
 oldsource=previous/('native-source' if mac else 'source')
 oldbuild=previous/('native-build' if mac else 'build')
 oldconfig=previous/('native-configure-v3.json' if mac else 'configure.json')
 if a.rebind or a.resume_initial:
  saved=json.loads((root/'INPUTS.json').read_text())
  if saved['sourceArchiveSha256']!=a.sha256:raise ValueError('Rebind source changed')
  if a.rebind and not (root/'BUILD.json').exists():raise ValueError('Initial build required')
  if a.resume_initial:
   if (root/'BUILD.json').exists() or json.loads((root/'initial-configure.json').read_text())['exitCode']==0:
    raise ValueError('Only the retained failed initial configure may resume')
   (root/'RESUME_REASON.json').write_text(json.dumps({'reason':'Darwin EPERM on an empty exited child group; now require an emptiness observation before/after signaling','oldEvidenceRetained':True,'guardianSha256':sha(a.guardian_dir/'guarded.py')})+'\n')
 else:
  root.mkdir(mode=0o700,parents=True,exist_ok=False)
  with tarfile.open(a.archive) as stream:stream.extractall(root/'source',filter='data')
  for item in json.loads((root/'source/scripts/private/native-dependencies.json').read_text())['dependencies']:
   archive=previous/'downloads'/(item['commit']+'.tar.gz')
   if sha(archive)!=item['sha256'] or archive.stat().st_size!=item['bytes']:raise ValueError('Dependency hash mismatch')
   target=root/'source/native/core'/item['destination'];target.mkdir(parents=True,exist_ok=True)
   with tarfile.open(archive) as stream:
    members=stream.getmembers();prefix=members[0].name.split('/')[0]+'/'
    for member in members:
     if member.name.rstrip('/')==prefix.rstrip('/'):continue
     if not member.name.startswith(prefix):raise ValueError('Dependency archive roots')
     member.name=member.name[len(prefix):];stream.extract(member,target,filter='data')
  (root/'INPUTS.json').write_text(json.dumps({'sourceArchiveSha256':a.sha256,'previousConfigure':str(oldconfig),
   'guardianSha256':sha(a.guardian_dir/'guarded.py'),'systemPackagesChanged':False},indent=2)+'\n')
 source=root/'source';build=root/'build';env=dict(os.environ,LC_ALL='C')
 if mac:env['PATH']=str(previous/'deps/bin')+':/usr/bin:/bin:/usr/sbin:/sbin'
 else:
  prefix=Path('/home/jjtseng/meepcoin-isolated-20261011-product/private-deps/sysroot/usr/lib/aarch64-linux-gnu')
  env.update(LD_LIBRARY_PATH=str(prefix),PKG_CONFIG_PATH=str(prefix/'pkgconfig'))
 def limits():
  os.nice(10);resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(512*1024**2,)*2)
  resource.setrlimit(resource.RLIMIT_CPU,(5400,)*2)
  if not mac:resource.setrlimit(resource.RLIMIT_AS,(4*1024**3,)*2)
 phase=('genesis-'+str(a.genesis)) if a.rebind else ('initial-resumed' if a.resume_initial else 'initial')
 def run(name,argv,seconds):
  began=time.monotonic();name=phase+'-'+name
  # Guardian Popen inherits this environment; restore controller environment after start.
  prior=dict(os.environ);os.environ.clear();os.environ.update(env)
  with (root/(name+'.log')).open('xb') as output:
   try:child=guarded.Child(argv,output=output,receipt=root/(name+'-GUARD_STOPPED.json'),seconds=seconds,limits=limits)
   finally:os.environ.clear();os.environ.update(prior)
   try:code=child.wait(timeout=seconds+45)
   finally:
    if child.poll() is None:child.terminate();child.wait(timeout=45)
  record={'argv':argv,'exitCode':code,'elapsedSeconds':time.monotonic()-began}
  (root/(name+'.json')).write_text(json.dumps(record,indent=2)+'\n')
  if code:raise RuntimeError(name+' failed; preserved log')
  return record
 argv=json.loads(oldconfig.read_text())['argv']
 argv=[value.replace(str(oldsource),str(source)).replace(str(oldbuild),str(build)) for value in argv]
 argv=[value for value in argv if not value.startswith('-DMEEPCOIN_TESTNET17_GENESIS_TIMESTAMP=')]
 argv+=['-DMEEPCOIN_TESTNET17_GENESIS_TIMESTAMP='+str(a.genesis)]
 records=[run('configure',argv,180)]
 records.append(run('build',[argv[0],'--build',str(build),'--target','daemon','wallet_rpc_server','simplewallet','--parallel','1'],5400 if not a.rebind else 1200))
 result={'status':'FRESH_NATIVE_BUILD_PASS','genesisUtcUnix':a.genesis,'sourceArchiveSha256':a.sha256,
  'platform':platform.platform(),'records':records,'binaries':{name:sha(build/'bin'/name) for name in ('meepcoind','meepcoin-wallet-rpc','meepcoin-wallet-cli')}}
 destination=root/(('GENESIS-'+str(a.genesis)+'.json') if a.rebind else 'BUILD.json')
 with destination.open('x') as output:json.dump(result,output,indent=2);output.write('\n')
 print(json.dumps({'status':result['status'],'genesisUtcUnix':a.genesis,'seconds':records[-1]['elapsedSeconds']}),flush=True)
if __name__=='__main__':main()
