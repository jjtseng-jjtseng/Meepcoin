"""Assemble a new participant package from verified libraries and fresh binaries.

No existing package or user data is modified. The detached publisher signature
is produced separately, after the complete archive descriptor is finalized.
"""
import argparse,hashlib,json,os,platform,re,shutil,subprocess,tarfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for name in ('root','source','network','source-record','output'):p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--version',required=True);a=p.parse_args();os.umask(0o077)
root=a.root.resolve(strict=True);source=a.source.resolve(strict=True)
old=Path.home()/'meepcoin-participant-20261015/installed-2'
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
for row in (old/'SHA256SUMS').read_text().splitlines():
 digest,name=row.split('  ',1);assert sha(old/name)==digest,'Prior dependency package changed'
network=json.loads(a.network.read_text());record=json.loads(a.source_record.read_text())
mac=platform.system()=='Darwin';assert mac or platform.system()=='Linux'
name='meepcoin-'+a.version+'-'+('macos26-arm64' if mac else 'debian13-arm64')
output=a.output.resolve();output.mkdir(mode=0o700,exist_ok=False);stage=output/name;stage.mkdir(mode=0o700)
for label in ('bin','libexec','wallet','provenance'):(stage/label).mkdir(mode=0o700)
for label in ('lib','licenses'):shutil.copytree(old/label,stage/label,symlinks=False)
for item in (source/'wallet').rglob('*'):
 if item.is_file() and (item.suffix in ('.py','.mjs') or 'web' in item.relative_to(source/'wallet').parts):
  target=stage/'wallet'/item.relative_to(source/'wallet');target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);shutil.copyfile(item,target)
native=root/'native-v1/build/bin';before={}
for label in ('meepcoind','meepcoin-wallet-rpc','meepcoin-wallet-cli'):
 target=stage/'libexec'/label;shutil.copyfile(native/label,target);target.chmod(0o700);before[label]=sha(target)
 if mac:
  outputText=subprocess.check_output(['otool','-L',str(target)],text=True)
  for row in outputText.splitlines()[1:]:
   imported=row.strip().split(' (',1)[0]
   if imported.startswith(('/usr/lib/','/System/Library/')):continue
   library=Path(imported).name;assert (stage/'lib'/library).is_file(),'Unbundled native dependency: '+library
   subprocess.run(['install_name_tool','-change',imported,'@loader_path/../lib/'+library,str(target)],check=True,capture_output=True)
  loads=subprocess.check_output(['otool','-l',str(target)],text=True)
  for rpath in re.findall(r'cmd LC_RPATH\s+cmdsize \d+\s+path (.+?) \(offset',loads):
   subprocess.run(['install_name_tool','-delete_rpath',rpath,str(target)],check=True,capture_output=True)
  subprocess.run(['codesign','--force','--sign','-',str(target)],check=True,capture_output=True)
  subprocess.run(['codesign','--verify','--strict',str(target)],check=True,capture_output=True)
 wrapper=stage/'bin'/label
 wrapper.write_text('#!/bin/sh\nset -eu\nroot=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)\n'+('' if mac else 'export LD_LIBRARY_PATH="$root/lib"\n')+'exec "$root/libexec/'+label+'" "$@"\n');wrapper.chmod(0o700)
assert before['meepcoind']==network['nativeSha256']
build=json.loads((root/'native-v1'/('GENESIS-'+str(network['genesisUtcUnix'])+'.json')).read_text())
assert build['genesisUtcUnix']==network['genesisUtcUnix']
assert build['sourceArchiveSha256']==record['nativeSourceArchiveSha256']
assert build['binaries']==before,'Every native program must match its exact fresh build'
manifest={'schema':'meepcoin-participant-release/1','releaseVersion':a.version,
 'platform':'macOS 26 ARM64' if mac else 'Debian 13 ARM64','network':'testnet17',
 'genesisHash':network['genesisHash'],'genesisUtcUnix':network['genesisUtcUnix'],'nativeVersion':network['nativeVersion'],
 'nativeSourceCommit':record['nativeSourceCommit'],'nativeSourceArchiveSha256':build['sourceArchiveSha256'],
 'walletSourceCommit':record['sourceCommit'],'walletSourceArchiveSha256':record['sourceArchiveSha256'],
 'pythonRequirement':'Python >=3.11; qualified '+platform.python_version(),'publicLaunchApproved':False,
 'connectionScope':'owner-operated two-device invitation rehearsal; LAN private peers; public HTTPS mining gateway',
 'nativeAuthentication':'per-participant restricted SSH tunnel; native RPC stays local',
 'nativeUpgradePolicy':'same native binary and network only; incompatible binding requires separate data',
 'bundledLibraryCount':len(list((stage/'lib').iterdir())),'noWalletOrDatabaseIncluded':True,
 'macSignature':'ad-hoc integrity signature; no Apple Developer ID/notarization' if mac else None}
(stage/'MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n')
after={label:sha(stage/'libexec'/label) for label in before}
for n,v in [('NATIVE_BUILD',build),('SOURCE',record),('NATIVE_BEFORE_RELOCATION',before),('NATIVE_AFTER_RELOCATION',after),('NETWORK',network)]:
 (stage/'provenance'/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
files=sorted(x for x in stage.rglob('*') if x.is_file())
(stage/'SHA256SUMS').write_text(''.join(sha(x)+'  '+x.relative_to(stage).as_posix()+'\n' for x in files))
archive=output/(name+'.tar.gz')
with tarfile.open(archive,'x:gz',compresslevel=3) as stream:
 for item in sorted(stage.rglob('*')):
  if item.is_file():stream.add(item,arcname=item.relative_to(stage).as_posix(),recursive=False)
descriptor={'schema':'meepcoin-signed-download/1','releaseVersion':a.version,'archive':archive.name,
 'sha256':sha(archive),'bytes':archive.stat().st_size,'platform':manifest['platform'],'genesis':manifest['genesisHash'],'files':len(files)+1}
(output/(name+'.json')).write_text(json.dumps(descriptor,indent=2)+'\n');print(json.dumps(descriptor),flush=True)
