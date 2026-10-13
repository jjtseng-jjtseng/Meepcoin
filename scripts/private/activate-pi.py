#!/usr/bin/env python3
"""Verify and install a new root-owned Pi release without starting any service."""
import argparse,hashlib,json,os,pwd,stat,subprocess,tarfile
from pathlib import Path,PurePosixPath

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--archive',type=Path,required=True);p.add_argument('--sha256',required=True)
 p.add_argument('--replace-current-archive-sha256')
 a=p.parse_args();assert os.geteuid()==0,'root required'
 assert len(a.sha256)==64 and all(x in '0123456789abcdef' for x in a.sha256)
 assert hashlib.sha256(a.archive.read_bytes()).hexdigest()==a.sha256,'archive hash mismatch'
 current=Path('/opt/meepcoin/current');receipt=Path('/etc/meepcoin/RELEASE.json');old=None
 if os.path.lexists(current):
  assert a.replace_current_archive_sha256,'explicit current archive digest required for replacement'
  old=json.loads(receipt.read_text());assert old['archiveSha256']==a.replace_current_archive_sha256
  assert current.is_symlink() and str(current.resolve(strict=True))==old['release']
 else:assert not receipt.exists() and not a.replace_current_archive_sha256
 for name in ['meepcoin-node.service','meepcoin-gateway.service','meepcoin-tunnel.service']:
  assert subprocess.run(['systemctl','is-active','--quiet',name]).returncode!=0,'service already running'
 identity=pwd.getpwnam('meepcoin');base=Path('/opt/meepcoin/releases')
 assert base.is_dir() and not base.is_symlink() and base.stat().st_uid==0
 os.chown(base,0,identity.pw_gid);base.chmod(0o750)
 with tarfile.open(a.archive) as stream:
  members=stream.getmembers();assert 1<=len(members)<=10000
  names=set();prefix=None;total=0
  for member in members:
   rel=PurePosixPath(member.name);assert not rel.is_absolute() and '..' not in rel.parts
   assert member.name not in names,'duplicate archive member';names.add(member.name)
   assert member.isdir() or member.isfile(),'archive links/devices refused'
   prefix=prefix or rel.parts[0];assert rel.parts[0]==prefix
   total+=member.size;assert total<=512*1024**2
  assert prefix.startswith('meepcoin-v17-') and len(prefix)<120
  destination=base/prefix;assert not destination.exists(),'release target exists'
  stream.extractall(base,filter='data')
 manifest=json.loads((destination/'MANIFEST.json').read_text())
 assert manifest['schema']=='meepcoin-invitation-release/1' and manifest['network']=='testnet17'
 assert manifest['noWalletOrDatabaseIncluded'] and not manifest['publicLaunchApproved']
 assert manifest['intendedOrigin']=='https://mine.meepcoin.me'
 if old:assert manifest['genesisHash']==old['genesisHash'],'network replacement requires a separate reset procedure'
 # Each manifest file is independently checked before the current symlink exists.
 subprocess.run(['sha256sum','--status','-c','SHA256SUMS'],cwd=destination,check=True)
 for path in [destination,*destination.rglob('*')]:
  assert not path.is_symlink()
  os.chown(path,0,identity.pw_gid)
  executable=path.is_file() and path.parent.name in ['bin','libexec']
  path.chmod(0o750 if path.is_dir() or executable else 0o640)
 for name in ['meepcoin-node.service','meepcoin-gateway.service','meepcoin-tunnel.service']:
  active=subprocess.run(['systemctl','is-active','--quiet',name])
  assert active.returncode!=0,'service already running'
 if old:
  backup=receipt.with_name('RELEASE-'+old['archiveSha256']+'.json')
  with backup.open('x') as stream:stream.write(json.dumps(old,indent=2)+'\n')
  backup.chmod(0o600)
 pending=current.with_name('current.pending');assert not os.path.lexists(pending)
 pending.symlink_to(destination,target_is_directory=True);os.replace(pending,current)
 # Node resolves its entry module through symlinks, while argv retains the
 # supplied path. Use the concrete immutable release path for the CLI guard.
 gateway=Path('/etc/meepcoin/gateway.json');cfg=json.loads(gateway.read_text())
 cfg['argv'][2]=str(destination/'source/pool/private/testnet_service.mjs')
 gateway.write_text(json.dumps(cfg,indent=2)+'\n')
 result={'status':'HASH_VERIFIED_ROOT_OWNED_V17_RELEASE_INSTALLED_SERVICES_STOPPED',
  'archiveSha256':a.sha256,'release':str(destination),'genesisHash':manifest['genesisHash'],
  'genesisUtcUnix':manifest['genesisUtcUnix'],'nativeVersion':manifest['nativeVersion'],
  'servicesStarted':False,'bootEnabled':False}
 receipt.write_text(json.dumps(result,indent=2)+'\n');receipt.chmod(0o640);os.chown(receipt,0,identity.pw_gid)
 print(json.dumps(result),flush=True)

if __name__=='__main__':main()
