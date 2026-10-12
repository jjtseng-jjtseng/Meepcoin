"""Verify ARM64 SDK archives against the qualified toolchain receipt before compiling."""
import hashlib,json,platform,sys
from pathlib import Path
manifest=json.loads((Path(__file__).parent/'wasm-toolchain.json').read_text())
if platform.machine() not in ['aarch64','arm64']:raise SystemExit('Only qualified ARM64 SDK archives are pinned')
sdk=Path(sys.argv[1]).resolve(strict=True)
for item in manifest['linuxArm64Downloads']:
 name=item['url'].rsplit('/',1)[-1]
 cached=(manifest['emsdk']['releaseBuild']+'-'+name) if name.startswith('wasm-binaries-') else name
 path=sdk/'downloads'/cached
 if not path.is_file():raise SystemExit('Keep SDK downloads: set EMSDK_KEEP_DOWNLOADS=1 before install')
 if path.stat().st_size!=item['bytes'] or hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']:
  raise SystemExit('SDK integrity mismatch: '+name)
 print(name+' verified')
