#!/usr/bin/env python3
"""Bounded ARM64 macOS native build in a private dependency prefix; no sudo."""
import argparse, hashlib, json, os, platform, resource, signal, subprocess, tarfile, time, urllib.request
from pathlib import Path

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--genesis', type=int, required=True)
    p.add_argument('--source-sha256', required=True)
    p.add_argument('--resume-expat-fix', action='store_true', help='Resume the preserved expat configure failure with the Xcode SDK path')
    p.add_argument('--resume-built-unbound', action='store_true', help='Resume the preserved install-target error after successful unbound build')
    a = p.parse_args()
    resume = a.resume_expat_fix or a.resume_built_unbound
    assert platform.system() == 'Darwin' and platform.machine() == 'arm64'
    root = a.root.resolve(strict=True)
    source = root / 'native-source'
    if resume:
        assert json.loads((root / 'unbound-configure.json').read_text())['exitCode'] != 0
    else:
        source.mkdir(mode=0o700, exist_ok=False)
    archive = root / 'native-source.tar'
    assert sha(archive) == a.source_sha256
    if not resume:
        with tarfile.open(archive) as tar:
            tar.extractall(source, filter='data')
    deps = root / 'deps'
    downloads = root / 'downloads'
    downloads.mkdir(mode=0o700, exist_ok=resume)
    inputs = []
    for item in json.loads((source / 'scripts/private/native-dependencies.json').read_text())['dependencies']:
        path = downloads / (item['commit'] + '.tar.gz')
        if not resume:
            with urllib.request.urlopen(item['url'], timeout=45) as response:
                path.write_bytes(response.read(16777217))
        assert path.stat().st_size == item['bytes'] and sha(path) == item['sha256']
        target = source / 'native/core' / item['destination']
        target.mkdir(parents=True, exist_ok=True)
        with tarfile.open(path) as tar:
            members = tar.getmembers()
            prefix = members[0].name.split('/')[0] + '/'
            for member in members:
                if member.name.rstrip('/') == prefix.rstrip('/'):
                    continue
                assert member.name.startswith(prefix)
                member.name = member.name[len(prefix):]
                if not resume:
                    tar.extract(member, target, filter='data')
        inputs.append(item)
    unbound = downloads / 'unbound-1.26.1.tar.gz'
    url = 'https://nlnetlabs.nl/downloads/unbound/unbound-1.26.1.tar.gz'
    expected = '35a6dc0e425a9282c3426d9a3043144011bf0534aed4b73ab62c52aee0af1503'
    if not resume:
        with urllib.request.urlopen(url, timeout=45) as response:
            unbound.write_bytes(response.read(16777217))
    assert sha(unbound) == expected
    if not resume:
        with tarfile.open(unbound) as tar:
            tar.extractall(root, filter='data')
    env = dict(os.environ, PATH=str(deps / 'bin') + ':/usr/bin:/bin:/usr/sbin:/sbin',
               PKG_CONFIG_PATH=str(deps / 'lib/pkgconfig'), LC_ALL='C')
    receipts = []
    def limits():
        os.nice(10)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (2400, 2400))
        resource.setrlimit(resource.RLIMIT_FSIZE, (512 * 1024**2,) * 2)
    def run(name, argv, seconds, cwd=None):
        if a.resume_built_unbound and name in ('unbound-configure', 'unbound-build'):
            prior = json.loads((root / (name + '-v2.json')).read_text())
            assert prior['exitCode'] == 0 and prior['ownedGroupEmpty']
            receipts.append(prior)
            return
        if a.resume_built_unbound:
            name += '-v3'
        elif a.resume_expat_fix:
            name += '-v2'
        began = time.monotonic()
        with (root / (name + '.log')).open('xb') as output:
            child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL, start_new_session=True, preexec_fn=limits)
            try:
                code = child.wait(timeout=seconds)
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=15)
                try:
                    os.killpg(child.pid, 0)
                    empty = False
                except ProcessLookupError:
                    empty = True
                receipt = {'name': name, 'argv': argv, 'exitCode': child.returncode,
                           'elapsedSeconds': time.monotonic() - began, 'ownedGroupEmpty': empty}
                (root / (name + '.json')).write_text(json.dumps(receipt, indent=2) + '\n')
                receipts.append(receipt)
        if code or not empty:
            raise RuntimeError(name + ' failed; see preserved log')
    sdk = subprocess.check_output(['/usr/bin/xcrun', '--show-sdk-path'], text=True).strip()
    run('unbound-configure', ['./configure', '--prefix=' + str(deps), '--with-ssl=' + str(deps),
        '--without-libevent', '--with-libexpat=' + sdk + '/usr', '--without-libnghttp2', '--without-python',
        '--without-pyunbound', '--disable-flto', '--enable-shared', '--disable-static'], 120, root / 'unbound-1.26.1')
    run('unbound-build', ['make', '-j2', 'libunbound.la'], 600, root / 'unbound-1.26.1')
    run('unbound-install', ['make', 'install-lib'], 60, root / 'unbound-1.26.1')
    cmake = str(deps / 'bin/cmake')
    build = root / 'native-build'
    run('native-configure', [cmake, '-S', str(source / 'native/core'), '-B', str(build), '-G', 'Ninja',
        '-DCMAKE_BUILD_TYPE=Release', '-DOPT_FLAGS_RELEASE=-O1 -g0', '-DSTATIC=OFF',
        '-DCMAKE_C_COMPILER=/usr/bin/clang', '-DCMAKE_CXX_COMPILER=/usr/bin/clang++',
        '-DCMAKE_PREFIX_PATH=' + str(deps), '-DOPENSSL_ROOT_DIR=' + str(deps),
        '-DBOOST_ROOT=' + str(deps), '-DBoost_NO_SYSTEM_PATHS=ON',
        '-DUNBOUND_INCLUDE_DIR=' + str(deps / 'include'),
        '-DUNBOUND_LIBRARIES=' + str(deps / 'lib/libunbound.dylib'),
        '-DCMAKE_POLICY_DEFAULT_CMP0167=OLD', '-DMANUAL_SUBMODULES=ON',
        '-DUSE_DEVICE_TREZOR=OFF', '-DUSE_READLINE=OFF', '-DBUILD_TESTS=OFF',
        '-DBUILD_GUI_DEPS=OFF', '-DUSE_CCACHE=OFF', '-DMEEPCOIN_TESTNET17=ON',
        '-DMEEPCOIN_TESTNET17_GENESIS_TIMESTAMP=' + str(a.genesis),
        '-DMEEPCOIN_MEEPOW_DIR=' + str(source / 'meepow')], 180)
    run('native-build', [cmake, '--build', str(build), '--target', 'daemon',
                        'wallet_rpc_server', 'simplewallet', '--parallel', '2'], 2400)
    binaries = {name: sha(build / 'bin' / name) for name in
                ('meepcoind', 'meepcoin-wallet-rpc', 'meepcoin-wallet-cli')}
    (root / 'BUILD.json').write_text(json.dumps({'status': 'MAC_ARM64_NATIVE_BUILD_PASS',
        'host': platform.platform(), 'genesisUtcUnix': a.genesis, 'sourceArchiveSha256': a.source_sha256,
        'dependencies': inputs, 'unbound': {'url': url, 'sha256': expected},
        'binaries': binaries, 'receipts': receipts, 'systemPackagesChanged': False}, indent=2) + '\n')
    print('MAC_ARM64_NATIVE_BUILD_PASS', flush=True)

if __name__ == '__main__':
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    main()
