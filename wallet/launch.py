#!/usr/bin/env python3
"""Start the local wallet using the installed release's verified identity.

The operator starts the exact local node separately. This launcher never starts
services, changes peers, opens an existing wallet or handles spending credentials.
Verify the downloaded archive against its published checksum before extraction;
SHA256SUMS detects local file corruption, not a malicious replacement publisher.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import sys

spec = importlib.util.spec_from_file_location('companion', Path(__file__).with_name('companion.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def verify_release(directory):
    root = directory.resolve(strict=True)
    manifest = json.loads((root / 'MANIFEST.json').read_text())
    if manifest.get('platform') != 'Debian 13 ARM64' or manifest.get('network') != 'testnet17':
        raise ValueError('Only the qualified Debian 13 ARM64 v17 release is supported by this launcher.')
    if platform.system() != 'Linux' or platform.machine() not in ('aarch64', 'arm64'):
        raise ValueError('This native release needs Linux ARM64. Windows/macOS native packages are not qualified.')
    os_release = platform.freedesktop_os_release()
    if os_release.get('ID') != 'debian' or os_release.get('VERSION_ID') != '13':
        raise ValueError('This packaged release is qualified on Debian 13 only.')
    if not c.HASH.fullmatch(manifest.get('genesisHash', '')):
        raise ValueError('Release genesis is invalid.')
    if not isinstance(manifest.get('nativeVersion'), str) or not manifest['nativeVersion']:
        raise ValueError('Release native version is missing.')
    checked = set()
    for line in (root / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match:
            raise ValueError('Malformed release checksum list.')
        digest, relative = match.groups()
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root) or relative in checked or not path.is_file():
            raise ValueError('Invalid or duplicate release checksum path.')
        hasher = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024**2), b''):
                hasher.update(block)
        if hasher.hexdigest() != digest:
            raise ValueError('Installed release file failed its checksum: ' + relative)
        checked.add(relative)
    required = {'MANIFEST.json', 'bin/meepcoin-wallet-rpc', 'libexec/meepcoin-wallet-rpc'}
    if not required <= checked:
        raise ValueError('Release checksum list does not cover the wallet or manifest.')
    return root, manifest, len(checked)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=Path, required=True)
    parser.add_argument('--wallet-dir', type=Path, required=True)
    parser.add_argument('--daemon-port', type=int, default=49081)
    parser.add_argument('--seconds', type=int, default=1800)
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    if not 1 <= args.daemon_port <= 65535 or not 60 <= args.seconds <= 3600:
        parser.error('Invalid loopback port or session lifetime (60-3600 seconds).')
    root, manifest, count = verify_release(args.release)
    daemon = c.RPC(args.daemon_port)
    info = daemon('get_info')
    header = daemon('get_block_header_by_height', {'height': 0})
    if info.get('status') != 'OK' or info.get('nettype') != 'testnet' or info.get('version') != manifest.get('nativeVersion'):
        raise ValueError('Local native node is not ready or has a different network/version.')
    if header.get('status') != 'OK' or header.get('block_header', {}).get('hash') != manifest['genesisHash']:
        raise ValueError('Local node genesis differs from the installed release. Wallet was not opened.')
    if args.verify_only:
        print(json.dumps({'status': 'INSTALLED_RELEASE_AND_LOCAL_NODE_IDENTITY_PASS', 'filesVerified': count,
                          'genesis': manifest['genesisHash'], 'nativeVersion': info['version'], 'walletOpened': False}))
        return
    os.execv(sys.executable, [sys.executable, str(Path(__file__).with_name('companion.py')),
        '--wallet-rpc', str(root / 'bin/meepcoin-wallet-rpc'), '--wallet-dir', str(args.wallet_dir),
        '--daemon-port', str(args.daemon_port), '--genesis', manifest['genesisHash'],
        '--network', 'testnet', '--seconds', str(args.seconds)])


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, c.WalletError) as error:
        raise SystemExit(str(error)) from None
