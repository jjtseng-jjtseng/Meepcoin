#!/usr/bin/env python3
"""Install a publisher-signed participant archive into a new private directory.

Obtain the publisher public key through an authenticated channel first. A key
downloaded alongside an archive does not authenticate its publisher. This tool
does not alter shell profiles, services, existing releases, wallets or databases.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def download(url, destination, limit):
    with urllib.request.urlopen(url, timeout=30) as source, destination.open('xb') as target:
        count = 0
        while block := source.read(1024 * 1024):
            count += len(block)
            if count > limit:
                raise ValueError('Download exceeds the release size limit.')
            target.write(block)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--descriptor-url', required=True)
    parser.add_argument('--publisher-key', type=Path, required=True, help='Previously authenticated Ed25519 PUBLIC key')
    parser.add_argument('--destination', type=Path, required=True, help='New application directory; data goes elsewhere')
    args = parser.parse_args()
    if sys.version_info < (3, 11):
        parser.error('Python 3.11 or later is required.')
    os.umask(0o077)
    key = args.publisher_key.read_text().strip().split()
    if len(key) < 2 or key[0] != 'ssh-ed25519':
        raise ValueError('An authenticated Ed25519 publisher public key is required.')
    destination = args.destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError('Installation destination already exists; nothing was overwritten.')
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = destination.parent.resolve(strict=True)
    if parent.stat().st_uid != os.getuid() or stat.S_IMODE(parent.stat().st_mode) & 0o077:
        raise ValueError('Installation parent must be owned by you with mode 0700.')
    if shutil.disk_usage(parent).free < 1024**3:
        raise ValueError('At least 1 GiB of free storage is required for installation.')
    with tempfile.TemporaryDirectory(prefix='.meepcoin-download-', dir=parent) as temporary:
        work = Path(temporary)
        descriptor, signature = work / 'release.json', work / 'release.json.sig'
        download(args.descriptor_url, descriptor, 64 * 1024)
        download(args.descriptor_url + '.sig', signature, 16 * 1024)
        allowed = work / 'allowed-signers'
        allowed.write_text('meepcoin ' + ' '.join(key[:2]) + '\n')
        verified = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(allowed), '-I', 'meepcoin',
                                   '-n', 'meepcoin-release', '-s', str(signature)],
                                  input=descriptor.read_bytes(), capture_output=True, timeout=15)
        if verified.returncode:
            raise ValueError('Publisher signature did not verify. Nothing was installed.')
        release = json.loads(descriptor.read_text())
        if release.get('schema') != 'meepcoin-signed-download/1':
            raise ValueError('Unknown signed release descriptor.')
        archive = work / 'release.tar.gz'
        archive_name = release['archive']
        if PurePosixPath(archive_name).name != archive_name or not archive_name.endswith('.tar.gz'):
            raise ValueError('Invalid signed archive name.')
        base = args.descriptor_url.rsplit('/', 1)[0] + '/'
        download(base + archive_name, archive, 512 * 1024**2)
        if archive.stat().st_size != release['bytes'] or digest(archive) != release['sha256']:
            raise ValueError('Downloaded archive differs from the signed release.')
        staging = work / 'application'
        staging.mkdir(mode=0o700)
        total = 0
        seen = set()
        with tarfile.open(archive, 'r:gz') as stream:
            for member in stream:
                relative = PurePosixPath(member.name)
                if (relative.is_absolute() or not relative.parts or any(p in ('..', '.') for p in relative.parts)
                        or member.name in seen or not (member.isfile() or member.isdir())):
                    raise ValueError('Archive has an unsafe, duplicate or linked path.')
                seen.add(member.name)
                target = staging.joinpath(*relative.parts)
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                total += member.size
                if member.size < 0 or total > 1536 * 1024**2:
                    raise ValueError('Archive expands beyond the installation limit.')
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with stream.extractfile(member) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o700 if member.mode & 0o111 else 0o600)
        # The signed archive covers the verifier too. Run it before publishing.
        code = ('import importlib.util,pathlib; p=pathlib.Path(__import__("sys").argv[1]); '
                's=importlib.util.spec_from_file_location("launch",p/"wallet/launch.py"); '
                'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); '
                'r,x,n=m.verify_release(p); print(n)')
        check = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(staging)], capture_output=True, text=True, timeout=60)
        if check.returncode:
            raise ValueError('Release preflight failed: ' + check.stderr.strip())
        if json.loads((staging / 'MANIFEST.json').read_text())['releaseVersion'] != release['releaseVersion']:
            raise ValueError('Release manifest and signed descriptor disagree.')
        os.rename(staging, destination)
        receipt = {'status': 'SIGNED_PARTICIPANT_INSTALL_PASS', 'directory': str(destination),
                   'releaseVersion': release['releaseVersion'], 'archiveSha256': release['sha256'],
                   'publisherSignatureVerified': True, 'filesVerified': int(check.stdout.strip()),
                   'walletOrDatabaseCreated': False}
        receipt_path = destination.with_name(destination.name + '-INSTALL.json')
        with receipt_path.open('x') as output:
            json.dump(receipt, output, indent=2)
            output.write('\n')
        print(json.dumps(receipt))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.SubprocessError, tarfile.TarError) as error:
        raise SystemExit(str(error)) from None
