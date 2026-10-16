#!/usr/bin/env python3
"""Verify, select a compatible update, or remove application files while keeping data."""
import argparse, hashlib, importlib.util, json, os, pathlib, secrets, shutil, subprocess, sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('launch', pathlib.Path(__file__).with_name('launch.py'))
launch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launch)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('verify', 'upgrade', 'remove'))
    p.add_argument('--release', type=pathlib.Path, required=True)
    p.add_argument('--data-dir', type=pathlib.Path)
    p.add_argument('--from-release', type=pathlib.Path)
    a = p.parse_args()
    os.umask(0o077)
    release, manifest, count = launch.verify_release(a.release)
    if a.action == 'verify':
        versions = {}
        for name in ('meepcoind', 'meepcoin-wallet-rpc', 'meepcoin-wallet-cli'):
            result = subprocess.run([str(release / 'bin' / name), '--version'], capture_output=True, text=True, timeout=15, check=True)
            if manifest['nativeVersion'] not in result.stdout:
                raise ValueError('Native executable version differs from the release: ' + name)
            versions[name] = manifest['nativeVersion']
        print(json.dumps({'status': 'PARTICIPANT_RELEASE_PREFLIGHT_PASS', 'filesVerified': count,
                          'releaseVersion': manifest['releaseVersion'], 'python': sys.version.split()[0],
                          'nativeProgramsLoaded': versions, 'freeBytes': shutil.disk_usage(release).free}))
        return
    if a.data_dir is None:
        p.error('upgrade/remove require the separate participant --data-dir.')
    data = a.data_dir.resolve(strict=True)
    if (data / 'control.sock').exists():
        raise ValueError('Stop the participant session and wait for PARTICIPANT_STOPPED first.')
    if release == data or release.is_relative_to(data) or data.is_relative_to(release):
        raise ValueError('Application and participant data directories must be separate.')
    if a.action == 'upgrade':
        if a.from_release is None:
            p.error('upgrade requires --from-release.')
        previous, before, _ = launch.verify_release(a.from_release)
        for field in ('platform', 'network', 'genesisHash', 'nativeVersion'):
            if before[field] != manifest[field]:
                raise ValueError('Incompatible network/platform update refused; data was not changed.')
        sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        for name in ('meepcoind', 'meepcoin-wallet-rpc', 'meepcoin-wallet-cli'):
            if sha(previous / 'libexec' / name) != sha(release / 'libexec' / name):
                raise ValueError('This initial release supports companion-only updates. Native changes require separate qualification.')
        selected = data / 'SELECTED_RELEASE.json'
        if selected.is_symlink():
            raise ValueError('Selected release must not be a symlink.')
        temporary = data / ('select-' + secrets.token_hex(8) + '.json')
        value = {'status': 'COMPATIBLE_PARTICIPANT_UPDATE_SELECTED', 'from': str(previous), 'release': str(release),
                 'releaseVersion': manifest['releaseVersion'], 'genesis': manifest['genesisHash'], 'walletAndDatabaseRetained': True}
        with temporary.open('x') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, selected)
        print(json.dumps(value))
        return
    # Only a fully verified application can be removed. Rename first, then delete
    # that exact sibling; the separate data directory is never a removal target.
    parent = release.parent.resolve(strict=True)
    quarantine = parent / ('.removed-' + release.name + '-' + secrets.token_hex(8))
    assert quarantine.parent == parent and not quarantine.exists()
    os.rename(release, quarantine)
    assert quarantine.resolve(strict=True).parent == parent
    assert not data.is_relative_to(quarantine) and not quarantine.is_relative_to(data)
    shutil.rmtree(quarantine)
    value = {'status': 'PARTICIPANT_APPLICATION_REMOVED', 'removed': str(release), 'retainedData': str(data),
             'walletAndDatabaseRetained': data.is_dir(), 'privateParticipantKeyRetained': (data / 'participant-key').is_file()}
    (parent / (release.name + '-REMOVAL.json')).write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps(value))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.SubprocessError, launch.c.WalletError) as error:
        raise SystemExit(str(error)) from None
