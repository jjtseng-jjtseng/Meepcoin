#!/usr/bin/env python3
"""Start/status/stop a finite participant node, private peer tunnel and local wallet.

Participant keys are generated on their own computer and never sent to the
operator. The approved peer descriptor contains a pinned SSH host public key.
This launcher changes no system service and never opens a wallet automatically.
"""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import stat
import subprocess
import sys
import time
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('launch', Path(__file__).with_name('launch.py'))
launch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launch)


def private(path):
    if path.is_symlink():
        raise ValueError('Private paths must not be symlinks.')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError('Private directory must be owned by you with mode 0700: ' + str(path))
    return path.resolve()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('start', 'status', 'stop', 'keygen'))
    p.add_argument('--data-dir', type=Path, required=True)
    p.add_argument('--release', type=Path)
    p.add_argument('--peer', type=Path, help='Operator-approved descriptor with pinned server key')
    p.add_argument('--seconds', type=int, default=1800)
    p.add_argument('--rpc-port', type=int, default=49081)
    p.add_argument('--peer-port', type=int, default=49080)
    a = p.parse_args()
    os.umask(0o077)
    root = private(a.data_dir)
    control = root / 'control.sock'
    if len(os.fsencode(control)) >= 100:
        raise ValueError('Choose a shorter data-directory path for the local control socket.')
    if a.action in ('status', 'stop'):
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(5)
            client.connect(str(control))
            client.sendall(a.action.encode('ascii'))
            print(client.recv(16384).decode('utf8'))
        return
    if a.action == 'keygen':
        key = root / 'participant-key'
        if key.exists() or key.with_suffix('.pub').exists():
            raise ValueError('Participant identity already exists; nothing was overwritten.')
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'meepcoin-private-participant',
                        '-f', str(key)], check=True, timeout=15)
        print(json.dumps({'status': 'PARTICIPANT_IDENTITY_CREATED', 'publicKeyFile': str(key.with_suffix('.pub')),
                          'privateKeyExported': False}))
        return
    if not a.release or not a.peer or not 60 <= a.seconds <= 3600:
        p.error('start requires --release, --peer and a 60-3600 second lifetime.')
    if not 1024 <= a.rpc_port <= 65535 or not 1024 <= a.peer_port <= 65535 or a.rpc_port == a.peer_port:
        p.error('Choose two different local ports from 1024-65535.')
    release, manifest, files = launch.verify_release(a.release)
    if root == release or root.is_relative_to(release) or release.is_relative_to(root):
        raise ValueError('Application and participant data must be in separate directories.')
    peer_info = a.peer.stat()
    if a.peer.is_symlink() or peer_info.st_uid != os.getuid() or stat.S_IMODE(peer_info.st_mode) & 0o077:
        raise ValueError('Peer descriptor must be owned by you with mode 0600.')
    peer = json.loads(a.peer.read_text())
    if peer.get('schema') != 'meepcoin-private-peer/1' or peer.get('genesis') != manifest['genesisHash']:
        raise ValueError('Peer descriptor belongs to another network.')
    ipaddress.ip_address(peer['host'])
    if not isinstance(peer['port'], int) or not 1024 <= peer['port'] <= 65535:
        raise ValueError('Invalid approved SSH port.')
    if peer['user'] != 'jjtseng' or peer['target'] != '127.0.0.1:49280':
        raise ValueError('Unsupported initial LAN peer route.')
    if not 0 < peer['expiresUtc'] - time.time() <= 24 * 3600:
        raise ValueError('Participant invitation has expired or has an invalid lifetime.')
    host_key = peer['hostPublicKey'].strip().split()
    if len(host_key) < 2 or host_key[0] != 'ssh-ed25519':
        raise ValueError('A pinned Ed25519 server key is required.')
    key = root / 'participant-key'
    if key.is_symlink() or key.stat().st_uid != os.getuid() or stat.S_IMODE(key.stat().st_mode) & 0o077:
        raise ValueError('Participant private key must be owned by you with mode 0600.')
    for port in (a.rpc_port, a.peer_port):
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(('127.0.0.1', port))
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(control))  # A stale socket is refused; never kill an unknown process.
    listener.listen(2)
    listener.settimeout(.2)
    run = private(root / ('session-' + secrets.token_hex(8)))
    known = run / 'known_hosts'
    known.write_text(f"[{peer['host']}]:{peer['port']} " + ' '.join(host_key[:2]) + '\n')
    logs, children, native_groups = [], [], []
    peak_rss = 0
    state = {'status': 'PARTICIPANT_STARTING', 'session': str(run), 'releaseVersion': manifest['releaseVersion'],
             'genesis': manifest['genesisHash'], 'seconds': a.seconds, 'filesVerified': files,
             'walletKeysLocal': True, 'rpcPubliclyExposed': False}
    stop_reason = 'startup_failed'
    def interrupted(*_):
        raise KeyboardInterrupt()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    def start(name, argv):
        log = (run / (name + '.log')).open('xb')
        logs.append(log)
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        children.append((name, child))
        return child
    def live():
        nonlocal stop_reason
        for name, child in children:
            if child.poll() is not None:
                stop_reason = 'unexpected_' + name + '_exit'
                raise ValueError('A participant process exited. Inspect session logs; no automatic restart.')
    deadline = min(time.monotonic() + a.seconds, time.monotonic() + peer['expiresUtc'] - time.time())
    try:
        ssh = start('peer', ['ssh', '-F', '/dev/null', '-N', '-T', '-o', 'BatchMode=yes',
            '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'UserKnownHostsFile=' + str(known),
            '-o', 'ExitOnForwardFailure=yes', '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=10',
            '-o', 'ServerAliveCountMax=2', '-i', str(key), '-p', str(peer['port']),
            '-L', f"127.0.0.1:{a.peer_port}:{peer['target']}", peer['user'] + '@' + peer['host']])
        until = min(deadline, time.monotonic() + 12)
        while True:
            live()
            try:
                with socket.create_connection(('127.0.0.1', a.peer_port), timeout=.2):
                    break
            except OSError:
                if time.monotonic() >= until:
                    raise ValueError('Private peer tunnel did not become ready.')
                time.sleep(.2)
        start('node', [sys.executable, '-B', str(release / 'wallet/node.py'), '--release', str(release),
            '--data-dir', str(root / 'node'), '--rpc-port', str(a.rpc_port), '--peer-port', str(a.peer_port),
            '--seconds', str(a.seconds)])
        daemon = launch.c.RPC(a.rpc_port)
        until = min(deadline, time.monotonic() + 60)
        while True:
            live()
            try:
                info = daemon('get_info')
                header = daemon('get_block_header_by_height', {'height': 0})
                if (info.get('nettype') != 'testnet' or info.get('version') != manifest['nativeVersion']
                        or header.get('block_header', {}).get('hash') != manifest['genesisHash']):
                    raise ValueError('Local node identity differs from the release.')
                if info.get('outgoing_connections_count', 0) > 0:
                    break
            except launch.c.WalletError:
                pass
            if time.monotonic() >= until:
                raise ValueError('Local node did not establish its approved private peer connection.')
            time.sleep(.3)
        for line in (run / 'node.log').read_text().splitlines():
            if line.startswith('{'):
                native = json.loads(line)
                if native.get('status') == 'PARTICIPANT_LOCAL_NODE_READY':
                    native_groups.append(native['nativePid'])
        start('wallet', [sys.executable, '-B', str(release / 'wallet/launch.py'), '--release', str(release),
            '--wallet-dir', str(root / 'wallets'), '--daemon-port', str(a.rpc_port), '--seconds', str(a.seconds)])
        until = min(deadline, time.monotonic() + 45)
        while 'LOCAL_WALLET_READY' not in (run / 'wallet.log').read_text(errors='replace'):
            live()
            if time.monotonic() >= until:
                raise ValueError('Local wallet did not become ready.')
            time.sleep(.2)
        process_files = sorted((root / 'wallets').glob('session-*/PROCESS.json'), key=lambda path: path.stat().st_mtime)
        native_groups.append(json.loads(process_files[-1].read_text())['nativePid'])
        state.update(status='PARTICIPANT_READY', height=info['height'],
                     privatePeers=info['outgoing_connections_count'],
                     openFile=str(root / 'wallets/OPEN_WALLET.html'))
        (run / 'READY.json').write_text(json.dumps(state, indent=2) + '\n')
        print(json.dumps(state), flush=True)
        stop_reason = 'deadline'
        next_resource_check = 0
        while time.monotonic() < deadline:
            live()
            if time.monotonic() >= next_resource_check:
                rss = subprocess.run(['ps', '-o', 'rss=', '-p', ','.join(map(str, native_groups))],
                                     capture_output=True, text=True, timeout=5, check=True)
                total_rss = sum(int(value) for value in rss.stdout.split())
                peak_rss = max(peak_rss, total_rss)
                state['nativeRssKiB'] = total_rss
                if total_rss > 2 * 1024**2:
                    stop_reason = 'memory_budget'
                    raise ValueError('Native processes exceeded the 2 GiB participant memory budget.')
                next_resource_check = time.monotonic() + 2
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            with client:
                client.settimeout(2)
                request = client.recv(16)
                if request == b'stop':
                    stop_reason = 'participant_stop'
                    client.sendall(json.dumps({'status': 'STOP_REQUEST_ACCEPTED'}).encode())
                    break
                current = daemon('get_info')
                state.update(height=current.get('height'), targetHeight=current.get('target_height'),
                             privatePeers=current.get('outgoing_connections_count'),
                             synchronized=current.get('synchronized'))
                client.sendall(json.dumps(state).encode())
    except KeyboardInterrupt:
        stop_reason = 'participant_stop'
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        clean = True
        exits = {}
        for name, child in reversed(children):
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=40)
            except subprocess.TimeoutExpired:
                clean = False
                child.kill()
                child.wait(timeout=10)
            exits[name] = child.returncode
        native_empty = True
        for group in native_groups:
            try:
                os.killpg(group, 0)
                native_empty = False
            except ProcessLookupError:
                pass
        clean = clean and native_empty
        for log in logs:
            log.close()
        listener.close()
        control.unlink()
        result = {'status': 'PARTICIPANT_STOPPED' if clean else 'PARTICIPANT_CLEANUP_FAILED',
                  'reason': stop_reason, 'controllerExitCodes': exits, 'controllersExited': True,
                  'gracefulCleanup': clean, 'walletAndDatabaseRetained': True, 'automaticRestart': False}
        result.update(ownedNativeGroupsEmpty=native_empty, nativeGroupsChecked=len(native_groups), peakNativeRssKiB=peak_rss)
        (run / 'STOPPED.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)
        if not clean:
            raise ValueError('A child controller did not finish graceful cleanup; inspect process receipts.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.SubprocessError, launch.c.WalletError) as error:
        raise SystemExit(str(error)) from None
