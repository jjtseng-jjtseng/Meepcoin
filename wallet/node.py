#!/usr/bin/env python3
"""Run the verified participant node with private loopback RPC and a finite lifetime.

Use either an operator-provided private SSH-forwarded peer port or --offline.
This starts no system service, mines nothing, handles no wallet keys and never
resets a database. A different release identity requires a new data directory.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import platform
from pathlib import Path
import secrets
import signal
import socket
import stat
import subprocess
import sys
import time
sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location('wallet_launch', Path(__file__).with_name('launch.py'))
launch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launch)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=Path, required=True)
    parser.add_argument('--data-dir', type=Path, required=True)
    parser.add_argument('--rpc-port', type=int, default=49081)
    parser.add_argument('--seconds', type=int, default=1800)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--peer-port', type=int, help='Existing operator-approved SSH forward on 127.0.0.1')
    mode.add_argument('--offline', action='store_true', help='Open only a local chain; no peers or mining')
    args = parser.parse_args()
    if not 1024 <= args.rpc_port <= 65535 or not 60 <= args.seconds <= 3600:
        parser.error('RPC port must be 1024-65535 and lifetime 60-3600 seconds.')
    if args.peer_port is not None and (not 1024 <= args.peer_port <= 65535 or args.peer_port == args.rpc_port):
        parser.error('Private peer port must be 1024-65535 and differ from RPC.')
    os.umask(0o077)
    release, manifest, count = launch.verify_release(args.release)
    checksums = (release / 'SHA256SUMS').read_text().splitlines()
    for name in ('bin/meepcoind', 'libexec/meepcoind'):
        if not any(row.endswith('  ' + name) for row in checksums):
            raise ValueError('Release checksum list must cover the native node and its wrapper.')
    # Refuse an already occupied RPC port before creating any persistent files.
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(('127.0.0.1', args.rpc_port))
    original = args.data_dir.absolute()
    if original.is_symlink():
        raise ValueError('Node directory must not be a symlink.')
    root = original.resolve()
    if root == release or root.is_relative_to(release):
        raise ValueError('Node data must be outside the verified release.')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = root.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError('Node directory must be owned by you with mode 0700.')
    identity = {'schema': 'meepcoin-participant-node/1', 'network': 'testnet',
                'genesis': manifest['genesisHash'], 'nativeVersion': manifest['nativeVersion'],
                'nativeSha256': hashlib.sha256((release / 'libexec/meepcoind').read_bytes()).hexdigest()}
    binding = root / 'NODE_IDENTITY.json'
    if binding.is_symlink():
        raise ValueError('Node identity must not be a symlink.')
    if binding.exists():
        if json.loads(binding.read_text()) != identity:
            raise ValueError('Node directory belongs to a different release. Use a new directory; no reset was performed.')
    else:
        if any(root.iterdir()):
            raise ValueError('Unbound existing data is refused. Use a new participant node directory.')
        with binding.open('x') as stream:
            json.dump(identity, stream)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        fd = os.open(root, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    run = root / ('node-session-' + secrets.token_hex(8))
    run.mkdir(mode=0o700)
    config = run / 'empty.conf'
    config.write_text('')
    child = None
    output = None
    reason = 'startup_failed'
    def interrupted(*_):
        raise KeyboardInterrupt()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    def limits():
        import resource
        os.nice(10)
        if platform.system() == 'Linux':
            resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024**2,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (args.seconds + 30,) * 2)
    p2p_port = launch.c.free_port()
    while p2p_port in (args.rpc_port, args.peer_port):
        p2p_port = launch.c.free_port()
    argv = [str(release / 'bin/meepcoind'), '--config-file', str(config), '--testnet',
            '--data-dir', str(root / 'chain'), '--no-zmq', '--disable-dns-checkpoints',
            '--check-updates', 'disabled', '--no-igd', '--in-peers', '0', '--hide-my-port',
            '--p2p-bind-ip', '127.0.0.1', '--p2p-bind-port', str(p2p_port),
            '--rpc-bind-ip', '127.0.0.1', '--rpc-bind-port', str(args.rpc_port), '--rpc-ssl', 'disabled',
            '--max-concurrency', '1', '--prep-blocks-threads', '1', '--non-interactive',
            '--log-file', str(run / 'native.log'), '--log-level', '0',
            '--max-log-files', '1', '--max-log-file-size', '1048576']
    argv += ['--offline', '--out-peers', '0'] if args.offline else [
        '--allow-local-ip', '--out-peers', '1', '--add-exclusive-node', '127.0.0.1:' + str(args.peer_port)]
    try:
        output = (run / 'process.log').open('xb')
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                 start_new_session=True, preexec_fn=limits)
        began = time.monotonic()
        deadline = began + args.seconds
        daemon = launch.c.RPC(args.rpc_port)
        while True:
            if child.poll() is not None:
                raise ValueError('Native node exited during startup; inspect this session log.')
            try:
                state = daemon('get_info')
                genesis = daemon('get_block_header_by_height', {'height': 0})
                if state.get('status') != 'OK' or state.get('nettype') != 'testnet' or state.get('version') != identity['nativeVersion']:
                    raise ValueError('Native node network or version differs from the verified release.')
                if genesis.get('status') != 'OK' or genesis.get('block_header', {}).get('hash') != identity['genesis']:
                    raise ValueError('Native node genesis differs from the verified release.')
                break
            except launch.c.WalletError:
                if time.monotonic() >= min(began + 45, deadline):
                    raise ValueError('Native node identity startup deadline expired.') from None
                time.sleep(.2)
        ready = {**identity, 'status': 'PARTICIPANT_LOCAL_NODE_READY', 'filesVerified': count,
                 'rpcOrigin': 'http://127.0.0.1:' + str(args.rpc_port), 'offline': args.offline,
                 'privatePeerPort': args.peer_port, 'seconds': args.seconds, 'nativePid': child.pid,
                 'rpcPubliclyExposed': False, 'miningStarted': False}
        (run / 'READY.json').write_text(json.dumps(ready, indent=2) + '\n')
        print(json.dumps(ready), flush=True)
        reason = 'deadline'
        while time.monotonic() < deadline:
            if child.poll() is not None:
                reason = 'unexpected_native_exit'
                raise ValueError('Native node exited; no automatic restart will occur.')
            time.sleep(.2)
    except KeyboardInterrupt:
        reason = 'operator_stop'
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        empty = child is None
        if child is not None:
            for sig, seconds in ((signal.SIGTERM, 30), (signal.SIGKILL, 10)):
                try:
                    os.killpg(child.pid, sig)
                except ProcessLookupError:
                    pass
                end = time.monotonic() + seconds
                while time.monotonic() < end:
                    child.poll()
                    try:
                        os.killpg(child.pid, 0)
                    except ProcessLookupError:
                        empty = True
                        break
                    time.sleep(.1)
                if empty:
                    break
        if output:
            output.close()
        stopped = {'status': 'PARTICIPANT_LOCAL_NODE_STOPPED', 'reason': reason,
                   'nativeExitCode': child.returncode if child else None, 'ownedGroupEmpty': empty,
                   'databaseRetained': True, 'automaticRestart': False}
        (run / 'STOPPED.json').write_text(json.dumps(stopped, indent=2) + '\n')
        print(json.dumps(stopped), flush=True)
        if not empty:
            raise ValueError('Owned node process group did not finish cleanup.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, launch.c.WalletError) as error:
        raise SystemExit(str(error)) from None
