"""Actual native controller-death regressions on disposable participant data.

Never reads a seed or password. Uses a verified release, owned child handles and
private run directories. A failed result is retained and never converted to pass.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import threading
import urllib.request
import urllib.parse
import re

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('launch', Path(__file__).with_name('launch.py'))
launch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launch)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--release', type=Path, required=True)
    p.add_argument('--run-dir', type=Path, required=True)
    p.add_argument('--peer', type=Path)
    p.add_argument('--participant-key', type=Path)
    a = p.parse_args()
    os.umask(0o077)
    root = a.run_dir.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    release, manifest, count = launch.verify_release(a.release)
    children, logs, rows = [], [], []
    def save(name, data):
        with (root / name).open('x') as stream:
            json.dump(data, stream, indent=2)
            stream.write('\n')
    def start(name, argv):
        output = (root / (name + '.log')).open('xb')
        logs.append(output)
        child = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, start_new_session=True)
        children.append(child)
        return child
    def until(fn, seconds=60):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            value = fn()
            if value:
                return value
            time.sleep(.1)
        raise AssertionError('Checkpoint deadline expired')
    def guards(directory):
        return list(directory.rglob('*GUARD_STOPPED.json'))
    def drained(directory, expected):
        found = guards(directory)
        return len(found) >= expected and all(json.loads(path.read_text())['ownedGroupDrained'] is True
                                              and json.loads(path.read_text()).get('error') is None for path in found)
    def kill_controller(child, directory, expected):
        began = time.monotonic()
        child.kill()
        child.wait(timeout=5)
        until(lambda: drained(directory, expected), 45)
        elapsed = time.monotonic() - began
        assert elapsed < 45
        return elapsed
    sentinel = start('unrelated-sentinel', [sys.executable, '-c', 'import time;time.sleep(600)'])
    port = launch.c.free_port()
    data = root / 'data'
    node_args = [sys.executable, '-B', str(release / 'wallet/node.py'), '--release', str(release),
                 '--data-dir', str(data), '--rpc-port', str(port), '--seconds', '180', '--offline']
    try:
        child = start('node-ready', node_args)
        until(lambda: list(data.glob('node-session-*/READY.json')))
        daemon = launch.c.RPC(port)
        before = daemon('get_block_header_by_height', {'height': 0})['block_header']['hash']
        elapsed = kill_controller(child, data, 1)
        assert sentinel.poll() is None
        with socket.socket() as probe:
            assert probe.connect_ex(('127.0.0.1', port)) != 0
        rows.append({'case': 'native_node_controller_SIGKILL_READY', 'drainSeconds': elapsed})
        restarted = start('node-reopen', node_args)
        until(lambda: len(list(data.glob('node-session-*/READY.json'))) == 2)
        assert daemon('get_block_header_by_height', {'height': 0})['block_header']['hash'] == before
        # Wallet RPC is real and encrypted-wallet handling is deliberately absent
        # here; create/recovery flows have their separate browser/native verifier.
        wallets = root / 'wallets'
        wallet_args = [sys.executable, '-B', str(release / 'wallet/companion.py'),
                       '--wallet-rpc', str(release / 'bin/meepcoin-wallet-rpc'),
                       '--wallet-dir', str(wallets), '--daemon-port', str(port),
                       '--genesis', manifest['genesisHash'], '--seconds', '180']
        wallet = start('wallet-ready', wallet_args)
        until(lambda: (wallets / 'OPEN_WALLET.html').exists())
        elapsed = kill_controller(wallet, wallets, 1)
        assert sentinel.poll() is None
        rows.append({'case': 'native_wallet_controller_SIGKILL_READY', 'drainSeconds': elapsed})
        wallet2 = start('wallet-reopen', wallet_args)
        until(lambda: len(list(wallets.glob('session-*/PROCESS.json'))) == 2)
        wallet2.terminate()
        wallet2.wait(timeout=45)
        restarted.terminate()
        restarted.wait(timeout=45)
        assert drained(data, 2) and drained(wallets, 2)
        # Kill at the concrete boundary after the native has forked but before
        # READY is required. The receipt observes the startup death boundary.
        startup = root / 'startup'
        args = list(node_args)
        args[args.index('--data-dir') + 1] = str(startup)
        child = start('node-startup', args)
        until(lambda: list(startup.glob('node-session-*/GUARD_STARTED.json')))
        elapsed = kill_controller(child, startup, 1)
        rows.append({'case': 'native_node_controller_SIGKILL_STARTUP', 'drainSeconds': elapsed,
                     'readyAlreadyWritten': bool(list(startup.glob('node-session-*/READY.json')))})
        assert rows[-1]['readyAlreadyWritten'] is False, 'Missed startup boundary; this attempt is not startup coverage'
        assert sentinel.poll() is None
        if a.peer:
            import shutil
            session_data = root / 'session-data'
            session_data.mkdir(mode=0o700)
            shutil.copyfile(a.participant_key, session_data / 'participant-key')
            (session_data / 'participant-key').chmod(0o600)
            session_args = [sys.executable, '-B', str(release / 'wallet/session.py'), 'start',
                            '--release', str(release), '--data-dir', str(session_data),
                            '--peer', str(a.peer), '--seconds', '180']
            child = start('session-ready', session_args)
            until(lambda: list(session_data.glob('session-*/READY.json')))
            elapsed = kill_controller(child, session_data, 5)
            recover = subprocess.run([sys.executable, '-B', str(release / 'wallet/session.py'),
                                      'recover', '--data-dir', str(session_data)],
                                     capture_output=True, text=True, timeout=10)
            assert recover.returncode == 0, recover.stderr
            assert not (session_data / 'control.sock').exists() and sentinel.poll() is None
            rows.append({'case': 'full_participant_SIGKILL_and_safe_socket_recovery', 'drainSeconds': elapsed})
            began = time.monotonic()
            reopened = start('session-reopen', session_args)
            until(lambda: len(list(session_data.glob('session-*/READY.json'))) == 2, 120)
            restart_seconds = time.monotonic() - began
            assert restart_seconds < 120 and sentinel.poll() is None
            reopened.terminate()
            assert reopened.wait(timeout=45) == 0
            assert drained(session_data, 10)
            rows.append({'case': 'full_participant_same_data_restart_after_recovery', 'restartSeconds': restart_seconds})
            startup_data = root / 'session-startup-data'
            startup_data.mkdir(mode=0o700)
            shutil.copyfile(a.participant_key, startup_data / 'participant-key')
            (startup_data / 'participant-key').chmod(0o600)
            startup_args = list(session_args)
            startup_args[startup_args.index('--data-dir') + 1] = str(startup_data)
            child = start('session-startup', startup_args)
            until(lambda: list(startup_data.glob('node/node-session-*/GUARD_STARTED.json')))
            assert not list(startup_data.glob('session-*/READY.json')), 'Missed full-session startup boundary'
            elapsed = kill_controller(child, startup_data, 3)
            recover = subprocess.run([sys.executable, '-B', str(release / 'wallet/session.py'),
                                      'recover', '--data-dir', str(startup_data)],
                                     capture_output=True, text=True, timeout=10)
            assert recover.returncode == 0, recover.stderr
            assert not (startup_data / 'control.sock').exists() and sentinel.poll() is None
            rows.append({'case': 'full_participant_SIGKILL_STARTUP_and_safe_socket_recovery',
                         'drainSeconds': elapsed, 'readyAlreadyWritten': False})
            # Freeze only this owned disposable native wallet. An authenticated
            # create request then blocks in real RPC while the outer controller
            # dies. Nested drain must share the original 45-second bound.
            blocked_data = root / 'blocked-data'
            blocked_data.mkdir(mode=0o700)
            shutil.copyfile(a.participant_key, blocked_data / 'participant-key')
            (blocked_data / 'participant-key').chmod(0o600)
            blocked_args = list(session_args)
            blocked_args[blocked_args.index('--data-dir') + 1] = str(blocked_data)
            child = start('session-blocked-request', blocked_args)
            until(lambda: list(blocked_data.glob('session-*/READY.json')))
            url = re.search(r'href="([^"]+)"', (blocked_data/'wallets/OPEN_WALLET.html').read_text()).group(1)
            parts = urllib.parse.urlsplit(url);origin = parts.scheme+'://'+parts.netloc
            token = urllib.parse.parse_qs(parts.fragment)['connect'][0]
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            def request(action, body, headers=None):
                req = urllib.request.Request(origin+'/api/'+action,data=json.dumps(body).encode(),headers={
                    'Content-Type':'application/json','Origin':origin,**(headers or {})})
                return opener.open(req,timeout=60)
            with request('session',{'token':token}) as response:
                csrf=json.load(response)['csrf'];cookie=response.headers['Set-Cookie'].split(';',1)[0]
            native_record = json.loads(next(blocked_data.glob('wallets/session-*/PROCESS.json')).read_text())
            os.kill(native_record['nativePid'],signal.SIGSTOP)
            entered=threading.Event();outcome=[]
            def blocked_request():
                entered.set()
                try:
                    with request('create',{'name':'blocked-disposable','password':'disposable-test-password'},
                                 {'Cookie':cookie,'X-Meep-CSRF':csrf}) as response:response.read()
                except Exception as error:outcome.append(type(error).__name__)
            worker=threading.Thread(target=blocked_request,daemon=True);worker.start();entered.wait(2);time.sleep(.5)
            elapsed=kill_controller(child,blocked_data,5)
            worker.join(5);assert not worker.is_alive() and outcome and sentinel.poll() is None
            recover=subprocess.run([sys.executable,'-B',str(release/'wallet/session.py'),'recover','--data-dir',str(blocked_data)],
                                   capture_output=True,text=True,timeout=10)
            assert recover.returncode==0,recover.stderr
            rows.append({'case':'full_participant_SIGKILL_during_blocked_real_wallet_RPC','drainSeconds':elapsed,
                         'frozenOwnedNativeExited':True,'requestSettled':True})
        save('RESULT.json', {'status': 'ACTUAL_NATIVE_CRASH_DRAIN_AND_REOPEN_PASS',
                             'genesis': before, 'releaseVersion': manifest['releaseVersion'],
                             'filesVerified': count, 'cases': rows, 'unrelatedSentinelPreserved': True,
                             'hardwarePowerLossQualified': False})
        print('ACTUAL_NATIVE_CRASH_DRAIN_AND_REOPEN_PASS', flush=True)
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=45)
        for output in logs:
            output.close()
        save('CLEANUP.json', {'allOwnedControllersExited': all(c.poll() is not None for c in children),
                              'nativeGuardReceipts': [json.loads(path.read_text()) for path in guards(root)]})


if __name__ == '__main__':
    main()
