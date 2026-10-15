#!/usr/bin/env python3
"""Finite per-participant SSH service in its own Linux user-service cgroup.

The operator supplies a private, sshd-validated configuration with MaxSessions=0
and a single PermitOpen peer target. Revocation stops the entire service cgroup,
including sshd-session processes which create their own process groups.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time


def start_unit(name, config, log, seconds):
    if not re.fullmatch(r'meepcoin-peer-[a-z0-9-]{1,48}', name) or not 30 <= seconds <= 3600:
        raise ValueError('Invalid participant unit name or finite lifetime.')
    info = config.stat()
    if config.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('SSH configuration must be owned by you with mode 0600.')
    subprocess.run(['/usr/sbin/sshd', '-t', '-f', str(config)], check=True, timeout=10)
    effective = subprocess.check_output(['/usr/sbin/sshd', '-T', '-f', str(config)], text=True, timeout=10)
    required = ('maxsessions 0', 'passwordauthentication no', 'kbdinteractiveauthentication no',
                'authenticationmethods publickey', 'allowtcpforwarding local', 'permitlisten none',
                'allowstreamlocalforwarding no', 'allowagentforwarding no', 'permittty no',
                'x11forwarding no', 'permituserrc no', 'gatewayports no')
    if not all(row in effective.splitlines() for row in required):
        raise ValueError('SSH configuration is missing a required participant restriction.')
    permitted = [row for row in effective.splitlines() if row.startswith('permitopen ')]
    if len(permitted) != 1 or not re.fullmatch(r'permitopen 127\.0\.0\.1:[0-9]{4,5}', permitted[0]):
        raise ValueError('Exactly one private loopback peer destination is required.')
    child = subprocess.Popen(['systemd-run', '--user', '--wait', '--pipe', '--collect', '--unit=' + name,
        '--property=CPUQuota=20%', '--property=MemoryMax=128M', '--property=TasksMax=32',
        '--property=Nice=10', '--property=RuntimeMaxSec=' + str(seconds),
        '--property=KillMode=control-group', '--property=TimeoutStopSec=10',
        '/usr/sbin/sshd', '-D', '-e', '-f', str(config)],
        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    until = time.monotonic() + 10
    cgroup = None
    try:
        while True:
            if child.poll() is not None:
                raise ValueError('Participant SSH unit exited during startup; inspect its log.')
            state = subprocess.run(['systemctl', '--user', 'show', name, '-p', 'ActiveState', '-p', 'ControlGroup'],
                                   capture_output=True, text=True, timeout=5)
            values = dict(row.split('=', 1) for row in state.stdout.splitlines() if '=' in row)
            cgroup = values.get('ControlGroup') or cgroup
            if values.get('ActiveState') == 'active' and cgroup:
                return child, cgroup
            if time.monotonic() >= until:
                raise ValueError('Participant SSH service startup deadline expired.')
            time.sleep(.1)
    except BaseException:
        # A failed start owns the same descendants as a successful start. Drain
        # the unit here because the caller has not received its handle yet.
        if cgroup is None:
            cgroup = (f'/user.slice/user-{os.getuid()}.slice/user@{os.getuid()}.service'
                      f'/app.slice/{name}.service')
        stop_unit(name, cgroup)
        child.wait(timeout=15)
        raise


def stop_unit(name, cgroup):
    if not re.fullmatch(r'meepcoin-peer-[a-z0-9-]{1,48}', name):
        raise ValueError('Refusing an unrelated service name.')
    expected = '/app.slice/' + name + '.service'
    if not cgroup.startswith('/user.slice/') or not cgroup.endswith(expected) or '..' in cgroup:
        raise ValueError('Refusing an unrelated service cgroup.')
    result = subprocess.run(['systemctl', '--user', 'stop', name], capture_output=True, text=True, timeout=20)
    # --collect may already have removed an expired unit. The exact recorded
    # kernel cgroup, rather than the daemon PID/group, proves descendant cleanup.
    path = Path('/sys/fs/cgroup') / cgroup.lstrip('/') / 'cgroup.events'
    until = time.monotonic() + 5
    while path.exists() and 'populated 1' in path.read_text().splitlines():
        if time.monotonic() >= until:
            raise ValueError('Participant SSH cgroup still contains processes after stop.')
        time.sleep(.1)
    state = subprocess.run(['systemctl', '--user', 'is-active', name], capture_output=True, text=True, timeout=5)
    if state.stdout.strip() == 'active':
        raise ValueError('Participant SSH service is still active after stop.')
    return {'unit': name, 'ownedCgroupEmpty': True, 'activeConnectionsRevoked': True,
            'listenerRevoked': True, 'stopExitCode': result.returncode}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('start', 'revoke'))
    p.add_argument('--state', type=Path, required=True)
    p.add_argument('--config', type=Path)
    p.add_argument('--unit')
    p.add_argument('--seconds', type=int, default=1800)
    a = p.parse_args()
    os.umask(0o077)
    if a.action == 'revoke':
        info = a.state.stat()
        if a.state.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('Service state must be privately owned by you.')
        state = json.loads(a.state.read_text())
        print(json.dumps(stop_unit(state['unit'], state['cgroup'])))
        return
    if a.config is None or a.unit is None or a.state.exists():
        p.error('start requires --config, --unit and a new --state file.')
    log_path = a.state.with_suffix('.log')
    if log_path.exists():
        p.error('A prior attempt log exists. Preserve it and choose a new --state path for the next attempt.')
    log = log_path.open('xb')
    child = None
    cgroup = None
    def interrupted(*_):
        raise KeyboardInterrupt()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    try:
        child, cgroup = start_unit(a.unit, a.config.resolve(strict=True), log, a.seconds)
        state = {'status': 'PARTICIPANT_SSH_CGROUP_READY', 'unit': a.unit, 'cgroup': cgroup,
                 'finiteSeconds': a.seconds, 'fullShellAllowed': False}
        with a.state.open('x') as stream:
            json.dump(state, stream, indent=2)
            stream.write('\n')
        print(json.dumps(state), flush=True)
        child.wait(timeout=a.seconds + 30)
    except KeyboardInterrupt:
        pass
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal.SIG_IGN)
        if cgroup:
            cleanup = stop_unit(a.unit, cgroup)
            a.state.with_suffix('.STOPPED.json').write_text(json.dumps(cleanup, indent=2) + '\n')
        if child:
            child.wait(timeout=15)
        log.close()


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None
