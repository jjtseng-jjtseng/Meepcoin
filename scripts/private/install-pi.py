#!/usr/bin/env python3
"""Provision only the dedicated MeepCoin account/directories/disabled systemd units.

Run once as root. Does not install packages, change boot settings, start services,
open firewall ports, read wallets, or edit existing accounts. Existing targets
cause refusal. Native RPC/P2P remain loopback. Release activation is separate.
"""
import grp, hashlib, json, os, pwd, shutil, subprocess
from pathlib import Path

ROOTS = ['/opt/meepcoin', '/etc/meepcoin', '/var/lib/meepcoin', '/var/log/meepcoin']
UNIT_NAMES = ['meepcoin.slice', 'meepcoin-node.service', 'meepcoin-gateway.service']


def main():
    if os.geteuid() != 0:
        raise SystemExit('root required for dedicated account provisioning')
    for name, lookup in [('meepcoin', pwd.getpwnam), ('meepcoin', grp.getgrnam)]:
        try:
            lookup(name)
        except KeyError:
            continue
        raise SystemExit('dedicated identity already exists; inspect before proceeding')
    for path in ROOTS + ['/etc/systemd/system/' + x for x in UNIT_NAMES]:
        if os.path.lexists(path):
            raise SystemExit('target already exists: ' + path)
    source = Path(__file__).resolve().parent / 'supervise-pi.py'
    if not source.is_file():
        raise SystemExit('watchdog source missing')
    before = subprocess.check_output(['systemctl', 'list-units', '--type=service',
                                     '--state=running', '--no-legend', '--plain'], text=True)
    subprocess.run(['groupadd', '--system', 'meepcoin'], check=True)
    subprocess.run(['useradd', '--system', '--gid', 'meepcoin', '--home-dir', '/var/lib/meepcoin',
                    '--shell', '/usr/sbin/nologin', '--no-create-home', 'meepcoin'], check=True)
    identity = pwd.getpwnam('meepcoin')
    os.umask(0o077)
    for path in ROOTS:
        Path(path).mkdir(mode=0o700)
    for path in ['/opt/meepcoin', '/etc/meepcoin']:
        os.chown(path, 0, identity.pw_gid)
        os.chmod(path, 0o750)
    for path in ['/var/lib/meepcoin', '/var/log/meepcoin']:
        os.chown(path, identity.pw_uid, identity.pw_gid)
    for path in ['chain', 'operator', 'backups', 'receipts']:
        directory = Path('/var/lib/meepcoin') / path
        directory.mkdir(mode=0o700)
        os.chown(directory, identity.pw_uid, identity.pw_gid)
    Path('/opt/meepcoin/releases').mkdir(mode=0o750)
    os.chown('/opt/meepcoin/releases', 0, identity.pw_gid)
    os.chmod('/opt/meepcoin/releases', 0o750)  # mkdir mode is filtered by umask.
    target = Path('/opt/meepcoin/supervise-pi.py')
    shutil.copyfile(source, target)
    target.chmod(0o755)
    empty = Path('/etc/meepcoin/empty.conf')
    empty.write_text('')
    empty.chmod(0o640)
    os.chown(empty, 0, identity.pw_gid)
    node_argv = ['/opt/meepcoin/current/bin/meepcoind', '--config-file', str(empty),
                 '--testnet', '--offline', '--data-dir', '/var/lib/meepcoin/chain',
                 '--no-zmq', '--disable-dns-checkpoints', '--check-updates', 'disabled',
                 '--no-igd', '--out-peers', '0', '--in-peers', '0', '--hide-my-port',
                 '--p2p-bind-ip', '127.0.0.1', '--p2p-bind-port', '49080',
                 '--rpc-bind-ip', '127.0.0.1', '--rpc-bind-port', '49081',
                 '--rpc-ssl', 'disabled', '--max-concurrency', '1', '--prep-blocks-threads', '1',
                 '--non-interactive', '--log-file', '/var/log/meepcoin/node-internal.log', '--log-level', '0']
    gateway_argv = ['/opt/meepcoin/current/bin/node', '--max-old-space-size=256',
                    '/opt/meepcoin/current/source/pool/private/testnet_service.mjs',
                    '/var/lib/meepcoin/operator/service.json']
    configs = {}
    for name, argv, rss, vas, duration in [('node', node_argv, 1536*1024**2, 2*1024**3, 5400),
                                          ('gateway', gateway_argv, 1024**3, 128*1024**3, 3600)]:
        cfg = {'argv': argv, 'rssBytes': rss, 'addressSpaceBytes': vas,
               'dataBytes': rss,
               'fileBytes': 128*1024**2, 'minFreeBytes': 3*1024**3,
               'maxSeconds': duration, 'dataDirectory': '/var/lib/meepcoin'}
        path = Path('/etc/meepcoin') / (name + '.json')
        path.write_text(json.dumps(cfg, indent=2) + '\n')
        path.chmod(0o640)
        os.chown(path, 0, identity.pw_gid)
        configs[name] = cfg
    units = {'meepcoin.slice': '[Unit]\nDescription=MeepCoin invitation experiment resource budget\n'
             '[Slice]\nCPUAccounting=yes\nCPUQuota=100%\nCPUWeight=10\nTasksAccounting=yes\nTasksMax=128\nIOWeight=10\n'}
    for name in ['node', 'gateway']:
        units['meepcoin-' + name + '.service'] = '''[Unit]
Description=MeepCoin invitation experiment NAME
After=network.target
ConditionPathExists=/opt/meepcoin/current/MANIFEST.json
CONDITION
[Service]
Type=simple
User=meepcoin
Group=meepcoin
Slice=meepcoin.slice
WorkingDirectory=/var/lib/meepcoin
ExecStart=/usr/bin/python3 /opt/meepcoin/supervise-pi.py /etc/meepcoin/NAME.json
Restart=no
KillMode=control-group
TimeoutStopSec=20
SendSIGKILL=yes
UMask=0077
Nice=10
OOMScoreAdjust=-500
CPUAccounting=yes
TasksAccounting=yes
TasksMax=64
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=no
PrivateDevices=yes
TemporaryFileSystem=/tmp:rw,nosuid,nodev,noexec,size=16M,mode=1777 /var/tmp:rw,nosuid,nodev,noexec,size=16M,mode=1777
InaccessiblePaths=/dev/shm
ReadOnlyPaths=/run
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=localhost
ReadWritePaths=/var/lib/meepcoin /var/log/meepcoin
StandardOutput=append:/var/log/meepcoin/NAME.log
StandardError=append:/var/log/meepcoin/NAME.log
LimitCORE=0
LimitNOFILE=256
LimitFSIZE=134217728
RuntimeMaxSec=RUNTIME
[Install]
WantedBy=multi-user.target
'''.replace('NAME', name).replace('RUNTIME', '5400' if name == 'node' else '3600').replace(
            'CONDITION', 'ConditionPathExists=/var/lib/meepcoin/operator/service.json' if name == 'gateway' else '')
    for name, text in units.items():
        path = Path('/etc/systemd/system') / name
        path.write_text(text)
        path.chmod(0o644)
    verify = subprocess.run(['systemd-analyze', 'verify', *[
        '/etc/systemd/system/' + x for x in UNIT_NAMES]], capture_output=True, text=True)
    if verify.returncode:
        raise RuntimeError('unit validation failed: ' + verify.stderr)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    after = subprocess.check_output(['systemctl', 'list-units', '--type=service',
                                    '--state=running', '--no-legend', '--plain'], text=True)
    before_names = {x.split()[0] for x in before.splitlines()}
    after_names = {x.split()[0] for x in after.splitlines()}
    receipt = {'status': 'DEDICATED_PI_ACCOUNT_AND_DISABLED_UNITS_INSTALLED',
               'uid': identity.pw_uid, 'gid': identity.pw_gid, 'roots': ROOTS,
               'units': list(units), 'unitSha256': {x: hashlib.sha256(y.encode()).hexdigest() for x,y in units.items()},
               'configs': configs, 'servicesStarted': False, 'servicesEnabledAtBoot': False,
               'priorRunningServicesStillRunning': sorted(before_names - after_names) == [],
               'priorServicesNoLongerRunning': sorted(before_names - after_names),
               'memoryControllerAvailable': 'memory' in Path('/sys/fs/cgroup/cgroup.controllers').read_text().split(),
               'rssWatchdogIsSampledNotHardKernelLimit': True,
               'publicExposure': False, 'nativeNetworking': 'numeric loopback only; offline; no peers'}
    Path('/etc/meepcoin/PROVISION.json').write_text(json.dumps(receipt, indent=2) + '\n')
    os.chown('/etc/meepcoin/PROVISION.json', 0, identity.pw_gid)
    os.chmod('/etc/meepcoin/PROVISION.json', 0o640)
    print(json.dumps(receipt), flush=True)


if __name__ == '__main__':
    main()
