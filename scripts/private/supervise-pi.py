#!/usr/bin/env python3
"""Fail-closed watchdog for one MeepCoin systemd unit on the invitation-test Pi.

CPU and task ceilings belong to systemd. RSS is sampled, NOT a kernel memory
reservation/hard ceiling; this Pi boots with cgroup_disable=memory. Each child
also receives address-space, core and individual-file limits. No automatic retry.
"""
import argparse, json, os, resource, signal, stat, subprocess, sys, time
from pathlib import Path


def load_config(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW)) as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
            raise ValueError('root-owned, non-writable regular watchdog config required')
        cfg = json.load(stream)
    if not isinstance(cfg.get('argv'), list) or not cfg['argv'] or any(
            not isinstance(x, str) or '\x00' in x for x in cfg['argv']):
        raise ValueError('explicit argv required')
    if not Path(cfg['argv'][0]).is_absolute():
        raise ValueError('absolute executable required')
    for name in ['rssBytes', 'addressSpaceBytes', 'dataBytes', 'fileBytes', 'minFreeBytes', 'maxSeconds']:
        if type(cfg.get(name)) is not int or cfg[name] <= 0:
            raise ValueError('positive integer required: ' + name)
    directory = Path(cfg['dataDirectory']).resolve(strict=True)
    if not directory.is_dir():
        raise ValueError('persistent data directory required')
    return cfg


def group_stats(group):
    rss, count = 0, 0
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            raw = (path / 'stat').read_text()
            fields = raw[raw.rfind(')') + 2:].split()
            if int(fields[2]) != group:
                continue
            count += 1
            rss += int(fields[21]) * os.sysconf('SC_PAGE_SIZE')
        except (OSError, ValueError, IndexError):
            pass  # A process can exit between directory enumeration and read.
    return rss, count


def unit_cgroup():
    """Require a dedicated systemd service cgroup; never monitor a login session."""
    for line in Path('/proc/self/cgroup').read_text().splitlines():
        if line.startswith('0::'):
            relative = line[3:]
            if not Path(relative).name.startswith('meepcoin-') or not relative.endswith('.service'):
                raise ValueError('dedicated meepcoin systemd service cgroup required')
            return Path('/sys/fs/cgroup') / relative.lstrip('/')
    raise ValueError('unified cgroup required')


def cgroup_stats(directory):
    rss, count = 0, 0
    for pid in (directory / 'cgroup.procs').read_text().split():
        try:
            fields = Path('/proc', pid, 'stat').read_text().rsplit(')', 1)[1].split()
            if fields[0] in ['Z', 'X']:
                continue
            count += 1
            rss += int(fields[21]) * os.sysconf('SC_PAGE_SIZE')
        except FileNotFoundError:
            pass  # Exited during the sample; other sampling errors fail closed.
    return rss, count


def supervise(cfg, test_group_only=False):
    directory = None if test_group_only else unit_cgroup()
    stopping = False
    reason = 'child_exit'
    def stop_signal(signum, _frame):
        nonlocal stopping, reason
        if not stopping:
            stopping, reason = True, 'operator_signal_' + str(signum)
    for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]:
        signal.signal(sig, stop_signal)
    def limits():
        for kind, amount in [(resource.RLIMIT_AS, cfg['addressSpaceBytes']),
                             (resource.RLIMIT_DATA, cfg['dataBytes']),
                             (resource.RLIMIT_FSIZE, cfg['fileBytes']),
                             (resource.RLIMIT_CORE, 0)]:
            resource.setrlimit(kind, (amount, amount))
        Path('/proc/self/oom_score_adj').write_text('1000')
    began, peak, child = time.monotonic(), 0, None
    try:
        child = subprocess.Popen(cfg['argv'], start_new_session=True, preexec_fn=limits)
        while child.poll() is None and not stopping:
            rss, count = cgroup_stats(directory) if directory else group_stats(child.pid)
            peak = max(peak, rss)
            fs = os.statvfs(cfg['dataDirectory'])
            if rss > cfg['rssBytes']:
                reason, stopping = 'rss_watchdog', True
            elif fs.f_bavail * fs.f_frsize < cfg['minFreeBytes']:
                reason, stopping = 'disk_floor', True
            elif time.monotonic() - began >= cfg['maxSeconds']:
                reason, stopping = 'runtime_limit', True
            elif count > 48:
                reason, stopping = 'process_watchdog', True
            if not stopping:
                time.sleep(.25)
    except Exception as error:
        reason, stopping = 'watchdog_error:' + type(error).__name__, True
    finally:
        if child is not None:
            # Includes descendants even if the leader has already exited.
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                child.poll()
                if group_stats(child.pid)[1] == 0:
                    break
                time.sleep(.1)
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                reason = 'watchdog_error:cleanup_timeout'
    remaining = group_stats(child.pid)[1] if child else 0
    receipt = {'type': 'meepcoin_watchdog_exit', 'reason': reason,
               'childExitCode': child.returncode if child else None,
               'peakSampledGroupRssBytes': peak, 'remainingGroupProcesses': remaining,
               'elapsedSeconds': time.monotonic() - began, 'rssIsSampledNotKernelLimit': True,
               'rssScope': 'unit_cgroup' if directory else 'test_process_group'}
    print(json.dumps(receipt), flush=True)
    # Caller/systemd must also prove the entire cgroup empty, catching setsid escape.
    return 0 if child and child.returncode == 0 and reason == 'child_exit' and not remaining else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    args = parser.parse_args()
    sys.exit(supervise(load_config(args.config)))
