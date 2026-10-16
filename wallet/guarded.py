"""POSIX child ownership through a live pipe, independent of controller survival.

The guardian retains its unreaped direct child as a process-group identity anchor
until shutdown finishes. No persisted PID authorizes a signal. Parent writers are
close-on-exec and explicitly closed in subsequent forked guardians.
"""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import time

_writers = set()


def _exited(pid):
    if hasattr(os, 'waitid') and hasattr(os, 'WNOWAIT'):
        return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    # Darwin runtimes without waitid: do not reap the identity anchor to poll it.
    result = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)],
                            capture_output=True, text=True, timeout=2)
    return result.returncode != 0 or result.stdout.strip().startswith('Z')


def _group_live(group):
    result = subprocess.run(['ps', '-axo', 'pgid=,stat='], capture_output=True,
                            text=True, timeout=2, check=True)
    return sum(1 for row in result.stdout.splitlines()
               if len(row.split()) == 2 and int(row.split()[0]) == group
               and not row.split()[1].startswith(('Z', 'X')))


def _guardian(alive, ready, argv, receipt, seconds, output, limits, owner, env):
    os.setsid()
    stopping = False
    reason = 'child_exit'
    child = None
    started = time.monotonic()
    detected = None
    empty = False
    error = None

    def stop(*_):
        nonlocal stopping, reason
        stopping, reason = True, 'controller_stop'

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop)
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output,
                                 stderr=subprocess.STDOUT, start_new_session=True,
                                 preexec_fn=limits, close_fds=True, env=env)
        with receipt.with_name(receipt.name.replace('STOPPED', 'STARTED')).open('x') as stream:
            json.dump({'guardianPid': os.getpid(), 'nativePid': child.pid, 'owner': owner}, stream)
        os.write(ready, json.dumps({'pid': child.pid, 'guardian': os.getpid()}).encode() + b'\n')
        os.close(ready)
        ready = None
        while not stopping:
            if select.select([alive], [], [], .1)[0] and os.read(alive, 1) == b'':
                detected = time.monotonic()
                reason = 'ownership_channel_closed'
                break
            if os.fstat(output.fileno()).st_size > 16 * 1024**2:
                reason = 'log_budget'
                break
            if time.monotonic() - started >= seconds:
                reason = 'deadline'
                break
            if _exited(child.pid):
                break
    except BaseException as failure:
        error = type(failure).__name__
        reason = 'guardian_error'
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        if child is not None:
            # child is still unreaped, so its PID and PGID cannot be recycled.
            for sig, allowance in ((signal.SIGTERM, 30), (signal.SIGKILL, 10)):
                try:
                    if _group_live(child.pid) == 0:
                        empty = True
                        break
                except (OSError, ValueError, subprocess.SubprocessError) as failure:
                    error = type(failure).__name__
                try:
                    os.killpg(child.pid, sig)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    # Darwin can return EPERM for the group of an already exited
                    # unreaped child. Confirm emptiness; never treat EPERM as proof.
                    try:
                        if _group_live(child.pid) == 0:
                            empty = True
                            break
                    except (OSError, ValueError, subprocess.SubprocessError):
                        pass
                    error = 'PermissionError'
                end = time.monotonic() + allowance
                while time.monotonic() < end:
                    try:
                        if _group_live(child.pid) == 0:
                            empty = True
                            break
                    except (OSError, ValueError, subprocess.SubprocessError) as failure:
                        # An observer failure must not skip escalation or reaping.
                        # Keep the unreaped anchor; never claim a verified drain.
                        error = type(failure).__name__
                        break
                    time.sleep(.1)
                if empty:
                    break
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                empty = False
        record = {'schema': 'meepcoin-owned-child/1', 'guardianPid': os.getpid(),
                  'nativePid': child.pid if child else None, 'reason': reason,
                  'nativeExitCode': child.returncode if child else None,
                  'ownedGroupDrained': empty, 'error': error, 'owner': owner,
                  'elapsedSeconds': time.monotonic() - started,
                  'drainAfterOwnershipLossSeconds': time.monotonic() - detected if detected else None,
                  'processIdentity': 'unreaped direct child; live ownership pipe',
                  'automaticRestart': False}
        temporary = receipt.with_name(receipt.name + '.pending')
        with temporary.open('x') as stream:
            json.dump(record, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, receipt)
        if ready is not None:
            os.close(ready)
        os.close(alive)
    os._exit(0 if empty and not error else 1)


class Child:
    def __init__(self, argv, *, output, receipt, seconds, limits=None, owner=None, env=None):
        if os.name != 'posix' or not 1 <= seconds <= 7200:
            raise ValueError('A bounded POSIX child is required.')
        self.receipt = Path(receipt)
        if self.receipt.exists() or self.receipt.is_symlink():
            raise ValueError('Owned child receipt already exists.')
        read_alive, write_alive = os.pipe()
        read_ready, write_ready = os.pipe()
        guardian = os.fork()
        if guardian == 0:
            try:
                os.close(write_alive)
                os.close(read_ready)
                for descriptor in _writers:
                    os.close(descriptor)
                _guardian(read_alive, write_ready, argv, self.receipt, seconds, output, limits, owner, env)
            except BaseException:
                # A terminal-receipt failure itself must remain diagnosable.
                # Tracebacks contain code/paths, never argv or wallet secrets.
                import traceback
                os.write(2, ('guardian_internal_error\n' + traceback.format_exc()).encode())
            finally:
                os._exit(1)
        os.close(read_alive)
        os.close(write_ready)
        self.guardian_pid = guardian
        self.writer = write_alive
        _writers.add(write_alive)
        self.returncode = None
        self._done = False
        try:
            if not select.select([read_ready], [], [], 5)[0]:
                raise RuntimeError('Owned child startup handshake timed out.')
            info = json.loads(os.read(read_ready, 1024))
            self.pid = info['pid']
        except BaseException:
            self._close()
            # The guardian handles EOF and its own timeout; retain failed receipts.
            end = time.monotonic() + 45
            while time.monotonic() < end:
                if os.waitpid(guardian, os.WNOHANG)[0]:
                    break
                time.sleep(.1)
            raise
        finally:
            os.close(read_ready)

    def _close(self):
        if self.writer is not None:
            _writers.discard(self.writer)
            os.close(self.writer)
            self.writer = None

    def poll(self):
        if not self._done:
            pid, status = os.waitpid(self.guardian_pid, os.WNOHANG)
            if pid:
                self._done = True
                # Once reaped, identity is no longer signalable. Receipt I/O may
                # fail (including ENOSPC); no exception may leave this as live.
                self.returncode = 1
                self._close()
                try:
                    data = json.loads(self.receipt.read_text())
                    self.returncode = (data['nativeExitCode'] if data['ownedGroupDrained']
                                       and not data['error'] and data['reason'] in ('child_exit', 'controller_stop') else 1)
                    if self.returncode is None:
                        self.returncode = os.waitstatus_to_exitcode(status) or 1
                except (OSError, ValueError, KeyError, TypeError):
                    self.returncode = 1
        return self.returncode

    def terminate(self):
        # Only a live direct guardian child is signaled, never a receipt PID.
        if self.poll() is None and not self._done:
            os.kill(self.guardian_pid, signal.SIGTERM)

    def kill(self):
        # Closing ownership initiates bounded escalation without killing guardian.
        self._close()

    def wait(self, timeout=None):
        end = time.monotonic() + (timeout if timeout is not None else 7200)
        while self.poll() is None:
            if time.monotonic() >= end:
                raise subprocess.TimeoutExpired('owned child', timeout)
            time.sleep(.1)
        return self.returncode


def register_native(run, role, genesis, release_version=None):
    """Publish the exact nested run before fork; standalone controllers return None."""
    raw = os.environ.get('MEEPCOIN_SESSION_OWNER')
    if raw is None:
        return None
    import re, stat
    owner = json.loads(raw)
    directory = Path(os.environ['MEEPCOIN_SESSION_RUN'])
    meta = directory.lstat()
    if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077
            or role not in ('node', 'wallet') or directory.name != owner.get('session')
            or not re.fullmatch(r'session-[a-f0-9]{16}', directory.name)
            or owner.get('genesis') != genesis
            or (release_version is not None and owner.get('releaseVersion') != release_version)
            or json.loads((directory / 'OWNER.json').read_text()) != owner):
        raise ValueError('Nested native ownership differs from participant session.')
    with (directory / ('native-' + role + '.json')).open('x') as stream:
        json.dump({'owner': owner, 'run': str(run.resolve())}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    return owner

