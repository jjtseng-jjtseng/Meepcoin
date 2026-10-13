#!/usr/bin/env python3
"""Real process watchdog checks; Linux only, disposable children, no services."""
import importlib.util, json, os, subprocess, sys, tempfile, time
from pathlib import Path

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('watchdog', here / 'supervise-pi.py')
watchdog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watchdog)
with tempfile.TemporaryDirectory(prefix='meep-watchdog-') as directory:
    common = {'argv': [sys.executable, '-c', 'pass'], 'rssBytes': 128*1024**2,
              'addressSpaceBytes': 256*1024**2, 'fileBytes': 1024**2,
              'dataBytes': 128*1024**2,
              'minFreeBytes': 1, 'maxSeconds': 10, 'dataDirectory': directory}
    cases = [
        ('normal_exit', {}, 'child_exit', 0),
        ('disk_floor', {'minFreeBytes': 2**62, 'argv': [sys.executable, '-c', 'import time;time.sleep(30)']}, 'disk_floor', 1),
        ('runtime_limit', {'maxSeconds': 1, 'argv': [sys.executable, '-c', 'import time;time.sleep(30)']}, 'runtime_limit', 1),
        ('rss_watchdog', {'rssBytes': 24*1024**2, 'argv': [sys.executable, '-c', 'import time;x=bytearray(48*1024**2);time.sleep(30)']}, 'rss_watchdog', 1),
        ('descendant_cleanup', {'argv': [sys.executable, '-c',
            'import subprocess,sys;subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"]);']}, 'child_exit', 0),
    ]
    rows = []
    for label, override, expected, exit_code in cases:
        config = dict(common, **override)
        # Each supervisor lives in a fresh process so signal handlers cannot leak.
        code = 'import importlib.util,json,sys; s=importlib.util.spec_from_file_location("w",sys.argv[1]);w=importlib.util.module_from_spec(s);s.loader.exec_module(w);sys.exit(w.supervise(json.loads(sys.argv[2]),test_group_only=True))'
        result = subprocess.run([sys.executable, '-c', code, str(here / 'supervise-pi.py'), json.dumps(config)],
                                capture_output=True, text=True, timeout=22)
        receipt = json.loads(result.stdout.strip())
        assert result.returncode == exit_code, (label, result.returncode, result.stderr, receipt)
        assert receipt['reason'] == expected and receipt['remainingGroupProcesses'] == 0, (label, receipt)
        rows.append({'case': label, **receipt})
    print(json.dumps({'status': 'REAL_PI_WATCHDOG_PROCESS_TESTS_PASS', 'cases': rows}, indent=2))
