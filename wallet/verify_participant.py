#!/usr/bin/env python3
"""Native half of one browser create -> mine -> pay -> recover rehearsal.

Only fresh offline regtest data. The browser half writes public checkpoints;
this controller independently checks canonical PoW, rewards, pool and cleanup.
No generated recovery words, wallet passwords or capabilities enter receipts.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import urllib.request

spec = importlib.util.spec_from_file_location('companion', Path(__file__).with_name('companion.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binaries', type=Path, required=True)
    parser.add_argument('--node', type=Path, required=True)
    parser.add_argument('--native-hash', type=Path, help='Native PoW CLI when it is outside the wallet bin directory')
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--wallet-port', type=int, default=46881)
    parser.add_argument('--mining-port', type=int, default=46882)
    parser.add_argument('--browser-binary', type=Path, required=True)
    parser.add_argument('--playwright-module', type=Path, required=True)
    parser.add_argument('--max-rss-mib', type=int, default=1536,
                        help='Sampled whole-owned-unit RSS ceiling, 512-4096 MiB (Pi qualification: 1536; CI x64: 2048)')
    args = parser.parse_args()
    assert 1024 <= args.wallet_port <= 65535 and 1024 <= args.mining_port <= 65535
    assert args.wallet_port != args.mining_port
    assert 512 <= args.max_rss_mib <= 4096, 'RSS budget must be 512-4096 MiB'
    rss_budget = args.max_rss_mib * 1024**2
    os.umask(0o077)
    root = args.run_dir.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    bins = args.binaries.resolve(strict=True)
    native_hash = (args.native_hash or bins / 'meepow-v2-hash').resolve(strict=True)
    source = Path(__file__).resolve().parents[1]
    children, logs = [], []
    browser_child = None
    began = time.monotonic()
    peak_rss = 0
    cgroup = next(line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
    cgroup_procs = Path('/sys/fs/cgroup') / cgroup.lstrip('/') / 'cgroup.procs'
    def unit_pids():
        return {int(pid) for path in cgroup_procs.parent.rglob('cgroup.procs') for pid in path.read_text().split()}
    assert unit_pids() == {os.getpid()}, 'Use a new dedicated systemd unit; never a shared shell cgroup'
    result = None
    daemon_port = c.free_port()
    assert daemon_port not in (args.wallet_port, args.mining_port)
    daemon = c.RPC(daemon_port)

    def save(name, value):
        with (root / name).open('x') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')

    def launch(name, argv, node=False):
        log = (root / (name + '.log')).open('xb')
        logs.append(log)
        def limits():
            import resource
            os.nice(10)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            # Chromium reserves a large virtual arena; the complete owned user
            # unit is sampled below rather than applying a virtual-memory cap.
            if name != 'browser':
                resource.setrlimit(resource.RLIMIT_AS, ((128 if node else 2) * 1024**3,) * 2)
            resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024**2,) * 2)
        child = subprocess.Popen(argv, cwd=root, stdin=subprocess.DEVNULL, stdout=log,
                                 stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=limits)
        children.append((name, child))
        return child

    def until(fn, seconds=120, allow_browser_exit=False):
        nonlocal peak_rss
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            rss = 0
            for pid in unit_pids():
                try:
                    rss += next((int(row.split()[1]) * 1024 for row in Path('/proc', str(pid), 'status').read_text().splitlines() if row.startswith('VmRSS:')), 0)
                except FileNotFoundError:
                    pass
            peak_rss = max(peak_rss, rss)
            assert rss < rss_budget, 'Owned unit exceeded sampled RSS budget'
            assert all(child.poll() is None or (allow_browser_exit and name == 'browser' and child.returncode == 0)
                       for name, child in children), 'Owned child exited early'
            try:
                value = fn()
                if value:
                    return value
            except (OSError, c.WalletError, ValueError):
                pass
            time.sleep(.2)
        raise RuntimeError('Finite participant checkpoint deadline')

    def checkpoint(name, seconds=600, allow_browser_exit=False):
        return until(lambda: json.loads((root / name).read_text()), seconds, allow_browser_exit)

    def header(height):
        reply = daemon('get_block_header_by_height', {'height': height, 'fill_pow_hash': True})
        assert reply.get('status') == 'OK'
        return reply['block_header']

    def pool():
        request = urllib.request.Request(f'http://127.0.0.1:{daemon_port}/get_transaction_pool_hashes',
                                         data=b'{}', headers={'Content-Type': 'application/json'})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=10) as response:
            value = json.load(response)
        assert value['status'] == 'OK'
        return value.get('tx_hashes', [])

    def interrupted(*_):
        raise KeyboardInterrupt()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGALRM):
        signal.signal(sig, interrupted)
    signal.alarm(1200)
    try:
        cfg = root / 'empty.conf'
        cfg.write_text('')
        launch('daemon', [str(bins / 'meepcoind'), '--config-file', str(cfg), '--data-dir', str(root / 'chain'),
            '--regtest', '--keep-fakechain', '--fixed-difficulty', '20', '--offline', '--no-zmq',
            '--disable-dns-checkpoints', '--check-updates', 'disabled', '--no-igd', '--out-peers', '0', '--in-peers', '0',
            '--rpc-bind-ip', '127.0.0.1', '--rpc-bind-port', str(daemon_port), '--rpc-ssl', 'disabled',
            '--max-concurrency', '1', '--prep-blocks-threads', '1', '--non-interactive',
            '--log-file', str(root / 'native.log'), '--log-level', '0'])
        until(lambda: daemon('get_info').get('height') == 1)
        genesis = until(lambda: header(0))['hash']
        wallets = root / 'wallets'
        launch('companion', ['python3', str(source / 'wallet/companion.py'),
            '--wallet-rpc', str(bins / 'meepcoin-wallet-rpc'), '--wallet-dir', str(wallets),
            '--daemon-port', str(daemon_port), '--genesis', genesis, '--network', 'regtest',
            '--host', '127.77.13.13', '--port', str(args.wallet_port), '--seconds', '1200'])
        link = wallets / 'OPEN_WALLET.html'
        until(link.exists)
        save('READY.json', {'genesis': genesis, 'walletOrigin': f'http://127.77.13.13:{args.wallet_port}',
                            'miningOrigin': f'http://127.0.0.1:{args.mining_port}', 'privateLinkFile': str(link)})
        print('PARTICIPANT_BROWSER_READY', flush=True)
        browser_child = launch('browser', [str(args.node.resolve(strict=True)), '--max-old-space-size=256',
            str(source / 'wallet/verify_participant_browser.mjs'), '--run-dir', str(root),
            '--browser', str(args.browser_binary.resolve(strict=True)),
            '--playwright-module', str(args.playwright_module.resolve(strict=True))], True)
        addresses = checkpoint('CREATED.json')
        alice, bob = addresses['alice'], addresses['bob']
        assert alice != bob and all(c.SLUG.fullmatch(name) for name in addresses['walletNames'])
        assert set(addresses['walletNames']) == {'alice', 'bob'}
        # 64 native fixture blocks supply maturity and ring decoys. They are
        # disclosed separately from the one genuinely browser-mined block.
        daemon('generateblocks', {'amount_of_blocks': 64, 'wallet_address': alice})
        assert daemon('get_info')['height'] == 65
        baseline_reward = sum(header(height)['reward'] for height in range(1, 65))
        gateway_config = {'endpoint': f'http://127.0.0.1:{daemon_port}/json_rpc', 'walletAddress': alice,
                          'nativeCommand': [str(native_hash)], 'port': args.mining_port, 'maxJobs': 4,
                          'readyFile': str(root / 'MINER_PRIVATE.json'), 'blockFile': str(root / 'MINED.json')}
        save('gateway-config.json', gateway_config)
        launch('gateway', [str(args.node.resolve(strict=True)), '--max-old-space-size=256',
                           str(source / 'wallet/participant_gateway.mjs'), str(root / 'gateway-config.json')], True)
        checkpoint('MINER_PRIVATE.json', 45)
        save('FUNDED.json', {'fixtureBlocks': 64, 'aliceBalanceAtomic': str(baseline_reward)})
        mined = checkpoint('MINED.json', 180)
        canonical = header(65)
        assert daemon('get_info')['height'] == 66 and canonical['difficulty'] == 20
        assert canonical['orphan_status'] is False
        assert int.from_bytes(bytes.fromhex(canonical['pow_hash']), 'little') * 20 < 2**256
        assert any(event['type'] == 'block_accepted' for event in mined['events'])
        save('REWARD.json', {'browserBlock': canonical, 'aliceBalanceAtomic': str(baseline_reward + canonical['reward'])})
        checkpoint('CANCELLED.json', 300)
        assert pool() == [], 'Cancelled review must not relay any transaction'
        save('CANCELLED_OK.json', {'nativePoolEmpty': True})
        sent = checkpoint('SENT.json', 300)
        assert c.HASH.fullmatch(sent['txHash']) and int(sent['amountAtomic']) == c.ATOMIC
        assert isinstance(sent['feeAtomic'], str) and 0 < int(sent['feeAtomic']) < c.ATOMIC
        assert pool() == [sent['txHash']], 'Browser confirmation must produce exactly one native pool entry'
        request = urllib.request.Request(f'http://127.0.0.1:{daemon_port}/get_transaction_pool',
                                         data=b'{}', headers={'Content-Type': 'application/json'})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=10) as response:
            pool_rows = json.load(response)['transactions']
        assert len(pool_rows) == 1 and pool_rows[0]['id_hash'] == sent['txHash']
        assert pool_rows[0]['fee'] == int(sent['feeAtomic']), 'Native pool fee must equal the reviewed browser fee'
        daemon('generateblocks', {'amount_of_blocks': 12, 'wallet_address': alice})
        assert daemon('get_info')['height'] == 78 and pool() == []
        request = urllib.request.Request(f'http://127.0.0.1:{daemon_port}/get_transactions',
            data=json.dumps({'txs_hashes': [sent['txHash']], 'decode_as_json': False}).encode(),
            headers={'Content-Type': 'application/json'})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=10) as response:
            canonical_tx = json.load(response)['txs']
        assert len(canonical_tx) == 1 and canonical_tx[0]['tx_hash'] == sent['txHash']
        assert canonical_tx[0]['in_pool'] is False and canonical_tx[0]['block_height'] == 66
        confirmation_rewards = sum(header(height)['reward'] for height in range(66, 78))
        expected_alice = baseline_reward + canonical['reward'] + confirmation_rewards - c.ATOMIC - int(sent['feeAtomic'])
        save('CONFIRMED.json', {'txHash': sent['txHash'], 'confirmations': 12,
             'aliceBalanceAtomic': str(expected_alice), 'bobBalanceAtomic': str(c.ATOMIC)})
        browser = checkpoint('BROWSER_RESULT.json', 300, allow_browser_exit=True)
        required = ('browserCreateAndBackup', 'backupWordsCleared', 'visibleBrowserMining', 'exactBrowserReward',
                    'reviewCancelNoRelay', 'confirmedSend', 'exactSenderBalance', 'exactRecipientBalance',
                    'seedRecoverySameAddressAndBalance', 'reloadLocksWallet', 'wrongPasswordLeavesLocked',
                    'switchingWalletClearsPaymentDraft')
        assert all(browser.get(key) is True for key in required), 'Missing browser evidence'
        assert browser['txHash'] == sent['txHash']
        assert browser['aliceBalanceAtomic'] == str(expected_alice)
        assert browser['bobBalanceAtomic'] == str(c.ATOMIC)
        assert browser_child.wait(timeout=30) == 0, 'Browser must finish normal shutdown before a passing receipt'
        result = {'status': 'OFFLINE_BROWSER_PARTICIPANT_JOURNEY_PASS', 'genesis': genesis,
                  'network': 'regtest', 'fixedDifficulty': 20, 'publicExposure': False,
                  'nativeFixtureBlocks': 64, 'browserMinedBlocks': 1, 'nativeConfirmationBlocks': 12,
                  'canonicalBrowserBlock': canonical, 'browser': browser,
                  'exactNativePoolReconciliation': True,
                  'nativePoolFeeMatchesBrowserReview': True, 'canonicalTransferHeight': 66,
                  'peakSampledOwnedUnitRssBytes': peak_rss,
                  'sampledOwnedUnitRssBudgetBytes': rss_budget,
                  'sourceSha256': {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                      for name in ['wallet/companion.py', 'wallet/web/app.js', 'wallet/verify_participant.py',
                                   'wallet/participant_gateway.mjs', 'wallet/verify_participant_browser.mjs']},
                  'limits': ['Browser frontend may connect through a private SSH forward to disposable Linux keys',
                             'Not an installed Windows/macOS native package qualification',
                             'Local HTTP secure-context rehearsal; not a fresh v17 public HTTPS release',
                             'One bounded run; not mobile, thermal or sustained-operation evidence']}
    finally:
        signal.alarm(0)
        cleanup = []
        cleanup_errors = []
        for name, child in reversed(children):
            try:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait(timeout=10)
            except Exception as error:
                cleanup_errors.append({'name': name, 'error': type(error).__name__})
        # setsid/setpgid do not leave the dedicated unit. Reconcile its complete
        # recursive membership even when a process-group leader exited first.
        # This unit was required to contain only this controller at startup.
        for sig, seconds in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
            try:
                for pid in unit_pids() - {os.getpid()}:
                    if pid not in unit_pids():
                        continue
                    try:
                        os.kill(pid, sig)
                    except ProcessLookupError:
                        pass
                end = time.monotonic() + seconds
                while unit_pids() - {os.getpid()} and time.monotonic() < end:
                    for _, child in children:
                        child.poll()
                    time.sleep(.1)
            except Exception as error:
                cleanup_errors.append({'name': 'owned-unit', 'error': type(error).__name__})
        for name, child in children:
            try:
                os.killpg(child.pid, 0)
                empty = False
            except ProcessLookupError:
                empty = True
            except OSError as error:
                empty = False
                cleanup_errors.append({'name': name, 'error': type(error).__name__})
            cleanup.append({'name': name, 'pid': child.pid, 'exitCode': child.returncode, 'ownedGroupEmpty': empty})
        for receipt in (root / 'wallets').glob('session-*/PROCESS.json'):
            try:
                pid = json.loads(receipt.read_text())['nativePid']
                os.killpg(pid, 0)
                empty = False
            except ProcessLookupError:
                empty = True
            except Exception as error:
                empty = False
                cleanup_errors.append({'name': 'native-wallet-child', 'error': type(error).__name__})
            cleanup.append({'name': 'native-wallet-child', 'receipt': str(receipt.relative_to(root)), 'ownedGroupEmpty': empty})
        browser_receipt = root / 'BROWSER_PROCESS.json'
        if browser_receipt.exists():
            try:
                identity = json.loads(browser_receipt.read_text())
                os.killpg(identity['processGroup'], 0)
                empty = False
            except ProcessLookupError:
                empty = True
            except Exception as error:
                empty = False
                cleanup_errors.append({'name': 'chromium-owned-group', 'error': type(error).__name__})
            cleanup.append({'name': 'chromium-owned-group', 'ownedGroupEmpty': empty})
        for log in logs:
            log.close()
        remaining = sorted(unit_pids() - {os.getpid()})
        memory_peak = cgroup_procs.parent / 'memory.peak'
        save('CLEANUP.json', {'processes': cleanup, 'seconds': time.monotonic() - began,
             'errors': cleanup_errors, 'remainingOwnedUnitPids': remaining,
             'recursiveOwnedUnitEmptyExceptController': not remaining,
             'sampledRssBudgetBytes': rss_budget, 'peakSampledRssBytes': peak_rss,
             'kernelMemoryPeakBytes': int(memory_peak.read_text()) if memory_peak.exists() else None,
             'memoryClaim': 'Sampled sum of RSS; not a kernel hard memory ceiling'})
        assert not cleanup_errors and not remaining and all(row['ownedGroupEmpty'] for row in cleanup)
    # No passing verdict exists until native, browser, detached helpers and the
    # complete owned unit have finished cleanup. Partial UI receipts are retained.
    assert result is not None
    result['ownedCleanupVerified'] = True
    save('RESULT.json', result)
    print(result['status'], flush=True)


if __name__ == '__main__':
    main()
