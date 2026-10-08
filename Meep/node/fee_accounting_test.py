#!/usr/bin/env python3
"""Verify transaction fee, change and sender-balance accounting at 11 decimals, on the live devnet.

The integration test already proves a 1 MEEP transfer arrives. This checks the arithmetic around it
exactly, in atomic units, with every coinbase credit accounted for rather than hand-waved:

    A_after  ==  A_before  -  amount  -  fee  +  (coinbase rewards A received while confirming)
    B_after  ==  B_before  +  amount

The coinbase term is the reason this is not a two-line test. Confirming a transaction requires
mining a block, and that block pays the miner. Rather than turn mining off (which would leave the
transaction unconfirmed) or ignore the credit (which would make the assertion meaningless), the
rewards of every block mined during the window are summed from the block headers and included.

Usage: fee_accounting_test.py [node_rpc_port] [walletA_port] [walletB_port] [out.md]

LOCALHOST / PRIVATE DEVELOPMENT CHAIN. Dev/test coins with no monetary value.
"""
import json, sys, time, urllib.request

COIN = 100000000000           # 10^11 -- MeepCoin uses 11 decimals
DECIMALS = 11
SEND_ATOMIC = 1 * COIN        # exactly 1 MEEP

NODE = int(sys.argv[1]) if len(sys.argv) > 1 else 29081
WA = int(sys.argv[2]) if len(sys.argv) > 2 else 29083
WB = int(sys.argv[3]) if len(sys.argv) > 3 else 29093   # devnet.ps1: wallet B RPC
OUT = sys.argv[4] if len(sys.argv) > 4 else "docs/FEE_ACCOUNTING_11DP.md"

lines = []
npass = nfail = 0


def say(s=""):
    print(s)
    lines.append(s)


def chk(cond, label):
    global npass, nfail
    if cond:
        npass += 1
        say(f"  [PASS] {label}")
    else:
        nfail += 1
        say(f"  [FAIL] {label}")
    return cond


def meep(atomic):
    """Render atomic units at the compiled 11 decimals, no rounding."""
    neg = atomic < 0
    a = abs(atomic)
    s = f"{a // COIN}.{a % COIN:0{DECIMALS}d}"
    return ("-" if neg else "") + s


def rpc(port, method, params=None, path="/json_rpc", timeout=120):
    body = json.dumps({"jsonrpc": "2.0", "id": "0", "method": method,
                       "params": params or {}}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read())
    if "error" in d:
        raise RuntimeError(f"{method}: {d['error']}")
    return d["result"]


def rest(port, path, params=None, timeout=60):
    body = json.dumps(params or {}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def refresh(port):
    try:
        rpc(port, "refresh")
    except Exception:
        pass


def balances(port):
    refresh(port)
    b = rpc(port, "get_balance", {"account_index": 0})
    return int(b["balance"]), int(b["unlocked_balance"])


def height():
    return int(rest(NODE, "/get_info")["height"])


def block_reward(h):
    return int(rpc(NODE, "get_block_header_by_height", {"height": h})["block_header"]["reward"])


def main():
    say("# MeepCoin — Fee, Change and Balance Accounting at 11 Decimals")
    say()
    say("**LOCALHOST / PRIVATE ONLY. Dev/test coins with NO monetary value.**")
    say()
    say(f"- Generated (UTC): {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say(f"- `COIN` = {COIN:,} atomic units per MEEP, {DECIMALS} decimals")
    say(f"- Sending exactly **1 MEEP** = **{SEND_ATOMIC:,} atomic units**")
    say()

    addr_a = rpc(WA, "get_address", {"account_index": 0})["address"]
    addr_b = rpc(WB, "get_address", {"account_index": 0})["address"]

    say("## 1. Starting state")
    say()
    a_bal0, a_unl0 = balances(WA)
    b_bal0, b_unl0 = balances(WB)
    h0 = height()
    say(f"- chain height: {h0}")
    say()
    say("| wallet | balance (atomic) | balance (MEEP) | unlocked (atomic) | unlocked (MEEP) |")
    say("|---|---|---|---|---|")
    say(f"| A | {a_bal0} | {meep(a_bal0)} | {a_unl0} | {meep(a_unl0)} |")
    say(f"| B | {b_bal0} | {meep(b_bal0)} | {b_unl0} | {meep(b_unl0)} |")
    say()
    chk(a_unl0 >= SEND_ATOMIC, f"wallet A has at least 1 MEEP unlocked ({meep(a_unl0)})")

    say()
    say("## 2. The transfer")
    say()
    res = rpc(WA, "transfer", {
        "destinations": [{"amount": SEND_ATOMIC, "address": addr_b}],
        "account_index": 0, "priority": 0, "get_tx_key": True, "ring_size": 16,
    })
    tx_hash = res["tx_hash"]
    amount = int(res["amount"])
    fee = int(res["fee"])
    say(f"- tx hash: `{tx_hash}`")
    say()
    say("| field | atomic | MEEP |")
    say("|---|---|---|")
    say(f"| amount | {amount} | {meep(amount)} |")
    say(f"| fee | {fee} | {meep(fee)} |")
    say(f"| amount + fee | {amount + fee} | {meep(amount + fee)} |")
    say()
    chk(amount == SEND_ATOMIC,
        f"the transfer amount is exactly 1 MEEP = {SEND_ATOMIC} atomic (not {10 * SEND_ATOMIC}, "
        f"which is what a 12-decimal assumption would have sent)")
    chk(fee > 0, f"a non-zero fee was charged ({meep(fee)} MEEP)")
    chk(meep(amount) == "1.00000000000", 'the amount renders as "1.00000000000" at 11 decimals')

    say()
    say("## 3. Confirmation, with every coinbase credit accounted for")
    say()
    # Confirm by mining to A. A therefore also earns coinbase during the window; those rewards are
    # summed from the block headers so the balance assertion stays exact instead of approximate.
    rest(NODE, "/start_mining", {"miner_address": addr_a, "threads_count": 6,
                                 "do_background_mining": False, "ignore_battery": True})
    deadline = time.time() + 600
    confirmed = False
    while time.time() < deadline:
        time.sleep(5)
        refresh(WB)
        try:
            got = rpc(WB, "get_transfer_by_txid", {"txid": tx_hash})
            if int(got["transfer"].get("confirmations", 0)) >= 2:
                confirmed = True
                break
        except Exception:
            pass
    rest(NODE, "/stop_mining", {})
    h1 = height()

    coinbase_to_a = sum(block_reward(h) for h in range(h0, h1))
    say(f"- mined heights {h0}..{h1 - 1} to wallet A while confirming ({h1 - h0} blocks)")
    say(f"- coinbase credited to A over that window: {coinbase_to_a} atomic = "
        f"{meep(coinbase_to_a)} MEEP")
    say()
    chk(confirmed, "the transaction reached at least 2 confirmations")

    say()
    say("## 4. Final state and the accounting identity")
    say()
    a_bal1, a_unl1 = balances(WA)
    b_bal1, b_unl1 = balances(WB)
    say("| wallet | balance (atomic) | balance (MEEP) |")
    say("|---|---|---|")
    say(f"| A | {a_bal1} | {meep(a_bal1)} |")
    say(f"| B | {b_bal1} | {meep(b_bal1)} |")
    say()

    a_delta = a_bal1 - a_bal0
    b_delta = b_bal1 - b_bal0
    a_expected = coinbase_to_a - amount - fee

    say("### Sender")
    say()
    say("```")
    say(f"A_before                 {a_bal0:>22}   {meep(a_bal0)}")
    say(f"+ coinbase while mining  {coinbase_to_a:>22}   {meep(coinbase_to_a)}")
    say(f"- amount sent            {amount:>22}   {meep(amount)}")
    say(f"- fee                    {fee:>22}   {meep(fee)}")
    say(f"= expected A_after       {a_bal0 + a_expected:>22}   {meep(a_bal0 + a_expected)}")
    say(f"  actual   A_after       {a_bal1:>22}   {meep(a_bal1)}")
    say(f"  difference             {a_bal1 - (a_bal0 + a_expected):>22}")
    say("```")
    say()
    chk(a_delta == a_expected,
        f"A's balance change is exactly coinbase - amount - fee "
        f"({meep(a_delta)} == {meep(a_expected)})")

    say()
    say("### Recipient")
    say()
    say("```")
    say(f"B_before                 {b_bal0:>22}   {meep(b_bal0)}")
    say(f"+ amount received        {amount:>22}   {meep(amount)}")
    say(f"= expected B_after       {b_bal0 + amount:>22}   {meep(b_bal0 + amount)}")
    say(f"  actual   B_after       {b_bal1:>22}   {meep(b_bal1)}")
    say("```")
    say()
    chk(b_delta == amount,
        f"B received exactly the amount sent, no more and no less ({meep(b_delta)})")
    chk(b_delta == SEND_ATOMIC, "B received exactly 1 MEEP")

    say()
    say("## 5. The fee went to the miner, not to the recipient")
    say()
    chk(b_delta != amount + fee, "B's credit excludes the fee")
    say(f"- the recipient is credited {meep(amount)} MEEP while the sender is debited "
        f"{meep(amount + fee)} MEEP; the {meep(fee)} MEEP difference is the fee paid to the miner "
        f"of the block that included the transaction.")

    say()
    say("## 6. Change output")
    say()
    refresh(WA)
    tr = rpc(WA, "get_transfer_by_txid", {"txid": tx_hash})["transfer"]
    say(f"- wallet A's record of the transaction: type `{tr.get('type')}`, "
        f"amount {tr.get('amount')} atomic, fee {tr.get('fee')} atomic")
    chk(int(tr.get("amount", -1)) == amount, "A's own record of the amount matches the transfer")
    chk(int(tr.get("fee", -1)) == fee, "A's own record of the fee matches the transfer")
    say()
    say("The change returned to A is implicit in the balance identity in section 4: A is debited")
    say("exactly `amount + fee`, which is only true if the remainder of every spent output came")
    say("back as change. Had change been lost or misscaled, A's delta would not balance.")

    say()
    say("---")
    say()
    say(f"**RESULT: {npass} passed, {nfail} failed**")
    say()
    say(f"**FEE AND BALANCE ACCOUNTING AT 11 DECIMALS: {'PASS' if nfail == 0 else 'FAIL'}**")
    say()
    say("_Dev/test coins on a private localhost chain. No monetary value._")

    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"\nwritten to {OUT}")
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
