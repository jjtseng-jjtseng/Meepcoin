#!/bin/bash
# Source regression for patches 0005 and 0006: nothing in the daemon/wallet source may AUTOMATICALLY
# log a private key, an ephemeral secret, the true ring position, or the ring members/signatures.
#
#   ./wallet_log_privacy_test.sh <reconstructed-checkout>
#
# <reconstructed-checkout> is the git checkout produced by reconstruct.sh, with the full series
# applied. The three revisions it compares are found BY TREE ID, not by HEAD~n: when patch 0007 was
# added, HEAD~1 stopped being patch 0005 and this regression would have compared the wrong pair --
# quietly, because the trees it names would still have existed further back. All three are read
# with `git show`; nothing is modified, built or run.
#
# WHAT THIS PROVES. That each leak was really there before, is really gone now, and that the whole
# production tree is clean under a detector that is itself tested. It proves nothing about the
# compiled binary; the binaries are scanned separately.
#
# WHAT IT DELIBERATELY DOES NOT DO. It does not ban the identifiers `real_output` or
# `real_output_in_tx_index`, and it does not look at the CONDITION of an assertion. Those are how a
# transaction is BUILT -- `src.real_output` tells the signer which ring member is real, and
# derive_public_key legitimately takes real_output_index as an argument. Banning them would ban
# spending. Only the LOGGED PAYLOAD is gated.
#
# It is also not a framework: one file, one detector, one set of checks.

set -u

# Resolved BEFORE the cd below. Read after it, `bash wallet_log_privacy_test.sh <checkout>` run from
# this directory resolved dirname "." against the CHECKOUT and silently found no patches at all, so
# every "patch NNNN unchanged" check compared a hash against an empty string.
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

CHECKOUT=${1:-}
[ -n "$CHECKOUT" ] || { echo "usage: $0 <reconstructed-checkout>" >&2; exit 2; }
cd "$CHECKOUT" 2>/dev/null || { echo "not a directory: $CHECKOUT" >&2; exit 2; }
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "not a git checkout: $CHECKOUT" >&2; exit 2; }

PRE_0005_TREE=d699f64cb7c265346b7df4f8309d019d43f4efdb   # what patch 0005 was applied to
POST_0005_TREE=776659034074752e5a7e708d15f3647d1bc90962  # what patch 0006 was applied to
PASS=0
FAIL=0

ok()   { PASS=$((PASS+1)); printf '  ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }
check() { # check <label> <expected> <actual>
  if [ "$2" = "$3" ]; then ok "$1 ($3)"; else bad "$1: expected $2, got $3"; fi
}

# commit_for_tree <tree> -- the revision in this history whose tree is <tree>
commit_for_tree() {
  local c
  for c in $(git rev-list HEAD); do
    if [ "$(git rev-parse "$c^{tree}")" = "$1" ]; then printf '%s\n' "$c"; return 0; fi
  done
  return 1
}

PRE=$(commit_for_tree "$PRE_0005_TREE")  || { echo "the pre-0005 tree is not in this history" >&2; exit 2; }
MID=$(commit_for_tree "$POST_0005_TREE") || { echo "the patch-0005 tree is not in this history" >&2; exit 2; }

old() { git show "$PRE:$1" 2>/dev/null; }     # before patch 0005
mid() { git show "$MID:$1" 2>/dev/null; }     # after 0005, before 0006
new() { git show "HEAD:$1" 2>/dev/null; }     # final

echo "-- the trees this regression compares --"
check "the pre-0005 locked tree is in this history"  "$PRE_0005_TREE"  "$(git rev-parse "$PRE^{tree}" 2>/dev/null)"
check "the patch-0005 locked tree is in this history" "$POST_0005_TREE" "$(git rev-parse "$MID^{tree}" 2>/dev/null)"

# Patches 0001-0006 must be byte-identical: later patches are additive, not a rewrite of history.
echo "-- patches 0001-0006 are byte-identical --"
expect_patch() { # expect_patch <glob> <sha256>
  local f
  f=$(ls "$SELF_DIR"/patches/"$1"* 2>/dev/null | head -1)
  check "patch $1 unchanged" "$2" "$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)"
}
expect_patch 0001 23576588a8dd513f92c4126baab97974cd966b59f5dbf58689f1fb7d1934a660
expect_patch 0002 c2a5002921b2a811cfcaf759955ee7d50c4869529d824ce68f1617b14105240d
expect_patch 0003 daac1c701180eade6e1eeb5c099c8c4f715014474d6d933283dc6dfbfa9eae2a
expect_patch 0004 1ba887e6459be6e60043d63cc98c332005b103e2c903c14a937496982886f172
expect_patch 0005 62894189e52f734d1ed65382ef2b4aff2f0da4eb3ac790d3b85680742cae822f
expect_patch 0006 e69979a833a63ec5d46957ea8df13ca467a616332d55dbfb6b9230c56b9f1efb

# ------------------------------------------------------------------ patch 0005: the routine helper
echo "-- patch 0005: the routine print_source_entry helper --"
check "pre-0005 wallet2.h defined it" 1 "$(old src/wallet/wallet2.h | grep -c 'inline void print_source_entry')"
check "pre-0005 wallet2.h logged it at level 0" 1 \
  "$(old src/wallet/wallet2.h | grep -c 'LOG_PRINT_L0("amount=.*real_output=')"
check "pre-0005 wallet2.cpp called it twice" 2 \
  "$(old src/wallet/wallet2.cpp | grep -c 'detail::print_source_entry(src);')"
check "no definition remains" 0 "$(new src/wallet/wallet2.h | grep -c 'print_source_entry')"
check "no call remains" 0 "$(new src/wallet/wallet2.cpp | grep -c 'print_source_entry')"

# ------------------------------------------------------------- patch 0006: the remaining payloads
echo "-- patch 0006: the remaining automatic payloads were there before --"
check "0005 tree logged the true ring position on bounds failure" 1 \
  "$(mid src/cryptonote_core/cryptonote_tx_utils.cpp | grep -c 'real_output index (')"
check "0005 tree logged the derived-key mismatch payload" 1 \
  "$(mid src/cryptonote_core/cryptonote_tx_utils.cpp | grep -c 'derived public key mismatch')"
check "0005 tree accumulated ring data into a stringstream" 1 \
  "$(mid src/cryptonote_core/cryptonote_tx_utils.cpp | grep -c 'std::stringstream ss_ring_s;')"
check "0005 tree logged the ephemeral secret key" 1 \
  "$(mid src/cryptonote_core/cryptonote_tx_utils.cpp | grep -c 'in_ephemeral_key: ')"
check "0005 tree dumped transaction_created twice" 2 \
  "$(mid src/cryptonote_core/cryptonote_tx_utils.cpp | grep -c 'transaction_created: ')"
check "0005 tree logged the miner tx secret key" 1 \
  "$(mid src/cryptonote_core/cryptonote_tx_utils.cpp | grep -c 'secret_key_explicit_print_ref{txkey.sec}')"
check "0005 tree logged the wallet view secret key" 1 \
  "$(mid src/wallet/wallet2.cpp | grep -c 'secret_key_explicit_print_ref{ack.m_view_secret_key}')"
check "0005 tree logged the device tx private key" 1 \
  "$(mid src/device/device_default.cpp | grep -c 'secret_key_explicit_print_ref{tx_privkey}')"

echo "-- and are gone now --"
for frag in 'real_output index (' 'derived public key mismatch' 'ss_ring_s' 'in_ephemeral_key: ' 'transaction_created: '; do
  check "gone from the final tree: $frag" 0 "$(new src/cryptonote_core/cryptonote_tx_utils.cpp | grep -cF -- "$frag")"
done
check "no secret key is printed in tx construction" 0 \
  "$(new src/cryptonote_core/cryptonote_tx_utils.cpp | grep -c 'secret_key_explicit_print_ref')"
check "no secret key is printed in wallet2" 0 "$(new src/wallet/wallet2.cpp | grep -c 'secret_key_explicit_print_ref')"
check "no secret key is printed in device_default" 0 "$(new src/device/device_default.cpp | grep -c 'secret_key_explicit_print_ref')"

echo "-- construction and validation are untouched --"
check "both paths still assign src.real_output" 2 \
  "$(new src/wallet/wallet2.cpp | grep -c 'src.real_output = it_to_replace - src.outputs.begin();')"
check "the bounds check itself still runs" 1 \
  "$(new src/cryptonote_core/cryptonote_tx_utils.cpp | grep -c 'if(src_entr.real_output >= src_entr.outputs.size())')"
check "the derived-key equality check still runs" 1 \
  "$(new src/cryptonote_core/cryptonote_tx_utils.cpp | grep -c 'if(!(in_ephemeral.pub == src_entr.outputs\[src_entr.real_output\].second.dest) )')"
check "ring signatures are still generated" 1 \
  "$(new src/cryptonote_core/cryptonote_tx_utils.cpp | grep -c 'crypto::generate_ring_signature(tx_prefix_hash')"
check "the explicit rpc_payment_info display is deliberately kept" 1 \
  "$(new src/simplewallet/simplewallet.cpp | grep -c 'RPC client secret key: ')"

# ------------------------------------------------------------------------------- the detector
# Multiline aware, stringstream aware, and TESTED on known-bad input before it is trusted.
echo "-- the full-tree detector, and proof that it works --"
git archive HEAD src > /tmp/meepcoin-privacy-src.tar 2>/dev/null || { bad "could not export the tree"; }
git archive "$MID" src > /tmp/meepcoin-privacy-prior.tar 2>/dev/null || { bad "could not export the prior tree"; }
DETECT_OUT=$(python3 - <<'PY' 2>&1
import re, sys, tarfile, io

LOG_MACROS = r'(?:LOG_PRINT_L\d|LOG_PRINT|LOG_ERROR|MLOG_[A-Z_]+|MLOG|MINFO|MWARNING|MERROR|MDEBUG|MTRACE|MGINFO|MCINFO|MCLOG[A-Z_]*|MCERROR|MCWARNING|MCDEBUG|MCTRACE|CHECK_AND_ASSERT_MES[A-Z_0-9]*|THROW_WALLET_EXCEPTION[A-Z_]*|message_writer)'
# Payloads that must never be written into a log automatically.
SENSITIVE = [
    ('true ring position',      r'\breal_output\b(?!_index)'),
    ('real output tx index',    r'\breal_output_in_tx_index\b'),
    ('explicit secret print',   r'secret_key_explicit_print_ref'),
    ('view secret key',         r'\bm_view_secret_key\b'),
    ('spend secret key',        r'\bm_spend_secret_key\b'),
    ('ephemeral secret key',    r'in_ephemeral\.sec\b'),
    ('tx secret key',           r'\btxkey\.sec\b|\btx_privkey\b'),
]
# The ONE deliberate exception: the operator explicitly asked for this, it is not automatic.
ALLOW = [('src/simplewallet/simplewallet.cpp', 'get_rpc_client_secret_key')]

def statements(text):
    """Yield (macro, full_call_text, line_no) with balanced parentheses, across newlines."""
    for m in re.finditer(LOG_MACROS + r'\s*\(', text):
        i = m.end() - 1
        depth = 0
        for j in range(i, min(len(text), i + 20000)):
            c = text[j]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    yield m.group(0)[:-1].strip(), text[i + 1:j], text.count('\n', 0, m.start()) + 1
                    break

def split_top(args):
    out, depth, cur = [], 0, ''
    for ch in args:
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur); cur = ''
        else:
            cur += ch
    out.append(cur)
    return out

def strip_literals(s):
    """Blank out the CONTENTS of string literals.

    A constant like "Invalid real_output" merely NAMES a field and discloses nothing; the leak is
    always an expression whose VALUE is streamed, e.g. `<< src.real_output`. Matching inside
    literals would flag static messages while adding no privacy, so the value is what is gated.
    """
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', s, flags=re.S)

def payload_of(macro, args):
    """Only the logged MESSAGE, never the asserted CONDITION."""
    parts = split_top(args)
    if macro.startswith('CHECK_AND_ASSERT_MES'):
        return ','.join(parts[2:])          # (condition, return, message...)
    if macro.startswith('THROW_WALLET_EXCEPTION'):
        return ','.join(parts[1:])
    if macro.startswith('MC'):
        return ','.join(parts[1:])          # (category, message...)
    return args

def scan(path, text):
    findings = []
    # 1. direct payloads
    for macro, args, line in statements(text):
        payload = strip_literals(payload_of(macro, args))
        for label, pat in SENSITIVE:
            if re.search(pat, payload):
                if any(path.endswith(f) and tok in payload for f, tok in ALLOW):
                    continue
                findings.append(f'{path}:{line}: {macro} logs {label}')
    # 2. indirect: a stream that received a sensitive payload and is later logged via .str()
    streams = set(re.findall(r'std::(?:o?stringstream|ostringstream)\s+(\w+)', text))
    for name in streams:
        got = []
        for w in re.finditer(re.escape(name) + r'\s*<<([^;]*);', text, re.S):
            for label, pat in SENSITIVE:
                if re.search(pat, strip_literals(w.group(1))):
                    got.append(label)
        if not got:
            continue
        for macro, args, line in statements(text):
            if re.search(re.escape(name) + r'\s*\.\s*str\s*\(\s*\)', payload_of(macro, args)):
                findings.append(f'{path}:{line}: {macro} logs stream {name} carrying {sorted(set(got))[0]}')
    return findings

# --- prove the detector catches known-bad input before trusting its silence
BAD = {
 'direct level-0 log': 'LOG_PRINT_L0("amount=" << print_money(src.amount) << ", real_output=" << src.real_output);',
 'demoted log':        'MDEBUG("x " << src.real_output);',
 'LOG_ERROR payload':  'LOG_ERROR("derived key mismatch, real out " << src_entr.real_output << "!");',
 'assert message':     'CHECK_AND_ASSERT_MES(r, false, "kd(" << crypto::secret_key_explicit_print_ref{txkey.sec} << ")");',
 'categorised log':    'MCINFO("construct_tx", "created: " << src_entr.real_output_in_tx_index);',
 'indirect stream':    ('std::stringstream ss_ring_s;\n'
                        'ss_ring_s << "real_output: " << src_entr.real_output << ENDL;\n'
                        'MCINFO("construct_tx", "transaction_created: " << h << ss_ring_s.str());'),
 'view key in assert': 'CHECK_AND_ASSERT_MES(r, false, "kd(" << crypto::secret_key_explicit_print_ref{ack.m_view_secret_key} << ")");',
}
GOOD = {
 'assert CONDITION using real_output_index':
   'CHECK_AND_ASSERT_MES(hwdev.derive_public_key(recv_derivation, real_output_index, ack.m_account_address.m_spend_public_key, in_ephemeral.pub), false, "Failed to derive public key");',
 'plain assignment':   'src.real_output = it_to_replace - src.outputs.begin();',
 'bounds check':       'if(src_entr.real_output >= src_entr.outputs.size()) { LOG_ERROR("input rejected: real output index is out of range for this input"); return false; }',
 'generic failure':    'LOG_ERROR("input rejected: derived key does not equal the referenced output key");',
 'ring signature call':'crypto::generate_ring_signature(tx_prefix_hash, ki, keys_ptrs, in_contexts[i].in_ephemeral.sec, src_entr.real_output, sigs.data());',
 'static message naming a field, no value':
   'THROW_WALLET_EXCEPTION_IF((size_t)sources_copy[idx].real_output >= sources_copy[idx].outputs.size(), error::wallet_internal_error, "Invalid real_output");',
 'explicit user display': 'message_writer() << tr("RPC client secret key: ") << crypto::secret_key_explicit_print_ref{m_wallet->get_rpc_client_secret_key()};',
}
detector_fails = 0
for name, snippet in BAD.items():
    path = 'src/simplewallet/simplewallet.cpp' if name == 'view key in assert' and False else 'src/x/y.cpp'
    if not scan(path, snippet):
        print(f'DETECTOR-MISS {name}'); detector_fails += 1
for name, snippet in GOOD.items():
    path = 'src/simplewallet/simplewallet.cpp' if name == 'explicit user display' else 'src/x/y.cpp'
    hits = scan(path, snippet)
    if hits:
        print(f'DETECTOR-FALSE-POSITIVE {name}: {hits}'); detector_fails += 1
print(f'DETECTOR_SELFTEST_FAILURES={detector_fails}')

def scan_tree(tar):
    found = []
    with tarfile.open(tar) as tf:
        for m in tf.getmembers():
            if not m.isfile() or not re.search(r'\.(cpp|h|hpp|c|inl)$', m.name):
                continue
            data = tf.extractfile(m).read().decode('utf-8', 'replace')
            found += scan(m.name, data)
    return found

# --- the detector must FIND the real historical leaks in the tree patch 0006 was applied to.
# A detector that is silent on both trees has proved nothing about the final one.
prior = scan_tree('/tmp/meepcoin-privacy-prior.tar')
for f in prior:
    print('PRIOR', f)
print(f'PRIOR_FINDINGS={len(prior)}')

# --- now the real tree
findings = scan_tree('/tmp/meepcoin-privacy-src.tar')
for f in findings:
    print('LEAK', f)
print(f'TREE_FINDINGS={len(findings)}')
PY
)
echo "$DETECT_OUT" | grep -E 'DETECTOR-MISS|DETECTOR-FALSE-POSITIVE|^LEAK' | head -20
check "the detector catches every injected known-bad case" "DETECTOR_SELFTEST_FAILURES=0" \
  "$(echo "$DETECT_OUT" | grep -o 'DETECTOR_SELFTEST_FAILURES=[0-9]*')"
check "the production tree has no automatic sensitive log payload" "TREE_FINDINGS=0" \
  "$(echo "$DETECT_OUT" | grep -o 'TREE_FINDINGS=[0-9]*')"
# The same detector, on the tree patch 0006 was applied to, must report the real leaks it removed.
PRIOR_N=$(echo "$DETECT_OUT" | grep -o 'PRIOR_FINDINGS=[0-9]*' | cut -d= -f2)
if [ "${PRIOR_N:-0}" -ge 6 ]; then ok "the detector finds the real pre-0006 leaks ($PRIOR_N)";
 else bad "the detector found only ${PRIOR_N:-0} pre-0006 leaks; it is not proving anything"; fi
rm -f /tmp/meepcoin-privacy-src.tar /tmp/meepcoin-privacy-prior.tar

echo
echo "================================================================="
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || { echo "WALLET LOG PRIVACY: FAIL"; exit 1; }
echo "WALLET LOG PRIVACY: PASS"
exit 0
