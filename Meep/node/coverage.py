#!/usr/bin/env python3
"""Sample-coverage accounting for topology claims.

The previous verdict code filtered the sample list to successful samples and then used `all(...)`.
`all([])` is True, so a run in which every sample errored -- or in which no sample was taken at all
-- would have reported "links up throughout". This module makes that impossible: coverage is
counted explicitly, and zero usable samples is a failure, not a pass.

Threshold values live in docs/round2/OPERATIONAL_PREREGISTRATION.md and are passed in, so the
numbers are pre-registered rather than chosen after seeing results.
"""


# --------------------------------------------------------------------- fixed preregistered policy
# The ONLY values an offline verifier may use. A raw record must never be able to choose the policy
# that validates it: reading thresholds out of the record under test let a forged report declare
# itself adequate. See docs/round2/OPERATIONAL_PREREGISTRATION.md sections 9 and 10.
TOPO_MIN_FRACTION = 0.90        # usable samples / scheduled samples, per phase
TOPO_MIN_SAMPLES = 10           # absolute floor of usable samples, per phase
TOPO_MAX_NONCONFORMANT = 0      # any non-conformant sample fails the phase
BRANCH_MAX_UNREADABLE = 2       # per phase
BRANCH_MIN_FRACTION = 0.90      # readable / observed, per phase
BRANCH_MIN_SAMPLES = 10         # readable samples, per phase
REQUIRED_NODES = ("h1", "h2", "atk")
# Only these phases carry coverage obligations. A `transition` sample -- taken after nominal mining
# end but before proven attacker quiescence -- is retained in the sequence but belongs to NEITHER
# phase, so it can inflate neither denominator.
COVERAGE_PHASES = ("mining", "post_stop")


def missing_explicit_flags(samples):
    """Samples in the CURRENT schema that fail to state both observations explicitly.

    The legacy fallbacks below exist only to describe old records. If they were allowed to run on a
    current record, an absent flag would silently become a successful observation."""
    bad = []
    for i, s in enumerate(samples):
        if not isinstance(s.get("topology_observed"), bool) or                 not isinstance(s.get("branch_readable"), bool):
            bad.append(i)
    return bad


def topology_observed(s):
    """Was the topology actually MEASURED for this sample?

    Samples written before the sampler split carry no topology_observed flag; for those the old
    top-level `error` key is the only signal, so it is honoured as a fallback. A current sample
    always states it explicitly.
    """
    if "topology_observed" in s:
        return bool(s["topology_observed"])
    return not s.get("error")


def branch_readable(s):
    """Was the branch view READ for this sample? Absent flag on a legacy sample means unknown,
    and unknown is treated as unreadable -- never as a successful observation."""
    if "branch_readable" in s:
        return bool(s["branch_readable"])
    return not s.get("error") and s.get("tips") is not None


def phase_counts(samples, phase):
    """expected/observed/conformant/non-conformant/error counts for one phase.

    "usable" here means the TOPOLOGY observation was attempted and completed. A sample whose
    branch view could not be read is still a usable topology sample: the two measurements are
    independent, and conflating them is exactly the defect this module now guards against.
    """
    inphase = [s for s in samples if s.get("phase") == phase]
    errors = [s for s in inphase if not topology_observed(s)]
    usable = [s for s in inphase if topology_observed(s)]
    conformant = [s for s in usable if s.get("topology_conformant")]
    nonconf = [s for s in usable if not s.get("topology_conformant")]
    return {"phase": phase, "observed": len(inphase), "usable": len(usable),
            "conformant": len(conformant), "non_conformant": len(nonconf),
            "errors": len(errors)}


def evaluate(samples, mine_s, post_s, sample_s, min_fraction, min_samples,
             allow_nonconformant):
    """Full coverage + conformance verdict.

    `min_fraction`  usable samples required, as a fraction of the number the sampler was scheduled
                    to take in that phase
    `min_samples`   absolute floor per phase, so a very short phase cannot pass on one sample
    `allow_nonconformant`  how many non-conformant samples a phase may contain and still count
    """
    expected = {"mining": max(1, int(mine_s // sample_s)),
                "post_stop": max(1, int(post_s // sample_s))}
    out = {"expected": expected, "phases": {}, "thresholds": {
        "min_usable_fraction": min_fraction, "min_usable_samples": min_samples,
        "max_non_conformant_samples": allow_nonconformant}}
    reasons = []
    for ph in ("mining", "post_stop"):
        c = phase_counts(samples, ph)
        exp = expected[ph]
        c["expected"] = exp
        c["usable_fraction"] = round(c["usable"] / exp, 4) if exp else 0.0
        fail = []
        if c["usable"] == 0:
            fail.append("zero usable samples")
        if c["usable"] < min_samples:
            fail.append(f"usable {c['usable']} < floor {min_samples}")
        if c["usable_fraction"] < min_fraction:
            fail.append(f"usable fraction {c['usable_fraction']} < {min_fraction}")
        if c["non_conformant"] > allow_nonconformant:
            fail.append(f"{c['non_conformant']} non-conformant samples "
                        f"> {allow_nonconformant} allowed")
        c["adequate"] = not fail
        c["failures"] = fail
        reasons += [f"{ph}: {f}" for f in fail]
        out["phases"][ph] = c
    out["adequate"] = not reasons
    out["failures"] = reasons
    return out


# --------------------------------------------------------------------------- branch readability
def branch_phase_counts(samples, phase):
    """Branch-view readability counts for one phase, independent of topology."""
    inphase = [s for s in samples if s.get("phase") == phase]
    readable = [s for s in inphase if branch_readable(s)]
    unreadable = [s for s in inphase if not branch_readable(s)]
    return {"phase": phase, "observed": len(inphase), "readable": len(readable),
            "unreadable": len(unreadable),
            "readable_fraction": round(len(readable) / len(inphase), 4) if inphase else 0.0,
            "errors": sorted({(s.get("branch_error") or "").split(":")[0]
                              for s in unreadable if s.get("branch_error")})}


def branch_evaluate(samples, mine_s, post_s, sample_s, max_unreadable, min_fraction, min_samples):
    """Preregistered branch-evidence coverage (OPERATIONAL_PREREGISTRATION.md section 9).

    All three limits apply per phase and the strictest governs:
      * at most `max_unreadable` unreadable branch samples,
      * at least `min_fraction` of observed samples readable,
      * at least `min_samples` readable samples.

    An unreadable branch view is an evidence-coverage fact. It is NEVER a topology verdict, and it
    can never be counted as same-tip, lag, fork, PARTITION or RECOVERY.
    """
    expected = {"mining": max(1, int(mine_s // sample_s)),
                "post_stop": max(1, int(post_s // sample_s))}
    out = {"expected": expected, "phases": {}, "thresholds": {
        "max_unreadable_samples": max_unreadable,
        "min_readable_fraction": min_fraction,
        "min_readable_samples": min_samples}}
    reasons = []
    for ph in ("mining", "post_stop"):
        c = branch_phase_counts(samples, ph)
        c["expected"] = expected[ph]
        fail = []
        if c["observed"] == 0:
            fail.append("zero samples observed")
        if c["unreadable"] > max_unreadable:
            fail.append(f"{c['unreadable']} unreadable branch samples > allowed {max_unreadable}")
        if c["readable_fraction"] < min_fraction:
            fail.append(f"readable fraction {c['readable_fraction']:.4f} < {min_fraction}")
        if c["readable"] < min_samples:
            fail.append(f"readable {c['readable']} < floor {min_samples}")
        c["adequate"] = not fail
        c["failures"] = fail
        out["phases"][ph] = c
        reasons += [f"{ph}: {f}" for f in fail]
    out["adequate"] = not reasons
    out["failures"] = reasons
    return out
