#!/usr/bin/env python3
"""Make the decimal-point and unit-name functions work at 11 decimals.

BLOCKER found by meepcoin-decimal-test, before the integration test reached it.

cryptonote_format_utils.cpp hardcodes Monero's decimal ladder in two places:

    void set_default_decimal_point(unsigned int dp) {
      switch (dp) { case 12: case 9: case 6: case 3: case 0: ... default: THROW; }
    }
    std::string get_unit(unsigned int dp) {
      switch (dp) { case 12: return "monero"; case 9: return "millinero"; ... default: THROW; }
    }

and wallet2.cpp:5053, in the wallet's default initialisation, calls

    cryptonote::set_default_decimal_point(CRYPTONOTE_DISPLAY_DECIMAL_POINT);

which is now set_default_decimal_point(11) -- not in the switch, so it THROWS
"Invalid decimal point specification: 11". The wallet could not be created or loaded at all.

Fix: derive the accepted ladder from CRYPTONOTE_DISPLAY_DECIMAL_POINT instead of hardcoding 12, so
the same bug cannot come back if the decimal point ever changes again. The accepted values become
the whole coin and its milli/micro/nano steps, plus 0 for the atomic unit:

    11 -> "meep"        (the whole coin)
     8 -> "millimeep"   (10^-3 MEEP)
     5 -> "micromeep"   (10^-6 MEEP)
     2 -> "nanomeep"    (10^-9 MEEP)
     0 -> "atomic"      (10^-11 MEEP, the indivisible unit)

"atomic" rather than "picomeep" on purpose: pico- means 10^-12, and MeepCoin's smallest unit is
10^-11, so the SI prefix would be a false claim.

simplewallet's `set unit` command is updated to accept these names; it previously accepted only
"monero"/"millinero"/"micronero"/"nanonero"/"piconero".

Idempotent.
"""
import os, sys

ROOT = os.path.expanduser("~/meepcoin-node")
FU = os.path.join(ROOT, "src/cryptonote_basic/cryptonote_format_utils.cpp")
SW = os.path.join(ROOT, "src/simplewallet/simplewallet.cpp")
MARK = "MeepCoin: the accepted decimal ladder is derived"

# ------------------------------------------------------------------ set_default_decimal_point
OLD_SET = """  void set_default_decimal_point(unsigned int decimal_point)
  {
    switch (decimal_point)
    {
      case 12:
      case 9:
      case 6:
      case 3:
      case 0:
        default_decimal_point = decimal_point;
        break;
      default:
        ASSERT_MES_AND_THROW("Invalid decimal point specification: " << decimal_point);
    }
  }"""

NEW_SET = """  // """ + MARK + """ from CRYPTONOTE_DISPLAY_DECIMAL_POINT
  // rather than hardcoded, so changing the decimal point cannot silently break wallet loading
  // again. Upstream hardcoded Monero's 12/9/6/3/0; at MeepCoin's 11 decimals that made
  // set_default_decimal_point(CRYPTONOTE_DISPLAY_DECIMAL_POINT) throw, and wallet2 calls it during
  // default initialisation -- no wallet could be created or loaded.
  static_assert(CRYPTONOTE_DISPLAY_DECIMAL_POINT >= 9,
                "the milli/micro/nano ladder needs at least 9 decimals");

  static bool meepcoin_decimal_point_is_valid(unsigned int decimal_point)
  {
    return decimal_point == CRYPTONOTE_DISPLAY_DECIMAL_POINT
        || decimal_point == CRYPTONOTE_DISPLAY_DECIMAL_POINT - 3
        || decimal_point == CRYPTONOTE_DISPLAY_DECIMAL_POINT - 6
        || decimal_point == CRYPTONOTE_DISPLAY_DECIMAL_POINT - 9
        || decimal_point == 0;
  }

  void set_default_decimal_point(unsigned int decimal_point)
  {
    if (meepcoin_decimal_point_is_valid(decimal_point))
      default_decimal_point = decimal_point;
    else
      ASSERT_MES_AND_THROW("Invalid decimal point specification: " << decimal_point);
  }"""

# ------------------------------------------------------------------ get_unit
OLD_UNIT = """    switch (decimal_point)
    {
      case 12:
        return "monero";
      case 9:
        return "millinero";
      case 6:
        return "micronero";
      case 3:
        return "nanonero";
      case 0:
        return "piconero";
      default:
        ASSERT_MES_AND_THROW("Invalid decimal point specification: " << decimal_point);
    }"""

NEW_UNIT = """    // Names derived from CRYPTONOTE_DISPLAY_DECIMAL_POINT, not hardcoded to Monero's 12.
    // 0 is called "atomic" rather than "picomeep" because pico- means 10^-12 while MeepCoin's
    // smallest unit is 10^-11; the SI prefix would be wrong.
    if (decimal_point == CRYPTONOTE_DISPLAY_DECIMAL_POINT)
      return "meep";
    if (decimal_point == CRYPTONOTE_DISPLAY_DECIMAL_POINT - 3)
      return "millimeep";
    if (decimal_point == CRYPTONOTE_DISPLAY_DECIMAL_POINT - 6)
      return "micromeep";
    if (decimal_point == CRYPTONOTE_DISPLAY_DECIMAL_POINT - 9)
      return "nanomeep";
    if (decimal_point == 0)
      return "atomic";
    ASSERT_MES_AND_THROW("Invalid decimal point specification: " << decimal_point);"""

# ------------------------------------------------------------------ simplewallet set_unit
OLD_SW = """  if (unit == "monero")
    decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT;
  else if (unit == "millinero")
    decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT - 3;
  else if (unit == "micronero")
    decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT - 6;
  else if (unit == "nanonero")
    decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT - 9;
  else if (unit == "piconero")
    decimal_point = 0;"""

NEW_SW = """  // MeepCoin unit names; these must match cryptonote::get_unit().
  if (unit == "meep")
    decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT;
  else if (unit == "millimeep")
    decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT - 3;
  else if (unit == "micromeep")
    decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT - 6;
  else if (unit == "nanomeep")
    decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT - 9;
  else if (unit == "atomic")
    decimal_point = 0;"""


def patch(path, pairs, label):
    s = open(path).read()
    if MARK in s or (label == "simplewallet set_unit" and NEW_SW in s):
        print(f"= {label} already patched")
        return True
    for old, new in pairs:
        if old not in s:
            print(f"! anchor not found in {label}")
            return False
        s = s.replace(old, new, 1)
    open(path, "w").write(s)
    print(f"+ {label}")
    return True


ok = True
ok &= patch(FU, [(OLD_SET, NEW_SET), (OLD_UNIT, NEW_UNIT)], "cryptonote_format_utils")
ok &= patch(SW, [(OLD_SW, NEW_SW)], "simplewallet set_unit")

if not ok:
    sys.exit(1)
print("DECIMAL_UNITS_OK")
