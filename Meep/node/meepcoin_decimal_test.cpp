// meepcoin-decimal-test — wallet amount parsing, formatting and RPC serialization at 11 decimals.
//
// MeepCoin uses CRYPTONOTE_DISPLAY_DECIMAL_POINT = 11 and COIN = 10^11, where Monero uses 12 and
// 10^12. Every amount a user types or reads passes through cryptonote::parse_amount() and
// print_money(), both driven by a process-wide default_decimal_point. This exercises the real
// functions from the real library.
//
// Sending, receiving, fee and change accounting are covered end-to-end by the devnet integration
// test, which moves exactly 1 MEEP between two wallets and checks both balances; this binary covers
// the parse/format/serialize layer, including the edges a live transfer cannot reach (negative
// input, overflow, over-precision).
//
// LOCALHOST / PRIVATE DEVELOPMENT CHAIN. Dev/test coins with no monetary value.

#include <cstdint>
#include <cstdio>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include "cryptonote_config.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "serialization/keyvalue_serialization.h"
#include "storages/portable_storage_template_helper.h"

using namespace cryptonote;

// A stand-in for the amount-bearing structs the wallet RPC serializes (transfer destinations,
// balance replies, tx info). Amounts cross the RPC boundary as JSON integers in atomic units.
struct amount_payload
{
  uint64_t amount;
  uint64_t fee;
  uint64_t change;

  BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(amount)
    KV_SERIALIZE(fee)
    KV_SERIALIZE(change)
  END_KV_SERIALIZE_MAP()
};

static int g_pass = 0, g_fail = 0;

static void chk(bool cond, const std::string &label) {
    if (cond) { ++g_pass; std::printf("  [PASS] %s\n", label.c_str()); }
    else      { ++g_fail; std::printf("  [FAIL] %s\n", label.c_str()); }
}

// Parsing must SUCCEED and yield exactly `want` atomic units.
static void parse_ok(const std::string &text, uint64_t want) {
    uint64_t got = 0;
    const bool ok = parse_amount(got, text);
    std::ostringstream o;
    o << "parse \"" << text << "\" -> " << want << " atomic";
    if (!ok)            { o << "  (parse_amount returned false)"; chk(false, o.str()); return; }
    if (got != want)    { o << "  (got " << got << ")";           chk(false, o.str()); return; }
    chk(true, o.str());
}

// Parsing must FAIL.
static void parse_rejects(const std::string &text, const std::string &why) {
    uint64_t got = 0;
    const bool ok = parse_amount(got, text);
    std::ostringstream o;
    o << "reject \"" << text << "\"  (" << why << ")";
    if (ok) o << "  -- accepted as " << got << " atomic";
    chk(!ok, o.str());
}

static void print_is(uint64_t atomic, const std::string &want) {
    const std::string got = print_money(atomic);
    std::ostringstream o;
    o << "print " << atomic << " atomic -> \"" << want << "\"";
    if (got != want) o << "  (got \"" << got << "\")";
    chk(got == want, o.str());
}

// A parse -> print -> parse round trip must be stable.
static void round_trip(const std::string &text) {
    uint64_t a = 0, b = 0;
    const bool ok1 = parse_amount(a, text);
    if (!ok1) { chk(false, "round trip \"" + text + "\": initial parse failed"); return; }
    const std::string printed = print_money(a);
    const bool ok2 = parse_amount(b, printed);
    std::ostringstream o;
    o << "round trip \"" << text << "\" -> " << a << " -> \"" << printed << "\" -> " << b;
    chk(ok2 && a == b, o.str());
}

int main() {
    std::printf("MeepCoin 11-decimal amount tests (real parse_amount / print_money)\n");
    std::printf("=================================================================\n\n");

    // The library's decimal point is process-wide and defaults from the config; a wallet sets it
    // explicitly at load time (wallet2.cpp: set_default_decimal_point(CRYPTONOTE_DISPLAY_DECIMAL_POINT)).
    set_default_decimal_point(CRYPTONOTE_DISPLAY_DECIMAL_POINT);

    const unsigned dp = get_default_decimal_point();
    const uint64_t one_meep = COIN;                                  // 100000000000
    const uint64_t max_atomic = std::numeric_limits<uint64_t>::max(); // 18446744073709551615

    std::printf("0. Configuration\n");
    chk(dp == 11, "get_default_decimal_point() == 11");
    chk(COIN == 100000000000ULL, "COIN == 100,000,000,000 (10^11)");
    chk(CRYPTONOTE_DISPLAY_DECIMAL_POINT == 11, "CRYPTONOTE_DISPLAY_DECIMAL_POINT == 11");
    {
        uint64_t p10 = 1;
        for (unsigned i = 0; i < dp; ++i) p10 *= 10;
        chk(p10 == COIN, "COIN == 10^decimal_point (they cannot disagree)");
    }

    std::printf("\n1. 1 MEEP\n");
    parse_ok("1",            one_meep);
    parse_ok("1.0",          one_meep);
    parse_ok("1.00000000000", one_meep);          // exactly 11 fractional digits
    print_is(one_meep,       "1.00000000000");
    round_trip("1");
    chk(one_meep == 100000000000ULL, "1 MEEP is 100,000,000,000 atomic units");

    std::printf("\n2. 0.1 MEEP\n");
    parse_ok("0.1",          one_meep / 10);
    parse_ok(".1",           one_meep / 10);
    print_is(one_meep / 10,  "0.10000000000");
    round_trip("0.1");
    chk(one_meep / 10 == 10000000000ULL, "0.1 MEEP is 10,000,000,000 atomic units");

    std::printf("\n3. 0.00000000001 MEEP -- one atomic unit\n");
    parse_ok("0.00000000001", 1);
    print_is(1,               "0.00000000001");
    round_trip("0.00000000001");

    std::printf("\n4. Maximum valid amount\n");
    // uint64 max at 11 decimals.
    parse_ok("184467440.73709551615", max_atomic);
    print_is(max_atomic,             "184467440.73709551615");
    round_trip("184467440.73709551615");

    std::printf("\n5. One atomic unit above the maximum\n");
    parse_rejects("184467440.73709551616", "uint64 overflow by 1 atomic unit");
    parse_rejects("184467441",             "one whole MEEP past the representable maximum");
    parse_rejects("184467440.73709551620", "10 atomic units past the maximum");

    std::printf("\n6. Too many decimal places\n");
    // 12 fractional digits with a non-zero last digit cannot be represented at 11 decimals.
    parse_rejects("1.000000000001",   "12 fractional digits");
    parse_rejects("0.000000000001",   "12 fractional digits, smaller than one atomic unit");
    parse_rejects("1.1234567890123",  "13 fractional digits");
    // Trailing zeros beyond the decimal point ARE trimmed, so these must be accepted. This is
    // upstream behaviour worth pinning: "1.000000000000" is 1 MEEP, not a precision error.
    parse_ok("1.000000000000",  one_meep);
    parse_ok("1.0000000000000", one_meep);

    std::printf("\n7. Zero\n");
    parse_ok("0",             0);
    parse_ok("0.0",           0);
    parse_ok("0.00000000000", 0);
    print_is(0,               "0.00000000000");
    round_trip("0");

    std::printf("\n8. Negative input\n");
    parse_rejects("-1",     "negative whole amount");
    parse_rejects("-0.1",   "negative fractional amount");
    parse_rejects("-0",     "negative zero");
    parse_rejects("- 1",    "sign separated from digits");

    std::printf("\n9. Overflow and malformed input\n");
    parse_rejects("18446744073709551616",    "2^64, no decimal point");
    parse_rejects("99999999999999999999999", "far past 2^64");
    parse_rejects("",                        "empty string");
    parse_rejects(".",                       "bare decimal point");
    parse_rejects("abc",                     "not a number");
    parse_rejects("1.2.3",                   "two decimal points");
    parse_rejects("0x10",                    "hex literal");
    parse_rejects("1e5",                     "scientific notation");
    parse_rejects("+1",                      "explicit plus sign");
    parse_rejects("1 000",                   "digit grouping");

    std::printf("\n10. Fee and change magnitudes render correctly\n");
    // Figures of the size a real transfer produces, to confirm nothing is off by a factor of ten.
    print_is(one_meep * 1000,        "1000.00000000000");
    print_is(12500000000ULL,         "0.12500000000");      // the tail reward
    print_is(1192092895507ULL,       "11.92092895507");      // the genesis / initial reward
    round_trip("11.92092895507");
    round_trip("0.12500000000");
    // A change output equal to a mined reward minus 1 MEEP minus a plausible fee.
    {
        const uint64_t fee = 127794000ULL;
        const uint64_t change = 1192092895507ULL - one_meep - fee;
        std::ostringstream o;
        o << "change arithmetic: 11.92092895507 - 1 - " << print_money(fee)
          << " = " << print_money(change);
        chk(change == 1192092895507ULL - 100000000000ULL - 127794000ULL, o.str());
        round_trip(print_money(change));
        round_trip(print_money(fee));
    }

    std::printf("\n11. RPC serialization of amounts (real epee KV path)\n");
    // Amounts cross the wallet-RPC boundary as JSON integers in atomic units, never as decimal
    // strings. Values above 2^53 cannot be represented exactly by a JSON double, so a serializer
    // that round-trips through one would corrupt large amounts; that is what these check.
    {
        const uint64_t cases[] = { 0, 1, 10000000000ULL, one_meep, 12500000000ULL,
                                   1192092895507ULL, 9007199254740993ULL /* 2^53 + 1 */,
                                   max_atomic };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            amount_payload out;
            out.amount = cases[i];
            out.fee    = 127794000ULL;
            out.change = cases[i] / 2;

            std::string js;
            const bool stored = epee::serialization::store_t_to_json(out, js);

            amount_payload back;
            back.amount = back.fee = back.change = 0;
            const bool loaded = stored && epee::serialization::load_t_from_json(back, js);

            std::ostringstream o;
            o << "epee JSON round trip of " << cases[i] << " atomic";
            if (!stored)      o << "  (store failed)";
            else if (!loaded) o << "  (load failed)";
            else if (back.amount != cases[i]) o << "  (got " << back.amount << ")";
            chk(loaded && back.amount == cases[i] && back.fee == 127794000ULL
                       && back.change == cases[i] / 2, o.str());
        }
    }
    {
        // The atomic value must not be silently rescaled: 1 MEEP over RPC is 10^11, not 10^12.
        amount_payload out;
        out.amount = one_meep;
        out.fee = 0;
        out.change = 0;
        std::string js;
        chk(epee::serialization::store_t_to_json(out, js), "1 MEEP payload serializes");
        chk(js.find("100000000000") != std::string::npos,
            "serialized JSON contains 100000000000 (1 MEEP at 11 decimals)");
        chk(js.find("1000000000000") == std::string::npos,
            "serialized JSON does NOT contain 1000000000000 (that would be 12 decimals)");
    }

    std::printf("\n12. No 12-decimal assumption survives in the display path\n");
    // print_money with an explicit decimal point must still work (used by simplewallet's
    // unit selection), and the default must be 11.
    print_is(one_meep, "1.00000000000");
    chk(print_money(one_meep, 12) == "0.100000000000",
        "print_money(1 MEEP, 12) == \"0.100000000000\" -- 12 dp would show a 10x smaller number");
    chk(print_money(one_meep, 11) == "1.00000000000",
        "print_money(1 MEEP, 11) == \"1.00000000000\"");
    chk(get_default_decimal_point() == 11, "the process default is still 11 after explicit calls");

    std::printf("\n=================================================================\n");
    std::printf("RESULT: %d passed, %d failed\n", g_pass, g_fail);
    std::printf("11-DECIMAL AMOUNT TESTS: %s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
