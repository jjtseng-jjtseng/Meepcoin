// MeepCoin: regression tests for the INHERITED MONERO RUNTIME CONTACTS.
//
// The previous round removed Monero's inherited *consensus* trust anchors. This one covers a
// different class of defect: things an ordinary daemon does at runtime that reach out to, or take
// instruction from, another project's infrastructure -- and one thing it did locally that was
// worse than any of them.
//
// THE LOCAL ONE FIRST. cryptonote::generate_genesis_block() used to read an environment variable,
// MEEPCOIN_EXPERIMENTAL_GENESIS_TS, and use it as the genesis timestamp. That function is shared
// production code: the daemon calls it when it initializes an empty database, and the wallet calls
// it when it derives the network's genesis. So two copies of the SAME binary could construct
// DIFFERENT genesis blocks -- different timestamp, different hashing blob, different block id --
// purely because one of them inherited an environment variable. That is a network-identity defect,
// and a warning printed at startup does not fix it. See HARNESS_COMPAT.md.
//
// THE CONTACT ONES. tools::check_updates() resolved updates.moneropulse.* TXT records and
// tools::get_update_url() built a download URL under getmonero.org. Both are shared by the daemon's
// periodic check, the daemon's update RPC, and the wallet API, so all three had to be fixed at
// once. They now fail closed with cleared outputs and no URL.
//
// WHAT THIS FILE DOES NOT COVER, AND WHY. The removed peer seeds (clearnet DNS, fallback IPs, Tor,
// I2P), the refused --enable-dns-blocklist, and the removed DNSResolver probe are NOT asserted
// here. Instantiating node_server<> needs a live core and would build a database; and the honest
// way to prove the DNS probe is gone is to read the constructor, not to construct one and hope
// nothing leaves the machine. Those are asserted by meepcoin_runtime_quarantine_guards.sh against
// the source, and again against the built daemon's strings. Neither this binary nor that script
// makes a DNS, TCP or HTTP request.
//
// Why a standalone binary rather than a case in tests/unit_tests/: the pinned build configures
// BUILD_TESTS=OFF, so anything added there would never run. Same reasoning, and same shape, as
// meepcoin_hardfork_test.cpp and meepcoin_trust_anchor_test.cpp.
//
// THE SEED SCHEDULE (patch 0004). rx_seedheight() -- which block's id seeds MeepHash at height h --
// read SEEDHASH_EPOCH_BLOCKS and SEEDHASH_EPOCH_LAG from the environment, so the same binary could
// derive a different seed, and therefore a different proof-of-work, depending on how it was started.
// Because the old code cached the values on first use, setting a variable inside this process
// proves nothing; section 4 re-executes THIS binary as child processes with adversarial values.
// Section 5 checks the committed, daemon-generated v16 block consensus vectors through the daemon's
// own main-chain and alternative-chain entry points, and the target boundary.
//
// LOCALHOST / PRIVATE DEVELOPMENT CHAIN. Dev/test coins with no monetary value.

#include <boost/multiprecision/cpp_int.hpp>
#include <climits>
#include <cstdint>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "crypto/hash.h"
#include "crypto/meep-hash.h"
#include "serialization/string.h"   // get_object_hash(blobdata) needs the std::string serializer
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/difficulty.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "common/updates.h"
#include "string_tools.h"

using namespace cryptonote;

namespace
{
int g_pass = 0;
int g_fail = 0;

void chk(bool ok, const char *what)
{
  if (ok) { ++g_pass; printf("  ok    %s\n", what); }
  else    { ++g_fail; printf("  FAIL  %s\n", what); }
}

std::string hex(const crypto::hash &h)
{
  return epee::string_tools::pod_to_hex(h);
}

struct netcase { const char *name; std::string tx; uint32_t nonce; };

const netcase g_nets[] = {
  { "MAINNET",  ::config::GENESIS_TX,           ::config::GENESIS_NONCE           },
  { "TESTNET",  ::config::testnet::GENESIS_TX,  ::config::testnet::GENESIS_NONCE  },
  { "STAGENET", ::config::stagenet::GENESIS_TX, ::config::stagenet::GENESIS_NONCE },
};

/** Everything about a genesis block that a peer would disagree with us about. */
struct genesis_identity
{
  bool        generated;
  uint64_t    timestamp;
  std::string hashing_blob;   // the exact bytes that are hashed
  std::string block_id;

  genesis_identity() : generated(false), timestamp(0) {}
};

genesis_identity capture(const netcase &n)
{
  genesis_identity g;
  block bl;
  g.generated = generate_genesis_block(bl, n.tx, n.nonce);
  if (!g.generated)
    return g;
  g.timestamp    = bl.timestamp;
  const blobdata hb = get_block_hashing_blob(bl);
  g.hashing_blob = epee::string_tools::buff_to_hex_nodelimer(hb);
  crypto::hash id;
  g.block_id = get_block_hash(bl, id) ? hex(id) : std::string("<uncomputable>");
  return g;
}

// ---------------------------------------------------------------------------------------------
// 1. The genesis is a property of the binary, not of the environment it inherited.
// ---------------------------------------------------------------------------------------------
void test_genesis_is_environment_independent()
{
  printf("\n-- genesis determinism: no environment variable can move it --\n");

  // Two distinct, plausible timestamps. Either would have been accepted by the removed override:
  // 2026-06-01T00:00:00Z and 2021-01-01T00:00:00Z. Neither is the compiled constant.
  static const char *const probes[] = { "1780272000", "1609459200" };

  unsetenv("MEEPCOIN_EXPERIMENTAL_GENESIS_TS");

  for (size_t ni = 0; ni < sizeof(g_nets)/sizeof(g_nets[0]); ++ni)
  {
    const netcase &n = g_nets[ni];
    const genesis_identity base = capture(n);

    char label[256];
    snprintf(label, sizeof(label), "%s: genesis is generated with the variable unset", n.name);
    chk(base.generated, label);
    if (!base.generated) continue;

    snprintf(label, sizeof(label),
             "%s: genesis timestamp is the compiled constant %llu",
             n.name, (unsigned long long)MEEPCOIN_GENESIS_TIMESTAMP);
    chk(base.timestamp == (uint64_t)MEEPCOIN_GENESIS_TIMESTAMP, label);

    snprintf(label, sizeof(label), "%s: genesis id %.12s is computable", n.name, base.block_id.c_str());
    chk(base.block_id != "<uncomputable>", label);

    for (size_t pi = 0; pi < sizeof(probes)/sizeof(probes[0]); ++pi)
    {
      const char *p = probes[pi];
      setenv("MEEPCOIN_EXPERIMENTAL_GENESIS_TS", p, 1);
      const genesis_identity got = capture(n);
      unsetenv("MEEPCOIN_EXPERIMENTAL_GENESIS_TS");

      snprintf(label, sizeof(label), "%s: still generated with the variable set to %s", n.name, p);
      chk(got.generated, label);
      if (!got.generated) continue;

      snprintf(label, sizeof(label), "%s: timestamp unmoved by MEEPCOIN_EXPERIMENTAL_GENESIS_TS=%s", n.name, p);
      chk(got.timestamp == base.timestamp, label);

      snprintf(label, sizeof(label), "%s: hashing blob byte-identical with the variable set to %s", n.name, p);
      chk(got.hashing_blob == base.hashing_blob, label);

      snprintf(label, sizeof(label), "%s: block id byte-identical with the variable set to %s", n.name, p);
      chk(got.block_id == base.block_id, label);
    }
  }

  // Set-then-unset inside one process: catches a cached first read as well as a live one. This
  // does NOT prove the name is unread everywhere -- meepcoin_runtime_quarantine_guards.sh asserts
  // separately that no production source calls getenv on it at all.
  setenv("MEEPCOIN_EXPERIMENTAL_GENESIS_TS", "1780272000", 1);
  const genesis_identity a = capture(g_nets[0]);
  unsetenv("MEEPCOIN_EXPERIMENTAL_GENESIS_TS");
  const genesis_identity b = capture(g_nets[0]);
  chk(a.generated && b.generated
      && a.timestamp == b.timestamp
      && a.hashing_blob == b.hashing_blob
      && a.block_id == b.block_id,
      "MAINNET: set-then-unset produces the identical genesis in one process");
}

// ---------------------------------------------------------------------------------------------
// 2. The genesis values themselves did not move in this commit.
// ---------------------------------------------------------------------------------------------
void test_genesis_values_unchanged()
{
  printf("\n-- genesis identity: unchanged from the previous commit --\n");

  // These are the ids the trust-anchor test already reports for the three configured networks.
  // Pinning them here means a future edit to the genesis constants -- which this round explicitly
  // may NOT make -- fails loudly instead of silently producing a different chain.
  struct expect_t { const char *name; const char *prefix; };
  static const expect_t expected[] = {
    { "MAINNET",  "5ee18340" },
    { "TESTNET",  "871bc633" },
    { "STAGENET", "825a2f71" },
  };

  for (size_t i = 0; i < sizeof(g_nets)/sizeof(g_nets[0]); ++i)
  {
    const genesis_identity g = capture(g_nets[i]);
    char label[256];
    snprintf(label, sizeof(label), "%s: genesis id still begins %s (got %.8s)",
             expected[i].name, expected[i].prefix, g.block_id.c_str());
    chk(g.generated && g.block_id.compare(0, 8, expected[i].prefix) == 0, label);
  }

  chk((uint64_t)MEEPCOIN_GENESIS_TIMESTAMP == 1785283200ULL,
      "MEEPCOIN_GENESIS_TIMESTAMP is still 1785283200");
}

// ---------------------------------------------------------------------------------------------
// 4. The seed schedule is a compile-time consensus rule: exact boundaries, and no environment input.
// ---------------------------------------------------------------------------------------------
uint64_t frozen_seed_height(uint64_t h)
{
  // The frozen rule, written out independently of rx-slow-hash.c.
  return (h <= 2048 + 64) ? 0 : (h - 64 - 1) & ~(uint64_t)(2048 - 1);
}

const uint64_t g_schedule_heights[] = {
  0, 1, 63, 64, 65, 1024, 1089, 2047, 2048, 2049, 2081, 2111, 2112, 2113, 2114, 3000, 4096,
  4159, 4160, 4161, 4162, 6208, 6209, 1000000,
};

/** A deterministic stand-in chain: the id of the block at height h. */
crypto::hash synthetic_block_id(uint64_t h)
{
  const std::string tag = "meepcoin-seed-schedule-block-" + std::to_string(h);
  return crypto::cn_fast_hash(tag.data(), tag.size());
}

const std::string &schedule_blob()
{
  // A 76-byte hashing blob shaped like a v16 header (nonce at offset 39); only determinism matters.
  static const std::string blob = [] {
    std::string b(76, '\0');
    b[0] = 16; b[1] = 16;
    for (size_t i = 2; i < b.size(); ++i) b[i] = (char)(i * 7 + 3);
    return b;
  }();
  return blob;
}

/**
 * Child mode: "<height> <seed> <next> <seed block id> <MeepHash>" per line. The MeepHash is the
 * derived context's output: the seed block id at the derived seed height, fed to meep_slow_hash
 * exactly as the main-chain get_block_longhash does, so a moved seed height shows up as a moved hash.
 * (get_block_longhash itself cannot be used here: with no Blockchain it always hashes with the zero
 * genesis-generation seed.)
 */
int seed_schedule_child()
{
  for (uint64_t h : g_schedule_heights)
  {
    uint64_t seed = 0, next = 0;
    crypto::rx_seedheights(h, &seed, &next);
    const crypto::hash id = synthetic_block_id(crypto::rx_seedheight(h));
    std::string line = std::to_string(h) + " " + std::to_string(seed) + " " + std::to_string(next) + " " + hex(id);
    if (h == 2112 || h == 2113 || h == 4161 || h == 1089 || h == 2081)
    {
      crypto::hash pow;
      meep_slow_hash(id.data, h, schedule_blob().data(), schedule_blob().size(), pow.data);
      line += " " + hex(pow);
    }
    printf("%s\n", line.c_str());
  }
  meep_slow_hash_free_state();
  return 0;
}

void test_seed_schedule_is_fixed()
{
  printf("\n-- seed schedule: the frozen 2048/64 rule, at the boundaries --\n");
  static const uint64_t exact[][2] = {
    { 0, 0 }, { 2112, 0 }, { 2113, 2048 }, { 4160, 2048 }, { 4161, 4096 },
  };
  for (const auto &e : exact)
  {
    char label[160];
    snprintf(label, sizeof(label), "seed height of %llu is %llu (got %llu)",
             (unsigned long long)e[0], (unsigned long long)e[1], (unsigned long long)crypto::rx_seedheight(e[0]));
    chk(crypto::rx_seedheight(e[0]) == e[1], label);
  }

  // Every height up to three epochs past the second boundary: rx_seedheight (main chain and
  // alternative chain) and rx_seedheights (block template, get_miner_data, RPC) are the same rule.
  bool all = true, next_ok = true;
  for (uint64_t h = 0; h <= 8400; ++h)
  {
    uint64_t seed = 0, next = 0;
    crypto::rx_seedheights(h, &seed, &next);
    if (crypto::rx_seedheight(h) != frozen_seed_height(h) || seed != frozen_seed_height(h)) all = false;
    if (next != frozen_seed_height(h + 64)) next_ok = false;
  }
  chk(all, "rx_seedheight and rx_seedheights equal the frozen rule at every height 0..8400");
  chk(next_ok, "the announced next seed height is the frozen rule at height + 64, at every height 0..8400");
  chk(crypto::rx_seedheight(1000000) == 999424, "seed height of 1000000 is 999424");
}

void test_seed_schedule_ignores_environment(const char *argv0)
{
  printf("\n-- seed schedule: child processes with adversarial SEEDHASH_EPOCH_* values --\n");

  // Every one of these moved at least one seed height in the inherited code (for example 1024 put
  // height 1089 on seed 1024, and a lag of 32 put height 2081 on seed 2048). The last two were
  // already ignored by it, and must stay ignored.
  static const char *const envs[] = {
    "SEEDHASH_EPOCH_BLOCKS=1024",
    "SEEDHASH_EPOCH_LAG=32",
    "SEEDHASH_EPOCH_BLOCKS=2 SEEDHASH_EPOCH_LAG=1",
    "SEEDHASH_EPOCH_BLOCKS=16 SEEDHASH_EPOCH_LAG=8",
    "SEEDHASH_EPOCH_BLOCKS=4096",
    "SEEDHASH_EPOCH_BLOCKS=garbage SEEDHASH_EPOCH_LAG=-5",
  };

  // The absolute path of THIS executable, resolved here: inside the child's shell /proc/self/exe
  // would name the shell, not this test.
  char exe[PATH_MAX] = {0};
  const ssize_t exe_len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
  const std::string self = exe_len > 0 ? std::string(exe, (size_t)exe_len) : std::string(argv0 ? argv0 : "");
  auto run_child = [&](const std::string &assignments, std::string &out) -> bool {
    // env -u clears anything inherited first, so the baseline is truly unset.
    const std::string cmd = "env -u SEEDHASH_EPOCH_BLOCKS -u SEEDHASH_EPOCH_LAG " + assignments + " '" + self
      + "' --seed-schedule-child";
    FILE *p = popen(cmd.c_str(), "r");
    if (!p) return false;
    char buf[512];
    out.clear();
    while (fgets(buf, sizeof(buf), p)) out += buf;
    return pclose(p) == 0;
  };

  std::string baseline;
  chk(run_child("", baseline), "child with SEEDHASH_EPOCH_BLOCKS and SEEDHASH_EPOCH_LAG unset ran");

  // The baseline itself must be the frozen rule, not merely self-consistent.
  bool baseline_rule = !baseline.empty();
  size_t lines = 0;
  for (size_t pos = 0; pos < baseline.size();)
  {
    size_t eol = baseline.find('\n', pos);
    if (eol == std::string::npos) break;
    const std::string l = baseline.substr(pos, eol - pos);
    unsigned long long h = 0, s = 0, n = 0;
    char idbuf[65] = {0};
    if (sscanf(l.c_str(), "%llu %llu %llu %64s", &h, &s, &n, idbuf) != 4
        || s != frozen_seed_height(h) || n != frozen_seed_height(h + 64)
        || std::string(idbuf) != hex(synthetic_block_id(frozen_seed_height(h))))
      baseline_rule = false;
    ++lines;
    pos = eol + 1;
  }
  chk(baseline_rule && lines == sizeof(g_schedule_heights) / sizeof(g_schedule_heights[0]),
      "the unset baseline is the frozen rule: seed, next seed and seed block id at every probed height");

  for (const char *e : envs)
  {
    std::string got;
    const bool ran = run_child(e, got);
    char label[200];
    snprintf(label, sizeof(label), "[%s] child ran", e);
    chk(ran, label);
    snprintf(label, sizeof(label), "[%s] seed heights, seed block ids and MeepHash results are byte-identical to the unset baseline", e);
    chk(ran && got == baseline, label);
    if (ran && got != baseline) printf("        got:\n%s        want:\n%s", got.c_str(), baseline.c_str());
  }
}

// ---------------------------------------------------------------------------------------------
// 5. The committed v16 block consensus vectors, through the daemon's own entry points.
// ---------------------------------------------------------------------------------------------
struct block_vector
{
  uint64_t height, seed_height, difficulty;
  const char *epoch_key, *block_hash, *prev_hash, *full_block_blob, *hashing_blob, *daemon_pow_hash;
};

// Generated from meepow/vectors/block_vectors_v16_devnet.json (sha256 d73d6413...690b0d), the committed,
// daemon-generated block consensus vectors. Copied verbatim; nothing here is computed by this test.
const block_vector g_v16_vectors[] = {
  { 0ULL, 0ULL, 1ULL,
    "871bc633e7fa6b1698e8d9864472b12850baa5c7dc9c56e02e9f476d1d875c74",
    "871bc633e7fa6b1698e8d9864472b12850baa5c7dc9c56e02e9f476d1d875c74",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "10108085a5d3060000000000000000000000000000000000000000000000000000000000000000214e0000020a01ff0001939298f2d82203f0d2a4ce0987104c2a012faa2c0e4f9d6692cdce578434575de531cda04457ec972101dcd49fb892af9ddd1c7f0d1a8ab718cbd510bb4919c33ec21c718bcf1a4425560000",
    "10108085a5d3060000000000000000000000000000000000000000000000000000000000000000214e0000fe1358050f42768e6d0c16a3f6a09e5edd53b60f96b4250de25fba0f5b2fc50b01",
    "3b754379d9c81d056a430834e8b5e5e90cb81748e63ee4535f9f62912698acd8" },
  { 1ULL, 0ULL, 500ULL,
    "871bc633e7fa6b1698e8d9864472b12850baa5c7dc9c56e02e9f476d1d875c74",
    "88da0c2baa6e7c6011e7145e71f94e31ba51a076a3408f29f6116aa722a5ed87",
    "871bc633e7fa6b1698e8d9864472b12850baa5c7dc9c56e02e9f476d1d875c74",
    "1010d8cdaad306871bc633e7fa6b1698e8d9864472b12850baa5c7dc9c56e02e9f476d1d875c7497ad6a51020b01ff0101a1b9f5f1d82203e346440a1ab1f6a1984f654328cdfccc9ae23c3973ca2b33b323ebfe5467052f8621010e5a5ecbf1def7f5b944f64c7c69bf798e6fd9ca969cd18262ab1440718572410000",
    "1010d8cdaad306871bc633e7fa6b1698e8d9864472b12850baa5c7dc9c56e02e9f476d1d875c7497ad6a51944d10106441c3f3d605e3910bf3fd3ae0da178a79d3adf56bbcaf8a72dc9bed01",
    "2d813368a51e8841841a344e204bb78ea77b773f6725e9808b03e1d1c0041700" },
  { 63ULL, 0ULL, 500ULL,
    "871bc633e7fa6b1698e8d9864472b12850baa5c7dc9c56e02e9f476d1d875c74",
    "318191b7deea2c1bb65190413d13bd5a243332ee787883238a26d715087703d1",
    "f8a3793a4fc19d29f30bda067299535cef4fc82b0a0d194456f4b31c8c36fd8f",
    "1010f3ceaad306f8a3793a4fc19d29f30bda067299535cef4fc82b0a0d194456f4b31c8c36fd8f79179e62024901ff3f018bb68ee1d82203e67e424530e1b02dfe858505891545b5effa472c9a6cb86c6f7e6017a72e0b90d62101248b76a0d160aead476894dbb35270083c995896d1b9e9eef02fec8446efcb700000",
    "1010f3ceaad306f8a3793a4fc19d29f30bda067299535cef4fc82b0a0d194456f4b31c8c36fd8f79179e622ff5da5de68295ababe28b7d3c21453f9276fd1f94c4737605266ce0c9d93ca801",
    "d38feca115a2254366ad76824fd5ab7bc5e6749ae2762a431cb7ed42ea652e00" },
  { 64ULL, 0ULL, 500ULL,
    "871bc633e7fa6b1698e8d9864472b12850baa5c7dc9c56e02e9f476d1d875c74",
    "60f798654f97008c6c0c121d50838f91f36f5645a8dee0ca0bb5a87f74d1ad66",
    "318191b7deea2c1bb65190413d13bd5a243332ee787883238a26d715087703d1",
    "1010f3ceaad306318191b7deea2c1bb65190413d13bd5a243332ee787883238a26d715087703d1666e7fad024a01ff4001aaddebe0d82203bbda21e43c18410ac13fa5d06584e604cb7d36c3560fddb88f1ecf70247cd5c21a21017ba8dd8bb98d585f9ad8159707e60b7527493034224cbfb109543ff674ac19d00000",
    "1010f3ceaad306318191b7deea2c1bb65190413d13bd5a243332ee787883238a26d715087703d1666e7fad35d9bf8dc24fcdc54fb33f3ea9f6494e1694480802b034bd158e5b9b520f561701",
    "6c070dc3a22deb6ed8543588eceb0c667f46159903279fe33d2fde7437980b00" },
  { 2047ULL, 0ULL, 500ULL,
    "871bc633e7fa6b1698e8d9864472b12850baa5c7dc9c56e02e9f476d1d875c74",
    "351b8b1007298279380c626545d94d564aca766492441f20703cca85a16c2615",
    "540001a605ffeda811966f18c28830dfec1597b5796c9f59de55eaf81c30c8e5",
    "1010fee1aad306540001a605ffeda811966f18c28830dfec1597b5796c9f59de55eaf81c30c8e548d1cecb02891001ffff0f01fd98cfc7d42203e286e63960b48be2a110e72825e15a6daff8cce5b9b3c6067815c18d3cad6e81082101d43014759dafcfdcce59c8f988cc400c1041619fd60de7834d5f9540d22a12ea0000",
    "1010fee1aad306540001a605ffeda811966f18c28830dfec1597b5796c9f59de55eaf81c30c8e548d1cecbe231c63d781df3e9bdf787e1728eb6b0fa72c6ce55bd80204fd17d27e6edec8f01",
    "6f3d62896b5a9045d13923e231e9e88198368738cf9af6f35fe7081173990300" },
  { 2048ULL, 0ULL, 500ULL,
    "871bc633e7fa6b1698e8d9864472b12850baa5c7dc9c56e02e9f476d1d875c74",
    "f66b60ce6a36fadf91424164c663643432c049f2af10a8141fe32f07a41d305f",
    "351b8b1007298279380c626545d94d564aca766492441f20703cca85a16c2615",
    "1010ffe1aad306351b8b1007298279380c626545d94d564aca766492441f20703cca85a16c2615eb680a43028a1001ff801001b5c4acc7d4220398a140efa48555f592e278b29a1fb3912f1773058c96204b87e5ce1afdd5113e9d2101dce8c779b858ffd74dc1e046e8aaa68c27dc0b261f4912a37d76a3b24dc35b590000",
    "1010ffe1aad306351b8b1007298279380c626545d94d564aca766492441f20703cca85a16c2615eb680a43121454804bb84f32af019995bd7a35e24607f788574f08798810242d1bd3bf2301",
    "fc197b45244f3a9fdfc8897a3cf1f568706bdaf4e015ab339be0e542bf683a00" },
  { 2112ULL, 0ULL, 500ULL,
    "871bc633e7fa6b1698e8d9864472b12850baa5c7dc9c56e02e9f476d1d875c74",
    "4276a417e58b300668c2f41b8c2307c99a350580b7d3b17b851993b9f65a97d5",
    "8613d92f974fd64cd2afde03abb1be787ff5e0812246f246b024c8a3dd2db87e",
    "1010bfe2aad3068613d92f974fd64cd2afde03abb1be787ff5e0812246f246b024c8a3dd2db87ede66dcd502ca1001ffc0100181a582b6d42203871c5fc56d49f355ba8347d6b18eebeff37c09b8857ef3c863e223c46c4b2a128c2101303aab41acb6b50a49a49bfd1f38b680c69a4de5d284e9fd16470006c32f07690000",
    "1010bfe2aad3068613d92f974fd64cd2afde03abb1be787ff5e0812246f246b024c8a3dd2db87ede66dcd5337b8d76072b3d8e6a018677f646144f21b2675e7e7ee5c0d32f399f5c6b0aa101",
    "7b02efe852edad14c282877c0c64d30f401a7b4f5f382358871b65efd5652300" },
  { 2113ULL, 2048ULL, 500ULL,
    "f66b60ce6a36fadf91424164c663643432c049f2af10a8141fe32f07a41d305f",
    "c32e39e215733d4ef3b54989ec72a45bc3b7ee15713f63dcd8ed7faa44482375",
    "4276a417e58b300668c2f41b8c2307c99a350580b7d3b17b851993b9f65a97d5",
    "1010c4e2aad3064276a417e58b300668c2f41b8c2307c99a350580b7d3b17b851993b9f65a97d5cb1c084f02cb1001ffc11001cbd0dfb5d42203ce300bf8da5643f4bea654d1f1b876a3e48486eab91f754d96149629b79deaafbe210165a679d8786b93365c7b149807a10fccf80311a2784ec29e2e3d2446af4479cb0000",
    "1010c4e2aad3064276a417e58b300668c2f41b8c2307c99a350580b7d3b17b851993b9f65a97d5cb1c084fd717816aa6ff5d5c8258597957e515ecaf0d46eab5681d97b53ca4f8b336aa0e01",
    "0f25c4a8f186c14795b2978948b1fa6b44c6f58ecce4c1a991b4eb5638f31600" },
};

crypto::hash pod_hash(const char *h)
{
  crypto::hash out;
  if (!epee::string_tools::hex_to_pod(std::string(h), out)) memset(out.data, 0xee, sizeof(out.data));
  return out;
}

void test_block_consensus_vectors()
{
  printf("\n-- block consensus vectors (v16, daemon-generated): seed rule, main and alternative chain --\n");
  const size_t n = sizeof(g_v16_vectors) / sizeof(g_v16_vectors[0]);
  auto id_at = [&](uint64_t height) -> const char * {
    for (size_t j = 0; j < n; ++j) if (g_v16_vectors[j].height == height) return g_v16_vectors[j].block_hash;
    return nullptr;
  };
  bool seed_rule = true, seed_id_ok = true, main_ok = true, alt_ok = true, blob_ok = true, id_ok = true, target_ok = true;
  for (size_t i = 0; i < n; ++i)
  {
    const block_vector &v = g_v16_vectors[i];
    if (crypto::rx_seedheight(v.height) != v.seed_height) seed_rule = false;

    // THE MAIN-CHAIN DERIVATION: the block id AT rx_seedheight(h), read by height, is the seed.
    const char *main_seed_id = id_at(crypto::rx_seedheight(v.height));
    if (!main_seed_id || std::string(main_seed_id) != v.epoch_key) { seed_id_ok = false; continue; }
    const crypto::hash seed = pod_hash(main_seed_id);
    const crypto::hash want = pod_hash(v.daemon_pow_hash);
    std::string hb, fb;
    epee::string_tools::parse_hexstr_to_binbuff(std::string(v.hashing_blob), hb);
    epee::string_tools::parse_hexstr_to_binbuff(std::string(v.full_block_blob), fb);

    // ...hashed exactly as get_block_longhash(pbc, ...) hashes it on the main chain.
    crypto::hash main_pow;
    meep_slow_hash(seed.data, v.height, hb.data(), hb.size(), main_pow.data);
    if (!(main_pow == want)) main_ok = false;

    block b;
    if (!parse_and_validate_block_from_blob(fb, b)) { blob_ok = false; alt_ok = false; id_ok = false; continue; }
    if (get_block_hashing_blob(b) != hb) blob_ok = false;
    crypto::hash alt_pow;
    get_altblock_longhash(b, alt_pow, seed, v.height);
    if (!(alt_pow == want)) alt_ok = false;
    if (!(get_block_hash(b) == pod_hash(v.block_hash))) id_ok = false;
    if (!check_hash(want, v.difficulty)) target_ok = false;
  }
  chk(seed_rule, "rx_seedheight reproduces every vector's committed seed height");
  chk(seed_id_ok, "the block id at rx_seedheight(h) is every vector's committed seed (epoch key)");
  chk(main_ok, "the main-chain derivation (that seed into meep_slow_hash) reproduces every daemon PoW byte-for-byte");
  chk(alt_ok, "get_altblock_longhash (alternative-chain path) reproduces every daemon PoW byte-for-byte");
  chk(blob_ok, "every full block parses and yields exactly its committed hashing blob");
  chk(id_ok, "every block id is exactly the committed one");
  chk(target_ok, "every committed PoW meets its committed difficulty");

  // THE SEED BLOCK ID AT THE FROZEN SEED HEIGHT. Height 2113's seed is block 2048's id: the main chain
  // reads it by height, and the alternative chain walks to the block at seed height + 1 and takes its
  // prev_id. Height 1's parent is the id at its seed height 0.
  const block_vector *v0 = nullptr, *v1 = nullptr, *v2048 = nullptr, *v2113 = nullptr;
  for (size_t i = 0; i < n; ++i)
  {
    if (g_v16_vectors[i].height == 0) v0 = &g_v16_vectors[i];
    if (g_v16_vectors[i].height == 1) v1 = &g_v16_vectors[i];
    if (g_v16_vectors[i].height == 2048) v2048 = &g_v16_vectors[i];
    if (g_v16_vectors[i].height == 2113) v2113 = &g_v16_vectors[i];
  }
  chk(v2048 && v2113 && std::string(v2113->epoch_key) == v2048->block_hash,
      "height 2113's MeepHash seed is exactly the id of block 2048 (its frozen seed height)");
  chk(v0 && v1 && std::string(v1->prev_hash) == v0->block_hash && std::string(v1->epoch_key) == v0->block_hash,
      "height 1's seed is the id of block 0, which is also what the next block's prev_id names");

  // The target boundary for difficulty 500: the largest passing hash passes, one more fails.
  {
    using boost::multiprecision::cpp_int;
    const cpp_int max256 = (cpp_int(1) << 256) - 1;
    const cpp_int limit = max256 / 500;
    auto to_hash = [](cpp_int x) {
      crypto::hash h;
      for (size_t i = 0; i < 32; ++i) { h.data[i] = (char)static_cast<unsigned>(cpp_int(x % 256)); x /= 256; }
      return h;
    };
    chk(check_hash(to_hash(limit), 500), "difficulty 500: the largest passing hash passes");
    chk(!check_hash(to_hash(limit + 1), 500), "difficulty 500: one above it fails");
  }

  // A different nonce is a different proof-of-work: the vector's PoW does not transfer.
  if (v2113)
  {
    std::string hb;
    epee::string_tools::parse_hexstr_to_binbuff(std::string(v2113->hashing_blob), hb);
    hb[39] = (char)(hb[39] ^ 0x01);
    const crypto::hash seed = pod_hash(v2113->epoch_key);
    crypto::hash moved;
    meep_slow_hash(seed.data, v2113->height, hb.data(), hb.size(), moved.data);
    chk(!(moved == pod_hash(v2113->daemon_pow_hash)), "height 2113 with one nonce bit flipped does not reproduce the vector's PoW");
  }
}

// ---------------------------------------------------------------------------------------------
// 3. The shared update helper fails closed and hands out no URL.
// ---------------------------------------------------------------------------------------------
void test_update_helper_fails_closed()
{
  printf("\n-- update supply chain: fails closed, no DNS, no URL --\n");

  // Deliberately pre-poisoned: if the implementation returned early without clearing them, the
  // caller would keep believing an update exists. Monero's daemon, its update RPC and the wallet
  // API all share this one function, so this is the single point that has to be right.
  std::string version = "9.9.9";
  std::string hash    = "deadbeef";

  const bool found = tools::check_updates("meepcoin", "source", version, hash);

  chk(!found, "tools::check_updates() reports no update");
  chk(version.empty(), "tools::check_updates() clears the version output");
  chk(hash.empty(), "tools::check_updates() clears the hash output");

  const std::string user_uri = tools::get_update_url("meepcoin", "source", "source", "0.18.5.1", true);
  const std::string auto_uri = tools::get_update_url("meepcoin", "source", "source", "0.18.5.1", false);

  chk(user_uri.empty(), "tools::get_update_url(user=true) returns no URL");
  chk(auto_uri.empty(), "tools::get_update_url(user=false) returns no URL");

  // Whatever they return, it must not name anyone's infrastructure.
  const std::string both = user_uri + auto_uri + version + hash;
  chk(both.find("getmonero") == std::string::npos, "no getmonero host in any update output");
  chk(both.find("moneropulse") == std::string::npos, "no moneropulse host in any update output");
}

} // namespace

int main(int argc, char **argv)
{
  // The child mode of section 4: print the seed schedule this process derives, and nothing else.
  if (argc == 2 && std::string(argv[1]) == "--seed-schedule-child")
    return seed_schedule_child();
  const char *argv0 = argc > 0 ? argv[0] : "";
  printf("=================================================================\n");
  printf("MeepCoin inherited-runtime-contact tests\n");
  printf("NOTE: this binary makes no DNS, TCP or HTTP request.\n");
  printf("=================================================================\n");

  test_genesis_is_environment_independent();
  test_genesis_values_unchanged();
  test_update_helper_fails_closed();

  test_seed_schedule_is_fixed();
  test_seed_schedule_ignores_environment(argv0);
  test_block_consensus_vectors();

  meep_slow_hash_free_state();

  printf("\n=================================================================\n");
  printf("RESULT: %d passed, %d failed\n", g_pass, g_fail);
  printf("RUNTIME QUARANTINE TESTS: %s\n", g_fail == 0 ? "PASS" : "FAIL");
  return g_fail == 0 ? 0 : 1;
}
