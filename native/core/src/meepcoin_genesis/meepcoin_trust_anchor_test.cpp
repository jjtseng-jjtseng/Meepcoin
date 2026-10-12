// MeepCoin: regression tests for the INHERITED MONERO TRUST ANCHORS.
//
// A fork of Monero inherits more than code. It inherits Monero's *decisions about what to trust*:
// hard-coded checkpoint hashes, a fixed proof-of-work answer for one historical block, a
// substituted block id for another, a precompiled checkpoint blob, and DNS names that hand out
// more checkpoints. Every one of those is correct for Monero and wrong for a different chain --
// they make a MeepCoin node treat Monero's history as authoritative and, at worst, reject its own
// legitimate low-height blocks.
//
// These run against the REAL daemon functions, not reimplementations, so they test what ships.
//
// Why a standalone binary rather than a case in tests/unit_tests/: the pinned build configures
// BUILD_TESTS=OFF, so anything added there would never run. A test that never runs is worse than no
// test, because it looks like coverage. Same reasoning, and same shape, as
// meepcoin_hardfork_test.cpp.
//
// LOCALHOST / PRIVATE DEVELOPMENT CHAIN. Dev/test coins with no monetary value.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "crypto/hash.h"
#include "crypto/meep-hash.h"
#include "serialization/string.h"   // get_object_hash(blobdata) needs the std::string serializer
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "checkpoints/checkpoints.h"
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

/** The contract the daemon itself uses when there is no chain to take a seed from. */
crypto::hash zero_seed()
{
  crypto::hash s;
  memset(&s, 0, sizeof(s));
  return s;
}

/** MeepHash-W v2 over a hashing blob, computed directly -- the answer every path must agree with. */
crypto::hash direct_meephash(const crypto::hash &seed, uint64_t height, const std::string &blob)
{
  crypto::hash out;
  meep_slow_hash(seed.data, height, blob.data(), blob.size(), out.data);
  return out;
}

/** A hashing blob that differs from another only in content, for "different input, different output". */
std::string blob_of(const char *tag, size_t len)
{
  std::string b(len, '\0');
  for (size_t i = 0; i < len; ++i) b[i] = (char)(tag[i % strlen(tag)] + (char)i);
  return b;
}

// ---------------------------------------------------------------- A. the long-hash exception
//
// Monero returns a FIXED, hard-coded proof-of-work result for height 202612 and ignores the block
// entirely. On a MeepCoin chain that height is an ordinary block, so the inherited exception makes
// the PoW of one block unfalsifiable: any blob, any nonce, same answer.
void test_longhash()
{
  printf("\n-- long hash: MeepHash at every height, no fixed exceptions --\n");

  const crypto::hash seed = zero_seed();
  const std::string blob = blob_of("meepcoin-block", 76);

  // The heights around the inherited Monero exception, plus the exception height itself.
  const uint64_t heights[] = { 202611, 202612, 202613 };
  // Both a low major version (a fresh chain mines at 1) and the current one: Monero used to branch
  // its PoW on major_version, and MeepCoin has exactly one PoW at every version.
  const int versions[] = { 1, (int)CURRENT_BLOCK_MAJOR_VERSION };

  for (uint64_t h : heights)
  {
    for (int v : versions)
    {
      crypto::hash got;
      const bool ok = get_block_longhash(NULL, blob, got, h, v, &seed, 0);
      const crypto::hash want = direct_meephash(seed, h, blob);

      char label[192];
      snprintf(label, sizeof(label),
               "main chain height %llu major_version %d equals direct MeepHash",
               (unsigned long long)h, v);
      chk(ok && got == want, label);
      if (!(ok && got == want))
        printf("        got  %s\n        want %s\n", hex(got).c_str(), hex(want).c_str());
    }
  }

  // THE DISCRIMINATING CASE. Under the inherited exception both of these returned the same fixed
  // Monero constant, which is precisely what made the exception unsafe.
  {
    const std::string a = blob_of("aaaa", 76);
    const std::string b = blob_of("bbbb", 76);
    crypto::hash ha, hb;
    get_block_longhash(NULL, a, ha, 202612, (int)CURRENT_BLOCK_MAJOR_VERSION, &seed, 0);
    get_block_longhash(NULL, b, hb, 202612, (int)CURRENT_BLOCK_MAJOR_VERSION, &seed, 0);
    chk(!(ha == hb), "height 202612: two different hashing blobs give two different results");
    if (ha == hb) printf("        both returned %s\n", hex(ha).c_str());

    chk(ha == direct_meephash(seed, 202612, a), "height 202612: blob A is the direct MeepHash of A");
    chk(hb == direct_meephash(seed, 202612, b), "height 202612: blob B is the direct MeepHash of B");

    // And specifically NOT the inherited constant.
    crypto::hash monero_fixed;
    epee::string_tools::hex_to_pod(
      std::string("84f64766475d51837ac9efbef1926486e58563c95a19fef4aec3254f03000000"), monero_fixed);
    chk(!(ha == monero_fixed) && !(hb == monero_fixed),
        "height 202612: the inherited Monero fixed long hash is never returned");
  }

  // The alternative-chain entry point must agree with the main-chain one for the same blob.
  {
    block b = boost::value_initialized<block>();
    b.major_version = (uint8_t)CURRENT_BLOCK_MAJOR_VERSION;
    b.minor_version = (uint8_t)CURRENT_BLOCK_MAJOR_VERSION;
    b.timestamp = 1700000000;
    b.nonce = 12345;
    b.prev_id = crypto::null_hash;

    const std::string hb = get_block_hashing_blob(b);
    for (uint64_t h : heights)
    {
      crypto::hash alt, main_res;
      get_altblock_longhash(b, alt, seed, h);
      get_block_longhash(NULL, hb, main_res, h, (int)b.major_version, &seed, 0);
      const crypto::hash want = direct_meephash(seed, h, hb);

      char label[192];
      snprintf(label, sizeof(label), "alt chain height %llu equals direct MeepHash",
               (unsigned long long)h);
      chk(alt == want, label);
      snprintf(label, sizeof(label), "alt chain height %llu agrees with the main chain",
               (unsigned long long)h);
      chk(alt == main_res, label);
    }

    // Changing only the nonce must change the answer at the previously-excepted height.
    block b2 = b;
    b2.nonce = 999;
    b2.invalidate_hashes();
    crypto::hash n1, n2;
    get_altblock_longhash(b,  n1, seed, 202612);
    get_altblock_longhash(b2, n2, seed, 202612);
    chk(!(n1 == n2), "height 202612: changing only the nonce changes the result");
  }
}

// ---------------------------------------------------------------- B. the historical block-id remap
//
// Monero substitutes a stored block id for one historical block whose blob hashes to a known
// value. MeepCoin has no such history; a block id must always be derived from the block.
void test_block_id()
{
  printf("\n-- block id: derived from the block, never substituted --\n");

  const crypto::hash monero_202612_id = [] {
    crypto::hash h;
    epee::string_tools::hex_to_pod(
      std::string("bbd604d2ba11ba27935e006ed39c9bfdd99b76bf4a50654bc1e1e61217962698"), h);
    return h;
  }();

  // A block whose coinbase declares height 202612 -- exactly the trigger the inherited remap used.
  for (uint64_t h : { (uint64_t)202611, (uint64_t)202612, (uint64_t)202613 })
  {
    block b = boost::value_initialized<block>();
    b.major_version = (uint8_t)CURRENT_BLOCK_MAJOR_VERSION;
    b.minor_version = (uint8_t)CURRENT_BLOCK_MAJOR_VERSION;
    b.timestamp = 1700000000 + h;
    b.nonce = (uint32_t)h;
    b.prev_id = crypto::null_hash;
    txin_gen in;
    in.height = h;
    b.miner_tx.vin.clear();
    b.miner_tx.vin.push_back(in);

    crypto::hash calculated;
    const bool ok = calculate_block_hash(b, calculated);

    crypto::hash canonical;
    chk(ok && get_object_hash(get_block_hashing_blob(b), canonical),
        "block id: the canonical hash is computable");

    char label[192];
    snprintf(label, sizeof(label), "coinbase height %llu: block id is the canonical hash",
             (unsigned long long)h);
    chk(ok && calculated == canonical, label);
    if (ok && !(calculated == canonical))
      printf("        got  %s\n        want %s\n", hex(calculated).c_str(), hex(canonical).c_str());

    snprintf(label, sizeof(label), "coinbase height %llu: never the inherited Monero block id",
             (unsigned long long)h);
    chk(!(calculated == monero_202612_id), label);
  }
}

// ---------------------------------------------------------------- C. built-in checkpoints
//
// Monero's built-in checkpoints pin Monero's chain. A MeepCoin node that loads them will reject
// its OWN low-height blocks, because they do not hash to Monero's values.
void test_checkpoints()
{
  printf("\n-- built-in checkpoints: empty until MeepCoin generates its own --\n");

  struct { network_type net; const char *name; } nets[] = {
    { MAINNET,  "MAINNET"  },
    { TESTNET,  "TESTNET"  },
    { STAGENET, "STAGENET" },
  };

  // A few inherited Monero values that must not appear anywhere in the defaults.
  const char *monero_hashes[] = {
    "bbd604d2ba11ba27935e006ed39c9bfdd99b76bf4a50654bc1e1e61217962698",  // mainnet 202612
    "771fbcd656ec1464d3a02ead5e18644030007a0fc664c0a964d30922821a8148",  // mainnet 1
    "48ca7cd3c8de5b6a4d53d2861fbdaedca141553559f9be9520068053cda8430b",  // testnet 0
    "76ee3cc98646292206cd3e86f74d88b4dcc1d937088645e9b0cbca84b7ce74eb",  // stagenet 0
  };

  for (const auto &n : nets)
  {
    checkpoints cp;
    const bool ok = cp.init_default_checkpoints(n.net);

    char label[192];
    snprintf(label, sizeof(label), "%s: init_default_checkpoints succeeds", n.name);
    chk(ok, label);

    snprintf(label, sizeof(label), "%s: no built-in checkpoints (%zu present)",
             n.name, cp.get_points().size());
    chk(cp.get_points().empty(), label);

    snprintf(label, sizeof(label), "%s: max checkpoint height is 0", n.name);
    chk(cp.get_max_height() == 0, label);

    snprintf(label, sizeof(label), "%s: height 0 is not inside a checkpoint zone", n.name);
    chk(!cp.is_in_checkpoint_zone(0), label);

    for (const char *mh : monero_hashes)
    {
      crypto::hash want;
      epee::string_tools::hex_to_pod(std::string(mh), want);
      bool found = false;
      for (const auto &kv : cp.get_points()) if (kv.second == want) found = true;
      snprintf(label, sizeof(label), "%s: inherited Monero hash %.12s... is absent", n.name, mh);
      chk(!found, label);
    }
  }
}

// ---------------------------------------------------------------- D. the per-block checkpoint blob
void test_per_block_checkpoint()
{
  printf("\n-- per-block checkpoints: the Monero blob is not compiled in --\n");
#if defined(PER_BLOCK_CHECKPOINT)
  chk(false, "PER_BLOCK_CHECKPOINT must NOT be defined for the MeepCoin build");
#else
  chk(true, "PER_BLOCK_CHECKPOINT is not defined");
#endif
}

// ---------------------------------------------------------------- E. checkpoint DNS
void test_dns_checkpoints()
{
  printf("\n-- checkpoint DNS: MoneroPulse is not consulted --\n");
  for (const auto net : { MAINNET, TESTNET, STAGENET })
  {
    checkpoints cp;
    // Must not resolve anything, must not add anything, and must not silently claim success in a
    // way that lets a caller believe DNS checkpoints are in force.
    const bool ok = cp.load_checkpoints_from_dns(net);
    chk(!ok, "load_checkpoints_from_dns is refused for MeepCoin");
    chk(cp.get_points().empty(), "and no checkpoint was imported");
  }
}

// ---------------------------------------------------------------- F. the genesis-guarded fixup
//
// BlockchainDB::fixup() re-adds key images that a historical Monero bug left out of the spent set.
// It is deliberately NOT removed, because it cannot run here: the whole body is gated on the
// height-0 block hash being EXACTLY Monero's mainnet genesis. This proves that guard cannot match
// any MeepCoin network, so the inherited body is unreachable rather than merely unused.
void test_db_fixup_is_inert()
{
  printf("\n-- database fixup: gated by the Monero genesis, therefore inert --\n");

  crypto::hash monero_mainnet_genesis;
  epee::string_tools::hex_to_pod(
    std::string("418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3"),
    monero_mainnet_genesis);

  struct netcase { const char *name; std::string tx; uint32_t nonce; };
  const netcase nets[] = {
    { "MAINNET",  ::config::GENESIS_TX,           ::config::GENESIS_NONCE           },
    { "TESTNET",  ::config::testnet::GENESIS_TX,  ::config::testnet::GENESIS_NONCE  },
    { "STAGENET", ::config::stagenet::GENESIS_TX, ::config::stagenet::GENESIS_NONCE },
  };

  for (const auto &n : nets)
  {
    block genesis;
    const bool ok = generate_genesis_block(genesis, n.tx, n.nonce);
    char label[224];
    snprintf(label, sizeof(label), "%s: MeepCoin genesis block is generated", n.name);
    chk(ok, label);
    if (!ok) continue;

    crypto::hash gid;
    const bool got = get_block_hash(genesis, gid);
    snprintf(label, sizeof(label), "%s: genesis block id is computable", n.name);
    chk(got, label);
    if (!got) continue;

    snprintf(label, sizeof(label),
             "%s: genesis %.12s is NOT Monero's mainnet genesis, so fixup() can never run",
             n.name, hex(gid).c_str());
    chk(!(gid == monero_mainnet_genesis), label);
  }
}

} // namespace

int main()
{
  printf("=================================================================\n");
  printf("MeepCoin inherited-trust-anchor tests\n");
  printf("=================================================================\n");

  test_longhash();
  test_block_id();
  test_checkpoints();
  test_per_block_checkpoint();
  test_dns_checkpoints();
  test_db_fixup_is_inert();

  meep_slow_hash_free_state();

  printf("\n=================================================================\n");
  printf("RESULT: %d passed, %d failed\n", g_pass, g_fail);
  printf("TRUST ANCHOR TESTS: %s\n", g_fail == 0 ? "PASS" : "FAIL");
  return g_fail == 0 ? 0 : 1;
}
