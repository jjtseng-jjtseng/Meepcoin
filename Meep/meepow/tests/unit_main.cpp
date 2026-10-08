// Unit tests for the MeepHash-W v0 reference library (spec-driven).
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <cstdint>
#include <cstring>
#include <random>
#include <set>

#include "endian.hpp"
#include "epoch.hpp"
#include "meepow/meepow.h"
#include "params.hpp"
#include "program.hpp"
#include "target.hpp"

#include "pool_message.hpp"  // pool/protocol strict parser (validation only)

using namespace meepow;

// --- endian + primitives -------------------------------------------------------------------
TEST_CASE("little-endian round trips are host-independent") {
    uint8_t buf[8];
    store_u64_le(buf, 0x0102030405060708ULL);
    CHECK(buf[0] == 0x08);
    CHECK(buf[7] == 0x01);
    CHECK(load_u64_le(buf) == 0x0102030405060708ULL);
    store_u32_le(buf, 0xAABBCCDDu);
    CHECK(buf[0] == 0xDD);
    CHECK(load_u32_le(buf) == 0xAABBCCDDu);
}

TEST_CASE("rotates are defined at n=0 and n=64 (no UB)") {
    CHECK(rotl64(0x1ULL, 0) == 0x1ULL);
    CHECK(rotl64(0x1ULL, 64) == 0x1ULL);
    CHECK(rotl64(0x8000000000000000ULL, 1) == 0x1ULL);
    CHECK(rotr64(0x1ULL, 1) == 0x8000000000000000ULL);
    CHECK(rotr64(0x1ULL, 0) == 0x1ULL);
}

TEST_CASE("mulhi64 matches unsigned __int128 across random + edge inputs") {
    auto ref = [](uint64_t a, uint64_t b) -> uint64_t {
        return (uint64_t)(((unsigned __int128)a * (unsigned __int128)b) >> 64);
    };
    uint64_t edges[] = {0, 1, 2, 0xFFFFFFFFULL, 0x100000000ULL, 0xFFFFFFFFFFFFFFFFULL,
                        0x8000000000000000ULL, 0x0123456789ABCDEFULL};
    for (uint64_t a : edges)
        for (uint64_t b : edges) CHECK(mulhi64(a, b) == ref(a, b));
    std::mt19937_64 rng(12345);
    for (int i = 0; i < 200000; ++i) {
        uint64_t a = rng(), b = rng();
        CHECK(mulhi64(a, b) == ref(a, b));
    }
}

TEST_CASE("byte_shuffle selects little-endian bytes by 3-bit indices") {
    // sel picks byte 0 for every output position -> broadcast of byte 0.
    uint64_t x = 0x1122334455667788ULL;  // LE byte0 = 0x88
    CHECK(byte_shuffle(x, 0) == 0x8888888888888888ULL);
    // Identity permutation: sel = 0,1,2,3,4,5,6,7 packed 3 bits each = 0xFAC688 ... compute.
    uint64_t sel = 0;
    for (int i = 0; i < 8; ++i) sel |= (uint64_t)i << (3 * i);
    CHECK(byte_shuffle(x, sel) == x);
}

// --- opcode table --------------------------------------------------------------------------
TEST_CASE("opcode table has exactly 256 entries with the specified distribution") {
    size_t sum = 0;
    for (size_t i = 0; i < NUM_OP_WEIGHTS; ++i) sum += OP_WEIGHTS[i].count;
    CHECK(sum == 256);

    uint8_t table[256];
    build_opcode_table(table);
    int counts[OP__COUNT] = {0};
    for (int i = 0; i < 256; ++i) {
        REQUIRE(table[i] < OP__COUNT);
        counts[table[i]]++;
    }
    for (size_t i = 0; i < NUM_OP_WEIGHTS; ++i)
        CHECK(counts[OP_WEIGHTS[i].op] == OP_WEIGHTS[i].count);
    // Every opcode appears at least once.
    for (int op = 0; op < OP__COUNT; ++op) CHECK(counts[op] > 0);
}

TEST_CASE("instruction decoder maps fields per spec") {
    uint8_t table[256];
    build_opcode_table(table);
    uint8_t word[8] = {0 /*sel->first opcode*/, 0x0F /*dst=7*/, 0x0A /*src=2*/, 0xFF /*aux=63*/,
                       0x01, 0x02, 0x03, 0x04};
    Instr ins = decode_instr(word, table);
    CHECK(ins.op == table[0]);
    CHECK(ins.dst == 7);
    CHECK(ins.src == 2);
    CHECK(ins.aux == 63);
    CHECK(ins.imm == 0x04030201u);
}

// --- epoch rules ---------------------------------------------------------------------------
TEST_CASE("epoch indices/sources at the specified boundary heights") {
    struct Case { uint64_t h; bool genesis; uint64_t src; };
    Case cs[] = {
        {0, true, 0}, {63, true, 0}, {64, true, 0}, {2047, true, 0}, {2048, true, 0},
        {2111, true, 0}, {2112, false, 2047}, {4095, false, 2047}, {4096, false, 2047},
    };
    for (auto& c : cs) {
        CHECK(epoch_uses_genesis(c.h) == c.genesis);
        if (!c.genesis) CHECK(epoch_source_height(c.h) == c.src);
    }
}

TEST_CASE("seed-block heights and genesis boundary") {
    CHECK(seed_uses_genesis(0));
    CHECK(seed_uses_genesis(63));
    CHECK_FALSE(seed_uses_genesis(64));
    CHECK(seed_block_height(64) == 0);
    CHECK(seed_block_height(2112) == 2048);
}

TEST_CASE("reorg fork-point rules (strict: source above fork changes)") {
    // h=2112 -> epoch source 2047, seed height 2048.
    CHECK(reorg_changes_epoch_key(2112, 2046));
    CHECK(reorg_changes_epoch_key(2112, 2046) == true);
    CHECK_FALSE(reorg_changes_epoch_key(2112, 2047));  // fork at the source -> shared -> unchanged
    CHECK_FALSE(reorg_changes_epoch_key(2112, 2048));
    CHECK(reorg_changes_seed_block(2112, 2047));
    CHECK_FALSE(reorg_changes_seed_block(2112, 2048));
    CHECK_FALSE(reorg_changes_seed_block(2112, 2049));
    // genesis-sourced heights never change.
    CHECK_FALSE(reorg_changes_epoch_key(100, 0));
    CHECK_FALSE(reorg_changes_seed_block(10, 0));
}

// Synthetic chains for competing-chain resolution.
namespace {
struct Chain { uint8_t tag; };
const uint8_t* chain_hash(uint64_t height, void* ctx) {
    // Deterministic per-(tag,height) 32-byte hash held in a rotating static buffer.
    static thread_local uint8_t bufs[4][32];
    static thread_local int slot = 0;
    Chain* c = (Chain*)ctx;
    uint8_t* b = bufs[slot];
    slot = (slot + 1) & 3;
    for (int i = 0; i < 32; ++i) b[i] = (uint8_t)(c->tag * 131u + height * 17u + i);
    return b;
}
}  // namespace

TEST_CASE("competing chains: epoch key differs only when the source is past the fork") {
    // Two chains that agree for heights <= forkPoint and differ above it.
    uint64_t forkPoint = 2047;
    auto get_forked = [&](uint64_t tagAbove) {
        return [tagAbove, forkPoint](uint64_t height, uint8_t out[32]) {
            Chain common{7}, above{(uint8_t)tagAbove};
            const uint8_t* h =
                (height <= forkPoint) ? chain_hash(height, &common) : chain_hash(height, &above);
            std::memcpy(out, h, 32);
        };
    };
    auto keyAt = [&](uint64_t h, uint64_t tagAbove) {
        uint8_t out[32];
        auto fn = get_forked(tagAbove);
        if (epoch_uses_genesis(h)) {
            std::memcpy(out, GENESIS_SEED, 32);
        } else {
            fn(epoch_source_height(h), out);
        }
        return std::vector<uint8_t>(out, out + 32);
    };
    // h=2112 source=2047 == forkPoint -> shared -> same key on both chains.
    CHECK(keyAt(2112, 1) == keyAt(2112, 2));
    // h=4160 source = 3*... compute: (4160-64)/2048 = 4096/2048 = 2 -> source 2*2048-1=4095 > fork.
    CHECK(epoch_source_height(4160) == 4095);
    CHECK(keyAt(4160, 1) != keyAt(4160, 2));  // source above fork -> differs
    CHECK(reorg_changes_epoch_key(4160, forkPoint));
}

// --- target / difficulty -------------------------------------------------------------------
TEST_CASE("difficulty_to_target known values and invalid zero") {
    uint8_t t[32];
    CHECK(meepow_difficulty_to_target(0, t) != 0);  // zero invalid
    // difficulty 1 -> 2^256 - 1 (all 0xff).
    REQUIRE(meepow_difficulty_to_target(1, t) == 0);
    for (int i = 0; i < 32; ++i) CHECK(t[i] == 0xff);
    // difficulty 2 -> (2^256-1)/2 = 0x7fff...ff : top byte (LE offset 31) = 0x7f, rest 0xff.
    REQUIRE(meepow_difficulty_to_target(2, t) == 0);
    CHECK(t[31] == 0x7f);
    CHECK(t[0] == 0xff);
}

TEST_CASE("hash_meets_target boundary: below, equal, above") {
    uint8_t target[32];
    REQUIRE(meepow_difficulty_to_target(1000, target) == 0);
    // equal passes
    CHECK(meepow_hash_meets_target(target, target) == 1);
    // below passes: subtract 1 from the little-endian integer
    uint8_t below[32];
    std::memcpy(below, target, 32);
    for (int i = 0; i < 32; ++i) { if (below[i]-- != 0) break; }
    CHECK(meepow_hash_meets_target(below, target) == 1);
    // above fails: add 1
    uint8_t above[32];
    std::memcpy(above, target, 32);
    for (int i = 0; i < 32; ++i) { if (++above[i] != 0) break; }
    CHECK(meepow_hash_meets_target(above, target) == 0);
}

// --- end-to-end hash determinism -----------------------------------------------------------
TEST_CASE("hash is deterministic and sensitive to inputs (FAST param, both constructions)") {
    uint8_t epochKey[32], seedHash[32];
    for (int i = 0; i < 32; ++i) { epochKey[i] = (uint8_t)(i + 1); seedHash[i] = (uint8_t)(200 - i); }
    const uint8_t tmpl[5] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00};

    for (uint8_t constr : {(uint8_t)MEEPOW_DATASET_A, (uint8_t)MEEPOW_DATASET_B}) {
        meepow_dataset* ds = meepow_dataset_create(MEEPOW_PARAM_FAST, constr, epochKey);
        REQUIRE(ds != nullptr);
        uint8_t h1[32], h2[32], hN[32], c1[32], ch[32];
        REQUIRE(meepow_hash(ds, seedHash, 4096, tmpl, sizeof(tmpl), 7, h1, c1, ch) == 0);
        REQUIRE(meepow_hash(ds, seedHash, 4096, tmpl, sizeof(tmpl), 7, h2, nullptr, nullptr) == 0);
        CHECK(std::memcmp(h1, h2, 32) == 0);  // determinism
        REQUIRE(meepow_hash(ds, seedHash, 4096, tmpl, sizeof(tmpl), 8, hN, nullptr, nullptr) == 0);
        CHECK(std::memcmp(h1, hN, 32) != 0);  // nonce sensitivity
        CHECK(std::memcmp(c1, ch, 32) != 0);  // distinct checkpoints
        meepow_dataset_free(ds);
    }

    // Construction A vs B must differ (different dataset -> different hash).
    meepow_dataset* dsA = meepow_dataset_create(MEEPOW_PARAM_FAST, MEEPOW_DATASET_A, epochKey);
    meepow_dataset* dsB = meepow_dataset_create(MEEPOW_PARAM_FAST, MEEPOW_DATASET_B, epochKey);
    uint8_t ha[32], hb[32];
    REQUIRE(meepow_hash(dsA, seedHash, 4096, tmpl, sizeof(tmpl), 7, ha, nullptr, nullptr) == 0);
    REQUIRE(meepow_hash(dsB, seedHash, 4096, tmpl, sizeof(tmpl), 7, hb, nullptr, nullptr) == 0);
    CHECK(std::memcmp(ha, hb, 32) != 0);
    meepow_dataset_free(dsA);
    meepow_dataset_free(dsB);
}

TEST_CASE("reusable context path equals the one-shot path byte-for-byte") {
    uint8_t epochKey[32], seedHash[32];
    for (int i = 0; i < 32; ++i) { epochKey[i] = (uint8_t)(i * 11 + 3); seedHash[i] = (uint8_t)(i + 1); }
    const uint8_t tmpl[7] = {9, 8, 7, 6, 5, 4, 3};
    for (uint8_t constr : {(uint8_t)MEEPOW_DATASET_A, (uint8_t)MEEPOW_DATASET_B}) {
        meepow_dataset* ds = meepow_dataset_create(MEEPOW_PARAM_FAST, constr, epochKey);
        REQUIRE(ds != nullptr);
        meepow_ctx* ctx = meepow_ctx_create(ds, seedHash, 4096, tmpl, sizeof(tmpl));
        REQUIRE(ctx != nullptr);
        for (uint32_t n : {0u, 1u, 42u, 1000u, 0xFFFFFFFFu}) {
            uint8_t h1[32], c1a[32], cha[32], h2[32], c1b[32], chb[32];
            REQUIRE(meepow_hash(ds, seedHash, 4096, tmpl, sizeof(tmpl), n, h1, c1a, cha) == 0);
            REQUIRE(meepow_ctx_hash(ctx, n, h2, c1b, chb) == 0);
            CHECK(std::memcmp(h1, h2, 32) == 0);
            CHECK(std::memcmp(c1a, c1b, 32) == 0);
            CHECK(std::memcmp(cha, chb, 32) == 0);
        }
        meepow_ctx_free(ctx);
        meepow_dataset_free(ds);
    }
}

TEST_CASE("empty template blob is accepted") {
    uint8_t epochKey[32] = {1};
    meepow_dataset* ds = meepow_dataset_create(MEEPOW_PARAM_FAST, MEEPOW_DATASET_A, epochKey);
    REQUIRE(ds != nullptr);
    uint8_t h[32];
    CHECK(meepow_hash(ds, epochKey, 0, nullptr, 0, 0, h, nullptr, nullptr) == 0);
    meepow_dataset_free(ds);
}

TEST_CASE("pool client-message parser accepts valid and rejects malformed messages") {
    auto parse = [](const std::string& s) {
        return meppool::parse_client_message((const uint8_t*)s.data(), s.size());
    };
    // Valid submit_share.
    auto ok = parse(R"({"type":"submit_share","jobId":"j1","nonce":"0000002a","workerId":"w1"})");
    CHECK(ok.ok);
    CHECK(ok.type == meppool::MsgType::submit_share);
    CHECK(ok.share.nonce == 42u);
    // Valid authorize_address.
    CHECK(parse(R"({"type":"authorize_address","address":"MEEPabc123"})").type ==
          meppool::MsgType::authorize_address);
    // Malformed / hostile inputs must be rejected without crashing.
    CHECK_FALSE(parse("not json").ok);
    CHECK_FALSE(parse(R"({"type":"submit_share","jobId":"j1","workerId":"w1"})").ok);   // no nonce
    CHECK_FALSE(parse(R"({"type":"submit_share","jobId":"j1","nonce":"2a","workerId":"w1"})").ok); // short nonce
    CHECK_FALSE(parse(R"({"type":"submit_share","nonce":"0000002a","workerId":"w1"})").ok); // no jobId
    CHECK_FALSE(parse(R"({"type":"bogus"})").ok);
    CHECK_FALSE(parse(R"({"noType":1})").ok);
    CHECK_FALSE(parse(std::string(5000, 'x')).ok);  // over MAX_MESSAGE_BYTES
    // Oversized jobId rejected.
    CHECK_FALSE(parse(R"({"type":"submit_share","jobId":")" + std::string(100, 'a') +
                      R"(","nonce":"0000002a","workerId":"w1"})").ok);
}

TEST_CASE("invalid arguments are rejected") {
    uint8_t epochKey[32] = {1}, h[32];
    CHECK(meepow_dataset_create(99, MEEPOW_DATASET_A, epochKey) == nullptr);  // bad param set
    CHECK(meepow_dataset_create(MEEPOW_PARAM_FAST, 42, epochKey) == nullptr); // bad construction
    CHECK(meepow_hash(nullptr, epochKey, 0, nullptr, 0, 0, h, nullptr, nullptr) != 0);
}
