// MeepCoin genesis generator.
//
// Produces a genuinely MeepCoin-specific genesis block instead of Monero's genesis coinbase with a
// byte edited. Everything is derived deterministically from a published nothing-up-my-sleeve
// string, so any reviewer can regenerate the exact same blob and confirm nothing was hidden in it.
//
//   sec = sc_reduce32(keccak("MeepCoin/GENESIS/<network>/v1"))
//   pub = sec * G
//
// The secret keys are printed too, deliberately: the genesis output is a few atomic units on a
// valueless private chain, and a genesis nobody can audit is worse than a genesis anybody can spend.
//
// Usage: meepcoin-genesis <network-label> <amount-atomic> <nonce> <timestamp>
//
// EXPERIMENTAL DEVNET. Test coins, no monetary value.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "string_tools.h"

extern "C" void sc_reduce32(unsigned char*);

using namespace cryptonote;

// crypto::secret_key is mlocked<scrubbed<ec_scalar>>, which is deliberately NOT trivially
// copyable, so epee::pod_to_hex refuses it. Hex the underlying bytes directly.
static std::string hex32(const void* p) {
    static const char* d = "0123456789abcdef";
    const unsigned char* b = static_cast<const unsigned char*>(p);
    std::string s(64, '0');
    for (int i = 0; i < 32; ++i) { s[i * 2] = d[b[i] >> 4]; s[i * 2 + 1] = d[b[i] & 15]; }
    return s;
}

static void derive_keypair(const std::string& context, crypto::secret_key& sec,
                           crypto::public_key& pub) {
    crypto::hash h = crypto::cn_fast_hash(context.data(), context.size());
    unsigned char buf[32];
    std::memcpy(buf, &h, 32);
    sc_reduce32(buf);                      // force a canonical ed25519 scalar
    std::memcpy(&sec, buf, 32);
    crypto::secret_key_to_public_key(sec, pub);
}

int main(int argc, char** argv) {
    const std::string net    = argc > 1 ? argv[1] : "devnet";
    const uint64_t amount    = argc > 2 ? strtoull(argv[2], nullptr, 10) : 17592186044415ULL;
    const uint32_t nonce     = argc > 3 ? (uint32_t)strtoul(argv[3], nullptr, 10) : 20001;
    const uint64_t timestamp = argc > 4 ? strtoull(argv[4], nullptr, 10) : 0;

    const std::string ctx_out = "MeepCoin/GENESIS/" + net + "/v1";
    const std::string ctx_tx  = "MeepCoin/GENESIS-TXKEY/" + net + "/v1";

    crypto::secret_key out_sec, tx_sec;
    crypto::public_key out_pub, tx_pub;
    derive_keypair(ctx_out, out_sec, out_pub);
    derive_keypair(ctx_tx,  tx_sec,  tx_pub);

    // ---- build the genesis coinbase -----------------------------------------------------------
    transaction tx{};
    tx.version = 1;
    tx.unlock_time = CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;

    txin_gen in{};
    in.height = 0;
    tx.vin.push_back(in);

    tx_out o{};
    o.amount = amount;
    txout_to_key tk{};
    tk.key = out_pub;
    o.target = tk;
    tx.vout.push_back(o);

    if (!add_tx_pub_key_to_extra(tx, tx_pub)) {
        std::fprintf(stderr, "failed to add tx pub key to extra\n");
        return 1;
    }

    const blobdata tx_blob = t_serializable_object_to_blob(tx);
    const std::string tx_hex = epee::string_tools::buff_to_hex_nodelimer(tx_blob);

    // ---- assemble the genesis block and hash it ------------------------------------------------
    block bl{};
    bool ok = generate_genesis_block(bl, tx_hex, nonce);
    if (!ok) { std::fprintf(stderr, "generate_genesis_block failed\n"); return 1; }
    bl.timestamp = timestamp;
    bl.invalidate_hashes();

    const crypto::hash block_hash = get_block_hash(bl);
    const blobdata block_blob = t_serializable_object_to_blob(bl);

    std::printf("network_label      = %s\n", net.c_str());
    std::printf("derivation_out     = %s\n", ctx_out.c_str());
    std::printf("derivation_txkey   = %s\n", ctx_tx.c_str());
    std::printf("out_public_key     = %s\n", hex32(out_pub.data).c_str());
    std::printf("out_secret_key     = %s\n", hex32(out_sec.data).c_str());
    std::printf("tx_public_key      = %s\n", hex32(tx_pub.data).c_str());
    std::printf("tx_secret_key      = %s\n", hex32(tx_sec.data).c_str());
    std::printf("genesis_amount     = %llu\n", (unsigned long long)amount);
    std::printf("unlock_time        = %llu\n", (unsigned long long)tx.unlock_time);
    std::printf("genesis_nonce      = %u\n", nonce);
    std::printf("genesis_timestamp  = %llu\n", (unsigned long long)timestamp);
    std::printf("GENESIS_TX         = %s\n", tx_hex.c_str());
    std::printf("genesis_block_blob = %s\n",
                epee::string_tools::buff_to_hex_nodelimer(block_blob).c_str());
    std::printf("genesis_block_hash = %s\n", hex32(block_hash.data).c_str());
    std::printf("major_version      = %u\n", (unsigned)bl.major_version);
    std::printf("minor_version      = %u\n", (unsigned)bl.minor_version);
    return 0;
}
