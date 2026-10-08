// MeepCoin v16 genesis generator + genesis-spendability auditor.
//
// SUPERSEDES node/meepcoin_genesis.cpp (the v1 generator), which is retained as a superseded
// development artifact. That generator derived the genesis output key as sec*G from a PUBLISHED
// string, so the private scalar was recoverable by anyone and the genesis reward was a spendable
// premine. This generator fixes that.
//
// UNSPENDABILITY ARGUMENT
// -----------------------
//   B = hash_to_p3(keccak(<burn-spend context>))    burn spend key, no known discrete log
//   A = hash_to_p3(keccak(<burn-view  context>))    burn view  key, no known discrete log
//   r = sc_reduce32(keccak(<txkey context>))        tx secret -- PUBLISHED, deliberately
//   R = r*G                                         tx public key
//   D = r*A                                         key derivation (computable: r is known)
//   P = Hs(D||0)*G + B                              the one-time output key
//
// To spend the output you need x with P = x*G. Then B = (x - Hs(D||0))*G, i.e. you would have
// recovered the discrete log of B. B is a hash-to-point image, so that is the discrete-log problem
// on ed25519. Publishing r does NOT help: r only reveals D and Hs(D||0), and the B term remains.
//
// Note carefully what is and is not claimed: unspendability rests on the hardness of the discrete
// log for a hash-to-curve point. It is NOT claimed to be information-theoretic.
//
// Usage:
//   meepcoin-genesis16 audit <secret_hex64> <expected_pub_hex64>
//   meepcoin-genesis16 gen <network-label> <amount-atomic> <nonce> <timestamp>
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
#include "ringct/rctOps.h"
#include "string_tools.h"

extern "C" {
#include "crypto/crypto-ops.h"
void sc_reduce32(unsigned char*);
}

using namespace cryptonote;

static std::string hex32(const void* p) {
    static const char* d = "0123456789abcdef";
    const unsigned char* b = static_cast<const unsigned char*>(p);
    std::string s(64, '0');
    for (int i = 0; i < 32; ++i) { s[i * 2] = d[b[i] >> 4]; s[i * 2 + 1] = d[b[i] & 15]; }
    return s;
}

// A point with no known discrete log: hash the context string to a curve point (cofactor cleared).
static crypto::public_key burn_point(const std::string& context) {
    crypto::hash h = crypto::cn_fast_hash(context.data(), context.size());
    rct::key k;
    std::memcpy(k.bytes, &h, 32);
    ge_p3 p3;
    rct::hash_to_p3(p3, k);
    rct::key out;
    ge_p3_tobytes(out.bytes, &p3);
    crypto::public_key pub;
    std::memcpy(&pub, out.bytes, 32);
    return pub;
}

static void derive_scalar(const std::string& context, crypto::secret_key& sec) {
    crypto::hash h = crypto::cn_fast_hash(context.data(), context.size());
    unsigned char buf[32];
    std::memcpy(buf, &h, 32);
    sc_reduce32(buf);
    std::memcpy(&sec, buf, 32);
}

// ------------------------------------------------------------------------------------------
static int do_audit(int argc, char** argv) {
    if (argc < 4) { std::fprintf(stderr, "audit <secret_hex64> <expected_pub_hex64>\n"); return 2; }
    std::string sh = argv[2], ph = argv[3];
    crypto::secret_key sec;
    crypto::public_key expect;
    if (!epee::string_tools::hex_to_pod(sh, sec) || !epee::string_tools::hex_to_pod(ph, expect)) {
        std::fprintf(stderr, "bad hex\n"); return 2;
    }
    crypto::public_key got;
    bool ok = crypto::secret_key_to_public_key(sec, got);
    std::printf("secret_is_valid_scalar = %s\n", ok ? "yes" : "no");
    std::printf("derived_public_key     = %s\n", hex32(got.data).c_str());
    std::printf("expected_public_key    = %s\n", hex32(expect.data).c_str());
    const bool match = ok && std::memcmp(&got, &expect, 32) == 0;
    std::printf("PRIVATE_KEY_IS_KNOWN   = %s\n", match ? "YES -- OUTPUT IS SPENDABLE" : "no");
    return match ? 1 : 0;   // non-zero when a known private key is proven
}

// ------------------------------------------------------------------------------------------
static int do_gen(int argc, char** argv) {
    const std::string net    = argc > 2 ? argv[2] : "devnet";
    const uint64_t amount    = argc > 3 ? strtoull(argv[3], nullptr, 10) : 0;
    const uint32_t nonce     = argc > 4 ? (uint32_t)strtoul(argv[4], nullptr, 10) : 20001;
    const uint64_t timestamp = argc > 5 ? strtoull(argv[5], nullptr, 10) : 0;

    const std::string ctx_spend = "MeepCoin/GENESIS/BURN-SPEND/v16/" + net;
    const std::string ctx_view  = "MeepCoin/GENESIS/BURN-VIEW/v16/"  + net;
    const std::string ctx_txkey = "MeepCoin/GENESIS/TXKEY/v16/"      + net;

    const crypto::public_key B = burn_point(ctx_spend);
    const crypto::public_key A = burn_point(ctx_view);

    crypto::secret_key r;
    derive_scalar(ctx_txkey, r);
    crypto::public_key R;
    if (!crypto::secret_key_to_public_key(r, R)) { std::fprintf(stderr, "txkey failed\n"); return 1; }

    crypto::key_derivation D;
    if (!crypto::generate_key_derivation(A, r, D)) { std::fprintf(stderr, "derivation failed\n"); return 1; }
    crypto::public_key P;
    if (!crypto::derive_public_key(D, 0, B, P)) { std::fprintf(stderr, "derive_public_key failed\n"); return 1; }
    crypto::view_tag vt;
    crypto::derive_view_tag(D, 0, vt);

    transaction tx{};
    tx.version = 2;                                   // RingCT-era transaction version
    tx.unlock_time = CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
    txin_gen in{};
    in.height = 0;
    tx.vin.push_back(in);

    tx_out o{};
    set_tx_out(amount, P, true /* use view tags at v16 */, vt, o);
    tx.vout.push_back(o);

    if (!add_tx_pub_key_to_extra(tx, R)) { std::fprintf(stderr, "extra failed\n"); return 1; }
    tx.rct_signatures.type = rct::RCTTypeNull;        // coinbase carries no RingCT signature
    tx.invalidate_hashes();

    const blobdata tx_blob = t_serializable_object_to_blob(tx);
    const std::string tx_hex = epee::string_tools::buff_to_hex_nodelimer(tx_blob);

    block bl{};
    if (!generate_genesis_block(bl, tx_hex, nonce)) { std::fprintf(stderr, "genesis failed\n"); return 1; }
    bl.timestamp = timestamp;
    bl.invalidate_hashes();
    const crypto::hash bh = get_block_hash(bl);

    std::printf("network_label       = %s\n", net.c_str());
    std::printf("ctx_burn_spend      = %s\n", ctx_spend.c_str());
    std::printf("ctx_burn_view       = %s\n", ctx_view.c_str());
    std::printf("ctx_txkey           = %s\n", ctx_txkey.c_str());
    std::printf("burn_spend_pub_B    = %s   (hash-to-point, NO known scalar)\n", hex32(B.data).c_str());
    std::printf("burn_view_pub_A     = %s   (hash-to-point, NO known scalar)\n", hex32(A.data).c_str());
    std::printf("tx_secret_r         = %s   (published; does not enable spending)\n", hex32(r.data).c_str());
    std::printf("tx_public_R         = %s\n", hex32(R.data).c_str());
    std::printf("output_onetime_P    = %s\n", hex32(P.data).c_str());
    std::printf("view_tag            = %02x\n", (unsigned)(unsigned char)vt.data);
    std::printf("output_type         = txout_to_tagged_key (view tags, HF >= 15)\n");
    std::printf("tx_version          = %llu\n", (unsigned long long)tx.version);
    std::printf("genesis_amount      = %llu\n", (unsigned long long)amount);
    std::printf("unlock_time         = %llu\n", (unsigned long long)tx.unlock_time);
    std::printf("genesis_nonce       = %u\n", nonce);
    std::printf("genesis_timestamp   = %llu\n", (unsigned long long)timestamp);
    std::printf("major_version       = %u\n", (unsigned)bl.major_version);
    std::printf("minor_version       = %u\n", (unsigned)bl.minor_version);
    std::printf("GENESIS_TX          = %s\n", tx_hex.c_str());
    std::printf("genesis_block_blob  = %s\n",
                epee::string_tools::buff_to_hex_nodelimer(t_serializable_object_to_blob(bl)).c_str());
    std::printf("genesis_block_hash  = %s\n", hex32(bh.data).c_str());
    return 0;
}

int main(int argc, char** argv) {
    const std::string mode = argc > 1 ? argv[1] : "gen";
    if (mode == "audit") return do_audit(argc, argv);
    return do_gen(argc, argv);
}
