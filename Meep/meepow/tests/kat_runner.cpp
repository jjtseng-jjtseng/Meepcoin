// Known-answer-test runner: recomputes every committed vector and compares byte-for-byte
// (spec §11). Exit 0 iff all vectors reproduce exactly. Used by ctest and by the CI scripts;
// the Node/browser Wasm runners consume the same JSON files and must match.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "hex_util.hpp"
#include "json_mini.hpp"
#include "meepow/meepow.h"

using namespace meepow_test;

namespace {

bool eq_bytes(const std::vector<uint8_t>& a, const uint8_t* b, size_t n) {
    return a.size() == n && std::memcmp(a.data(), b, n) == 0;
}

int run_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) { fprintf(stderr, "cannot open %s\n", path.c_str()); return 2; }
    std::stringstream ss;
    ss << in.rdbuf();
    JsonValue root = json_parse(ss.str());
    if (root.type != JsonValue::Arr) { fprintf(stderr, "expected top-level array\n"); return 2; }

    int total = 0, failed = 0;
    for (const JsonValue& v : root.arr) {
        ++total;
        int param = (int)v.at("paramSetId").as_int();
        std::string cstr = v.at("datasetConstruction").as_str();
        uint8_t constr = (cstr == "A") ? MEEPOW_DATASET_A : MEEPOW_DATASET_B;
        auto epochKey = hex_to_bytes(v.at("epochKey").as_str(), 32);
        auto seedHash = hex_to_bytes(v.at("seedBlockHash").as_str(), 32);
        uint64_t height = hex_be_to_u64(v.at("blockHeight").as_str());
        auto tmpl = hex_to_bytes(v.at("templateBlob").as_str());  // any even length
        uint32_t nonce = hex_be_to_u32(v.at("nonce").as_str());
        uint64_t difficulty = hex_be_to_u64(v.at("difficulty").as_str());

        auto expHash = hex_to_bytes(v.at("finalHash").as_str(), 32);
        auto expC1 = hex_to_bytes(v.at("checkpointRound1").as_str(), 32);
        auto expCh = hex_to_bytes(v.at("checkpointRoundHalf").as_str(), 32);
        auto expTarget = hex_to_bytes(v.at("target").as_str(), 32);
        bool expPasses = v.at("passes").as_bool();

        meepow_dataset* ds = meepow_dataset_create((uint8_t)param, constr, epochKey.data());
        if (!ds) { fprintf(stderr, "vector %d: dataset create failed\n", total); ++failed; continue; }
        uint8_t hash[32], c1[32], ch[32], target[32];
        int rc = meepow_hash(ds, seedHash.data(), height, tmpl.empty() ? nullptr : tmpl.data(),
                             tmpl.size(), nonce, hash, c1, ch);
        meepow_dataset_free(ds);
        meepow_difficulty_to_target(difficulty, target);
        int passes = meepow_hash_meets_target(hash, target);

        bool ok = rc == 0 && eq_bytes(expHash, hash, 32) && eq_bytes(expC1, c1, 32) &&
                  eq_bytes(expCh, ch, 32) && eq_bytes(expTarget, target, 32) &&
                  (passes != 0) == expPasses;
        if (!ok) {
            ++failed;
            fprintf(stderr, "vector %d MISMATCH:\n", total);
            fprintf(stderr, "  got hash   %s\n  exp hash   %s\n",
                    bytes_to_hex(hash, 32).c_str(), v.at("finalHash").as_str().c_str());
        }
    }
    fprintf(stderr, "%s: %d/%d passed\n", path.c_str(), total - failed, total);
    return failed == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: meepow-kat <vectors.json> [more.json ...]\n"); return 2; }
    int rc = 0;
    for (int i = 1; i < argc; ++i) rc |= run_file(argv[i]);
    return rc;
}
