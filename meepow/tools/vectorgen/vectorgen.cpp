// Deterministic test-vector generator (spec §11). Produces self-consistent vectors by running
// the reference library; the cross-implementation guarantee is that native (Debug/Release/ASan,
// gcc/clang), Wasm-in-Node, and browser Wasm all reproduce every field byte-for-byte.
//
// Usage: meepow-vectorgen <output_dir>
//   writes <dir>/vectors_fast.json  (param FAST, >100 vectors, both constructions)
//          <dir>/vectors_dev.json   (param DEV, a smaller set)
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <random>
#include <string>
#include <vector>

#include "hex_util.hpp"
#include "meepow/meepow.h"

using namespace meepow_test;

namespace {

struct Cfg {
    uint8_t param, constr;
    uint8_t epochKey[32], seedHash[32];
    uint64_t height;
    uint32_t nonce;
    std::vector<uint8_t> tmpl;
    uint64_t difficulty;
};

// Dataset cache keyed by (param, construction, epochKey) so DEV datasets are reused.
struct DsCache {
    std::map<std::string, meepow_dataset*> m;
    meepow_dataset* get(uint8_t param, uint8_t constr, const uint8_t key[32]) {
        std::string k;
        k.push_back((char)param);
        k.push_back((char)constr);
        k.append((const char*)key, 32);
        auto it = m.find(k);
        if (it != m.end()) return it->second;
        meepow_dataset* ds = meepow_dataset_create(param, constr, key);
        m[k] = ds;
        return ds;
    }
    ~DsCache() {
        for (auto& kv : m) meepow_dataset_free(kv.second);
    }
};

std::string vector_json(const Cfg& c, DsCache& cache) {
    meepow_dataset* ds = cache.get(c.param, c.constr, c.epochKey);
    uint8_t hash[32], c1[32], ch[32], target[32];
    meepow_hash(ds, c.seedHash, c.height, c.tmpl.empty() ? nullptr : c.tmpl.data(), c.tmpl.size(),
                c.nonce, hash, c1, ch);
    meepow_difficulty_to_target(c.difficulty, target);
    int passes = meepow_hash_meets_target(hash, target);

    std::string j = "{";
    j += "\"algoVersion\":0,";
    j += "\"paramSetId\":" + std::to_string((int)c.param) + ",";
    j += "\"datasetConstruction\":\"" + std::string(c.constr == MEEPOW_DATASET_A ? "A" : "B") + "\",";
    j += "\"epochKey\":\"" + bytes_to_hex(c.epochKey, 32) + "\",";
    j += "\"seedBlockHash\":\"" + bytes_to_hex(c.seedHash, 32) + "\",";
    j += "\"blockHeight\":\"" + u64_to_hex_be(c.height) + "\",";
    j += "\"templateBlob\":\"" + bytes_to_hex(c.tmpl.data(), c.tmpl.size()) + "\",";
    j += "\"nonce\":\"" + u32_to_hex_be(c.nonce) + "\",";
    j += "\"checkpointRound1\":\"" + bytes_to_hex(c1, 32) + "\",";
    j += "\"checkpointRoundHalf\":\"" + bytes_to_hex(ch, 32) + "\",";
    j += "\"finalHash\":\"" + bytes_to_hex(hash, 32) + "\",";
    j += "\"difficulty\":\"" + u64_to_hex_be(c.difficulty) + "\",";
    j += "\"target\":\"" + bytes_to_hex(target, 32) + "\",";
    j += std::string("\"passes\":") + (passes ? "true" : "false");
    j += "}";
    return j;
}

void fill_bytes(std::mt19937_64& rng, uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; ++i) p[i] = (uint8_t)rng();
}

std::vector<Cfg> make_configs(uint8_t param, int base_count) {
    std::mt19937_64 rng(0xC0FFEE ^ param);
    // Edge heights (spec §9) and a spread of difficulties incl. boundaries.
    uint64_t heights[] = {0, 63, 64, 2047, 2048, 2111, 2112, 4095, 4096, 4160, 100000};
    uint64_t diffs[] = {1, 2, 3, 1000, 1u << 20, 0xFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};
    std::vector<Cfg> cfgs;
    for (int i = 0; i < base_count; ++i) {
        Cfg c{};
        c.param = param;
        fill_bytes(rng, c.epochKey, 32);
        fill_bytes(rng, c.seedHash, 32);
        c.height = heights[i % (sizeof(heights) / sizeof(heights[0]))];
        c.nonce = (uint32_t)rng();
        size_t tlen = (size_t)(rng() % 40);  // includes 0-length templates
        c.tmpl.resize(tlen);
        fill_bytes(rng, c.tmpl.data(), tlen);
        c.difficulty = diffs[i % (sizeof(diffs) / sizeof(diffs[0]))];
        // Emit both constructions for each base config.
        c.constr = MEEPOW_DATASET_A;
        cfgs.push_back(c);
        c.constr = MEEPOW_DATASET_B;
        cfgs.push_back(c);
    }
    return cfgs;
}

bool write_file(const std::string& path, const std::vector<Cfg>& cfgs, DsCache& cache) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path.c_str()); return false; }
    fputs("[\n", f);
    for (size_t i = 0; i < cfgs.size(); ++i) {
        std::string j = vector_json(cfgs[i], cache);
        fputs("  ", f);
        fputs(j.c_str(), f);
        fputs(i + 1 < cfgs.size() ? ",\n" : "\n", f);
    }
    fputs("]\n", f);
    fclose(f);
    fprintf(stderr, "wrote %s (%zu vectors)\n", path.c_str(), cfgs.size());
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: meepow-vectorgen <output_dir>\n");
        return 2;
    }
    std::string dir = argv[1];
    DsCache cache;
    auto fast = make_configs(MEEPOW_PARAM_FAST, 60);  // 120 vectors
    auto dev = make_configs(MEEPOW_PARAM_DEV, 6);      // 12 vectors
    bool ok = write_file(dir + "/vectors_fast.json", fast, cache) &&
              write_file(dir + "/vectors_dev.json", dev, cache);
    return ok ? 0 : 1;
}
