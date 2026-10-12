// Real Blockchain + LMDB regression. No mock PoW, database, or fork choice.
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/difficulty.h"
#include <boost/filesystem.hpp>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <ctime>
using namespace cryptonote;
namespace {
void require(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
struct Node {
  tx_memory_pool pool;
  Blockchain chain;
  BlockchainLMDB* db;
  account_base account;
  Node(const std::string& path, size_t count, uint64_t bytes): pool(chain), chain(pool) {
    const std::pair<uint8_t, uint64_t> schedule[] = {{16, 0}, {0, 0}};
    const test_options options{schedule, 0};
    auto owned = std::unique_ptr<BlockchainLMDB>(new BlockchainLMDB);
    owned->open(path);
    db = owned.release(); // Blockchain owns the open database after init.
    require(chain.init(db, FAKECHAIN, true, &options, 20), "chain init");
    require(pool.init(), "pool init");
    chain.set_alt_block_limits(count, bytes);
    account.generate();
  }
  ~Node() { pool.deinit(); }
};
block make(Node& node, const crypto::hash* parent, unsigned salt) {
  block b{};
  difficulty_type diff;
  uint64_t height, reward, seed_height;
  crypto::hash seed;
  const blobdata extra(4, static_cast<char>(salt));
  require(node.chain.create_block_template(b, parent, node.account.get_keys().m_account_address,
    diff, height, reward, extra, seed_height, seed), "template");
  require(diff == 20, "fixed difficulty not used");
  b.timestamp = uint64_t(time(nullptr)) - 600 + height * 5;
  for (b.nonce = 0; b.nonce < 10000; ++b.nonce) {
    b.invalidate_hashes();
    crypto::hash hash;
    require(get_block_longhash(&node.chain, b, hash, height, &seed), "real PoW");
    if (check_hash(hash, diff)) return b;
  }
  throw std::runtime_error("nonce bound");
}
struct Verdict { bool result; block_verification_context context; };
Verdict submit(Node& node, const block& b) {
  block_complete_entry entry{};
  entry.block = block_to_blob(b);
  std::vector<block> parsed;
  Verdict verdict{false, {}};
  const bool prepared = node.chain.prepare_handle_incoming_blocks({entry}, parsed);
  try {
    require(prepared, "prepare");
    verdict.result = node.chain.add_new_block(b, verdict.context);
  } catch (...) { node.chain.cleanup_handle_incoming_blocks(); throw; }
  require(node.chain.cleanup_handle_incoming_blocks(), "cleanup");
  return verdict;
}
void accepted(const Verdict& v) { require(v.result && !v.context.m_verifivation_failed, "valid block rejected"); }
void limited(const Verdict& v) {
  require(!v.result && v.context.m_altchain_limited && !v.context.m_verifivation_failed &&
    !v.context.m_bad_pow && !v.context.m_marked_as_orphaned, "capacity refusal was punitive or accepted");
}
uint64_t stored_bytes(Node& n) {
  uint64_t total = 0;
  require(n.db->for_all_alt_blocks([&](const crypto::hash&, const alt_block_data_t&, const blobdata_ref* blob) {
    total += sizeof(crypto::hash) + sizeof(alt_block_data_t) + blob->size(); return true;
  }, true), "enumeration");
  return total;
}
void fill_main(Node& n) { for (unsigned i = 0; i < 8; ++i) accepted(submit(n, make(n, nullptr, 0))); }
void count_case(const std::string& root) {
  Node n(root + "/count", 8, 1024 * 1024);
  fill_main(n);
  const auto original_tip = n.db->top_block_hash();
  const auto fork = n.db->get_block_hash_from_height(1);
  crypto::hash retained;
  for (unsigned i = 0; i < 8; ++i) {
    const auto b = make(n, &fork, i + 1);
    accepted(submit(n, b));
    if (i == 0) retained = get_block_hash(b);
  }
  require(n.db->get_alt_block_count() == 8, "cache not filled");
  const auto before_bytes = stored_bytes(n);
  block refused_block;
  for (unsigned i = 0; i < 24; ++i) {
    auto b = make(n, &fork, i + 9);
    limited(submit(n, b));
    if (i == 0) refused_block = b;
  }
  require(n.db->get_alt_block_count() == 8 && stored_bytes(n) == before_bytes &&
    n.db->top_block_hash() == original_tip, "sibling flood changed bounded state");
  // Extending one retained branch must evict weaker leaves, never its ancestry.
  bool reorganized = false;
  for (unsigned i = 0; i < 7; ++i) {
    const auto b = make(n, &retained, 50);
    const auto v = submit(n, b);
    accepted(v);
    retained = get_block_hash(b);
    reorganized = reorganized || v.context.m_added_to_main_chain;
    require(n.db->get_alt_block_count() <= 8, "count ceiling exceeded during reorg");
  }
  require(reorganized && n.db->top_block_hash() == retained, "higher-work reorg lost at capacity");
  n.db->drop_alt_blocks();
  accepted(submit(n, refused_block));
  require(n.db->get_alt_block(get_block_hash(refused_block), nullptr, nullptr),
    "capacity refusal was permanently cached as invalid");
  std::cout << "{\"case\":\"count-flood-and-reorg\",\"refusedSiblings\":24,\"maxRecords\":8,\"higherWorkReorg\":true}" << std::endl;
}
void byte_case(const std::string& root) {
  Node n(root + "/bytes", 32, 850);
  fill_main(n);
  const auto fork = n.db->get_block_hash_from_height(1);
  unsigned admitted = 0, refused = 0;
  for (unsigned i = 0; i < 16; ++i) {
    const auto v = submit(n, make(n, &fork, i + 1));
    if (v.result) { accepted(v); ++admitted; } else { limited(v); ++refused; }
    require(stored_bytes(n) <= 850, "byte ceiling exceeded");
  }
  require(admitted > 0 && admitted < 16 && refused > 0 && n.db->get_alt_block_count() < 32,
    "byte limit not independently exercised");
  const auto near_tip = n.db->get_block_hash_from_height(7);
  accepted(submit(n, make(n, &near_tip, 90)));
  require(stored_bytes(n) <= 850, "replacement exceeded byte ceiling");
  std::cout << "{\"case\":\"byte-flood-and-replacement\",\"admitted\":" << admitted
    << ",\"refused\":" << refused << ",\"storedBytes\":" << stored_bytes(n) << "}" << std::endl;
}
void no_room_case(const std::string& root) {
  Node n(root + "/protected", 2, 1024 * 1024);
  fill_main(n);
  auto parent = n.db->get_block_hash_from_height(1);
  for (unsigned i = 0; i < 2; ++i) {
    const auto b = make(n, &parent, 1); accepted(submit(n, b)); parent = get_block_hash(b);
  }
  const auto before = stored_bytes(n);
  const auto b = make(n, &parent, 1);
  limited(submit(n, b));
  require(stored_bytes(n) == before && n.db->get_alt_block(parent, nullptr, nullptr),
    "protected ancestry partially evicted");
  std::cout << "{\"case\":\"protected-ancestry-refusal\",\"partialEviction\":false}" << std::endl;
}
}
int main(int argc, char** argv) {
  try {
    require(argc == 2, "usage: meepcoin-alt-storage-test NEW_DIRECTORY");
    require(!boost::filesystem::exists(argv[1]), "output exists");
    boost::filesystem::create_directories(argv[1]);
    count_case(argv[1]); byte_case(argv[1]); no_room_case(argv[1]);
    std::cout << "{\"status\":\"REAL_LMDB_ALT_STORAGE_PASS\",\"mockDatabase\":false,\"mockPow\":false}" << std::endl;
    return 0;
  } catch (const std::exception& e) { std::cerr << "ALT STORAGE FAIL: " << e.what() << std::endl; return 1; }
}
