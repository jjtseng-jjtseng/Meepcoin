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
struct FaultLMDB: BlockchainLMDB {
  bool fail_insert = false;
  void add_alt_block(const crypto::hash& id, const alt_block_data_t& data, const blobdata_ref& blob) override {
    if (fail_insert) throw DB_ERROR("deliberate insertion fault after planned eviction");
    BlockchainLMDB::add_alt_block(id, data, blob);
  }
};
struct Node {
  tx_memory_pool pool;
  Blockchain chain;
  BlockchainLMDB* db;
  account_base account;
  Node(const std::string& path, size_t count, uint64_t bytes): pool(chain), chain(pool) {
    const std::pair<uint8_t, uint64_t> schedule[] = {{16, 0}, {0, 0}};
    const test_options options{schedule, 0};
    auto owned = std::unique_ptr<BlockchainLMDB>(new FaultLMDB);
    owned->open(path);
    db = owned.release(); // Blockchain owns the open database after init.
    require(chain.init(db, FAKECHAIN, true, &options, 20), "chain init");
    require(pool.init(), "pool init");
    chain.set_alt_block_limits(count, bytes);
    chain.set_invalid_block_limit(4);
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
void winning_boundary_case(const std::string& root) {
  Node n(root + "/winning-boundary", 8, 1024 * 1024);
  fill_main(n);
  auto parent = n.db->get_block_hash_from_height(0);
  for (unsigned i = 0; i < 8; ++i) {
    const auto b = make(n, &parent, 1); accepted(submit(n, b)); parent = get_block_hash(b);
  }
  require(n.db->get_alt_block_count() == 8, "protected boundary not full");
  const auto winning = make(n, &parent, 1);
  const auto v = submit(n, winning);
  accepted(v);
  require(v.context.m_added_to_main_chain && n.db->top_block_hash() == get_block_hash(winning),
    "winning candidate wrongly required an extra storage slot");
  require(n.db->get_alt_block_count() <= 8, "retained disconnected branch exceeded ceiling");
  std::cout << "{\"case\":\"winning-candidate-at-protected-capacity\",\"higherWorkReorg\":true}" << std::endl;
}
block excessive_reward(Node& n, block b) {
  ++b.miner_tx.vout.front().amount;
  b.miner_tx.invalidate_hashes();
  for (b.nonce = 0; b.nonce < 10000; ++b.nonce) {
    b.invalidate_hashes();
    crypto::hash hash;
    require(get_block_longhash(&n.chain, b, hash, get_block_height(b), nullptr), "invalid reward PoW");
    if (check_hash(hash, difficulty_type(20))) return b;
  }
  throw std::runtime_error("invalid reward nonce bound");
}
void failed_winner_case(const std::string& root, bool bad_ancestor) {
  Node n(root + (bad_ancestor ? "/bad-ancestor" : "/bad-winner"), 8, 1024 * 1024);
  fill_main(n);
  const auto tip = n.db->top_block_hash();
  const auto height = n.db->height();
  const auto work = n.db->get_block_cumulative_difficulty(height - 1);
  auto parent = n.db->get_block_hash_from_height(0);
  for (unsigned i = 0; i < 8; ++i) {
    auto b = make(n, &parent, 1);
    if (bad_ancestor && i == 4) b = excessive_reward(n, b);
    accepted(submit(n, b)); parent = get_block_hash(b);
  }
  auto winner = make(n, &parent, 1);
  if (!bad_ancestor) winner = excessive_reward(n, winner);
  const auto v = submit(n, winner);
  require(!v.result && v.context.m_verifivation_failed, "invalid reward fork accepted");
  require(n.db->top_block_hash() == tip && n.db->height() == height &&
    n.db->get_block_cumulative_difficulty(height - 1) == work, "failed reorg did not restore canonical state");
  require(n.db->get_alt_block_count() == (bad_ancestor ? 4 : 8), "failed reorg removed wrong retained ancestors");
  if (!bad_ancestor) {
    int where = -1;
    require(n.chain.have_block(get_block_hash(winner), &where) && where == HAVE_BLOCK_INVALID,
      "invalid winning reward was not remembered");
    const auto replay = submit(n, winner);
    require(!replay.result && replay.context.m_already_exists && !replay.context.m_added_to_main_chain,
      "invalid winner replay repeated validation");
    require(n.db->top_block_hash() == tip && n.db->get_alt_block_count() == 8,
      "duplicate invalid winner changed chain state");
    const auto valid_winner = make(n, &parent, 2);
    accepted(submit(n, valid_winner));
    require(n.db->top_block_hash() == get_block_hash(valid_winner), "invalid identity poisoned a valid sibling");
  }
  std::cout << "{\"case\":\"" << (bad_ancestor ? "invalid-intermediate-reorg" : "invalid-uncached-winner-reorg")
    << "\",\"canonicalRestored\":true}" << std::endl;
}
void invalid_identity_case(const std::string& root) {
  Node n(root + "/invalid-identities", 8, 1024 * 1024);
  fill_main(n);
  const auto tip = n.db->top_block_hash();
  crypto::hash first{}, last{};
  for (unsigned i = 0; i < 5; ++i) {
    const auto bad = excessive_reward(n, make(n, nullptr, i + 1));
    const auto v = submit(n, bad);
    require(!v.result && v.context.m_verifivation_failed, "bad reward accepted");
    if (i == 0) first = get_block_hash(bad);
    last = get_block_hash(bad);
    require(n.chain.get_invalid_block_count() <= 4 && n.db->top_block_hash() == tip,
      "invalid identities exceeded bound or changed canonical chain");
  }
  int where = -1;
  require(n.chain.get_invalid_block_count() == 4 && !n.chain.have_block(first) &&
    n.chain.have_block(last, &where) && where == HAVE_BLOCK_INVALID, "invalid FIFO eviction failed");
  n.chain.flush_invalid_blocks();
  require(n.chain.get_invalid_block_count() == 0 && !n.chain.have_block(last), "invalid cache flush incomplete");
  std::cout << "{\"case\":\"bounded-invalid-identities\",\"maxIdentities\":4,\"fifoEvicted\":true,\"flushCleared\":true}" << std::endl;
}
void atomic_eviction_case(const std::string& root) {
  Node n(root + "/eviction-fault", 2, 1024 * 1024);
  fill_main(n);
  auto fork = n.db->get_block_hash_from_height(1);
  const auto a = make(n, &fork, 1), b = make(n, &fork, 2);
  accepted(submit(n, a)); accepted(submit(n, b));
  auto parent = get_block_hash(a);
  const auto child = make(n, &parent, 3);
  const auto before = stored_bytes(n);
  const auto tip = n.db->top_block_hash();
  static_cast<FaultLMDB*>(n.db)->fail_insert = true;
  const auto v = submit(n, child);
  static_cast<FaultLMDB*>(n.db)->fail_insert = false;
  require(!v.result && v.context.m_verifivation_failed, "insertion fault accepted");
  require(n.db->top_block_hash() == tip && stored_bytes(n) == before && n.db->get_alt_block_count() == 2 &&
    n.db->get_alt_block(get_block_hash(a), nullptr, nullptr) && n.db->get_alt_block(get_block_hash(b), nullptr, nullptr),
    "failed insertion committed partial eviction");
  accepted(submit(n, child));
  require(n.db->get_alt_block_count() == 2 && n.db->get_alt_block(parent, nullptr, nullptr), "retry lost protected parent");
  std::cout << "{\"case\":\"eviction-insertion-exception\",\"transactionAborted\":true,\"sameBytesRetry\":true}" << std::endl;
}
}
int main(int argc, char** argv) {
  try {
    require(argc == 2, "usage: meepcoin-alt-storage-test NEW_DIRECTORY");
    require(!boost::filesystem::exists(argv[1]), "output exists");
    boost::filesystem::create_directories(argv[1]);
    count_case(argv[1]); byte_case(argv[1]); no_room_case(argv[1]); winning_boundary_case(argv[1]);
    failed_winner_case(argv[1], false); failed_winner_case(argv[1], true); atomic_eviction_case(argv[1]);
    invalid_identity_case(argv[1]);
    std::cout << "{\"status\":\"REAL_LMDB_ALT_STORAGE_PASS\",\"mockDatabase\":false,\"mockPow\":false}" << std::endl;
    return 0;
  } catch (const std::exception& e) { std::cerr << "ALT STORAGE FAIL: " << e.what() << std::endl; return 1; }
}
