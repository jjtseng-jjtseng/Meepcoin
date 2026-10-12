// Real Blockchain/LMDB acceptance; time() alone is wrapped for exact clock-boundary replay.
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/meepcoin_asert.h"
#include "common/util.h"
#include "misc_language.h"
#include <boost/filesystem.hpp>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <ctime>
using namespace cryptonote;
static time_t fixture_clock=1791806400;
extern "C" time_t __wrap_time(time_t* result){if(result)*result=fixture_clock;return fixture_clock;}
static void require(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
struct Node {
 tx_memory_pool pool;Blockchain chain;BlockchainLMDB* db;
 Node(const std::string& path,uint8_t version):pool(chain),chain(pool){
  const std::pair<uint8_t,uint64_t> schedule[]={{16,0},{version,1},{0,0}};const test_options opts{schedule,0};
  auto owned=std::unique_ptr<BlockchainLMDB>(new BlockchainLMDB);owned->open(path);db=owned.release();
  require(chain.init(db,FAKECHAIN,true,&opts,0),"chain init");require(pool.init(),"pool init");
 }
 ~Node(){pool.deinit();}
};
struct Verdict {bool accepted;block_verification_context context;};
static Verdict submit(Node& n,const block& b){
 block_complete_entry entry{};entry.block=block_to_blob(b);std::vector<block> parsed;
 bool prepared=n.chain.prepare_handle_incoming_blocks({entry},parsed);Verdict v{false,{}};
 try{require(prepared,"prepare");v.accepted=n.chain.add_new_block(b,v.context);}
 catch(...){n.chain.cleanup_handle_incoming_blocks();throw;}
 require(n.chain.cleanup_handle_incoming_blocks(),"cleanup");return v;
}
static void accepted(Verdict v){require(v.accepted&&!v.context.m_verifivation_failed,"valid block rejected");}
static difficulty_type query(Node& n){db_rtxn_guard tx(n.db);return n.chain.get_difficulty_for_next_block();}
static void record(Node& n){
 db_rtxn_guard tx(n.db);auto h=n.db->height()-1;auto t=n.db->get_block_timestamp(h);auto g=n.db->get_block_timestamp(0);auto d=query(n);
 require(d==meepcoin_asert_difficulty(h,t,g),"caller/header mismatch");
 std::cout<<"{\"case\":\"native-next\",\"parentHeight\":"<<h<<",\"parentTime\":"<<t<<",\"genesisTime\":"<<g<<",\"difficulty\":\""<<d<<"\"}"<<std::endl;
}
static block make(Node& n,const account_public_address& address,uint64_t timestamp,const crypto::hash* from=nullptr,unsigned salt=0){
 block b{};difficulty_type difficulty;uint64_t height,reward,seedheight;crypto::hash seed;
 require(n.chain.create_block_template(b,from,address,difficulty,height,reward,blobdata(1,char(salt)),seedheight,seed),"template");
 require(b.major_version==17&&difficulty>=20&&difficulty<=1000,"template policy bound");b.timestamp=timestamp;
 for(b.nonce=0;b.nonce<30000;++b.nonce){b.invalidate_hashes();crypto::hash pow;require(get_block_longhash(&n.chain,b,pow,height,&seed),"PoW");if(check_hash(pow,difficulty)){
  std::cout<<"{\"case\":\"mined\",\"height\":"<<height<<",\"time\":"<<timestamp<<",\"difficulty\":\""<<difficulty<<"\",\"pow\":\""<<epee::string_tools::pod_to_hex(pow)<<"\"}"<<std::endl;return b;
 }}throw std::runtime_error("bounded nonce search exhausted");
}
static uint64_t median(Node& n){db_rtxn_guard tx(n.db);std::vector<uint64_t> values;const uint64_t count=n.db->height();for(uint64_t i=count>11?count-11:0;i<count;++i)values.push_back(n.db->get_block_timestamp(i));return epee::misc_utils::median(values);}
int main(int argc,char**argv){try{
 if(argc==2&&std::string(argv[1])=="arithmetic") { difficulty_type sum=7, max=std::numeric_limits<difficulty_type>::max(); require(meepcoin_add_chainwork(max-20,20,sum)&&sum==max,"chainwork exact maximum"); require(!meepcoin_add_chainwork(max-20,21,sum)&&sum==max,"chainwork overflow leaves output unchanged");uint64_t h,t,g;while(std::cin>>h>>t>>g)std::cout<<meepcoin_asert_difficulty(h,t,g)<<'\n';return 0;}
 require(argc==2,"usage: native-asert ROOT | arithmetic");const std::string root=argv[1];require(!boost::filesystem::exists(root),"new root required");boost::filesystem::create_directory(root);tools::set_max_concurrency(2);
 account_base account;account.generate();const auto address=account.get_keys().m_account_address;const uint64_t genesis_time=uint64_t(fixture_clock)-12000;crypto::hash tip;uint64_t finalheight;
 {
 Node a(root+"/a",17),b(root+"/b",17);block genesis=a.db->get_top_block();genesis.timestamp=genesis_time;genesis.major_version=16;genesis.minor_version=16;genesis.invalidate_hashes();
 require(a.chain.reset_and_set_genesis_block(genesis)&&b.chain.reset_and_set_genesis_block(genesis),"reset private genesis");record(a);
 for(uint64_t height=1;height<=64;++height){auto block=make(a,address,genesis_time+height*45);accepted(submit(a,block));accepted(submit(b,block));record(a);require(query(a)==query(b),"peer difficulty mismatch");}
 auto competing=make(b,address,genesis_time+65*45,nullptr,9);accepted(submit(b,competing));
 auto bad=make(a,address,median(a)-1,nullptr,1);auto prior=a.db->top_block_hash();auto prior_b=b.db->top_block_hash();
 auto va=submit(a,bad),vb=submit(b,bad);require(!va.accepted&&!vb.accepted&&va.context.m_verifivation_failed&&vb.context.m_verifivation_failed,"MAIN/ALT median-1 rejection");require(a.db->top_block_hash()==prior&&b.db->top_block_hash()==prior_b,"invalid block changed tip");
 auto equal=make(a,address,median(a),nullptr,2);accepted(submit(a,equal));accepted(submit(b,equal));record(a);
 std::cout<<"{\"case\":\"main-alt-median\",\"belowRejectedBoth\":true,\"equalAcceptedBoth\":true}"<<std::endl;
 auto future=make(a,address,uint64_t(fixture_clock)+121,nullptr,3);prior=a.db->top_block_hash();prior_b=b.db->top_block_hash();va=submit(a,future);vb=submit(b,future);
 require(!va.accepted&&!vb.accepted&&va.context.m_too_far_future&&vb.context.m_too_far_future&&a.db->top_block_hash()==prior&&b.db->top_block_hash()==prior_b,"future rejected both with temporary classification");++fixture_clock;
 accepted(submit(a,future));accepted(submit(b,future));require(a.db->top_block_hash()==b.db->top_block_hash(),"same-byte future retry convergence");record(a);
 std::cout<<"{\"case\":\"future-retry\",\"mainAltTooNewRejected\":true,\"sameBytesAtExact120Accepted\":true,\"invalidCacheDidNotPoisonRetry\":true}"<<std::endl;
 auto parent=a.db->get_block_hash_from_height(50);bool switched=false;unsigned branch=0;
 for(;branch<48;++branch){auto alt=make(a,address,genesis_time+(51+branch)*45+3,&parent,7);auto v=submit(a,alt);accepted(v);parent=get_block_hash(alt);record(a);if(v.context.m_added_to_main_chain){switched=true;break;}}
 require(switched&&a.db->top_block_hash()==parent,"higher-work reorg");require(a.chain.recalculate_difficulties(0)==0,"recalculation drift");
 auto replay=a.db->get_top_block();auto before=a.db->height();a.chain.pop_blocks(1);record(a);accepted(submit(a,replay));require(a.db->height()==before,"pop replay");record(a);
 tip=a.db->top_block_hash();finalheight=a.db->height();
 std::cout<<"{\"case\":\"native-lifecycle\",\"alternativeBlocks\":"<<branch+1<<",\"higherWorkReorg\":true,\"recalculationNoDrift\":true,\"popReplay\":true,\"finalHeight\":"<<finalheight<<",\"tip\":\""<<epee::string_tools::pod_to_hex(tip)<<"\"}"<<std::endl;
 }
 {Node reopened(root+"/a",17);require(reopened.db->height()==finalheight&&reopened.db->top_block_hash()==tip,"reopen");record(reopened);}
 std::cout<<"{\"status\":\"UNACTIVATED_V17_REAL_NATIVE_LIFECYCLE_PASS\",\"realLmdb\":true,\"validPow\":true,\"restart\":true,\"publicPolicyActivated\":false}"<<std::endl;return 0;
 }catch(const std::exception& e){std::cerr<<"native ASERT failed: "<<e.what()<<std::endl;return 1;}}
