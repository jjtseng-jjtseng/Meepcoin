// meepcoin-blockhashing — convert a full block blob into the block HASHING blob.
//
// Proof-of-work is computed over get_block_hashing_blob(), which is the block header plus the
// transaction merkle root plus the transaction count -- NOT the full serialized block returned by
// the get_block RPC. Confusing the two makes every valid block appear to fail its own PoW.
//
// Usage: meepcoin-blockhashing <full_block_blob_hex>
#include <cstdio>
#include <string>

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "string_tools.h"

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: %s <full_block_blob_hex>\n", argv[0]); return 2; }
    std::string blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(std::string(argv[1]), blob)) {
        std::fprintf(stderr, "bad hex\n"); return 2;
    }
    cryptonote::block b;
    if (!cryptonote::parse_and_validate_block_from_blob(blob, b)) {
        std::fprintf(stderr, "could not parse block\n"); return 1;
    }
    const cryptonote::blobdata hb = cryptonote::get_block_hashing_blob(b);
    std::printf("%s\n", epee::string_tools::buff_to_hex_nodelimer(hb).c_str());
    return 0;
}
