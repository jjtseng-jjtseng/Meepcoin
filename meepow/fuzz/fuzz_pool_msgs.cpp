// libFuzzer target: strict pool client-message parsing must never crash on arbitrary bytes and
// must enforce its size/schema limits (pool/protocol/pool_message.hpp). Validation only — no
// networking, no server. See threat model T1 (server never trusts client-supplied hashes).
#include <cstddef>
#include <cstdint>

#include "pool_message.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    meppool::ParseResult r = meppool::parse_client_message(data, size);
    if (r.ok) {
        // Post-conditions the parser guarantees on success (checked, not assumed).
        if (r.type == meppool::MsgType::submit_share) {
            if (r.share.jobId.size() > meppool::MAX_ID_LEN) __builtin_trap();
            if (r.share.workerId.size() > meppool::MAX_ID_LEN) __builtin_trap();
        }
        if (r.type == meppool::MsgType::authorize_address &&
            r.address.size() > meppool::MAX_ADDR_LEN)
            __builtin_trap();
    }
    return 0;
}
