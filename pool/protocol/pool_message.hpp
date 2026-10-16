// Strict pool-message parser/validator (Phase 1A: schema + validation ONLY, no networking).
//
// Browsers cannot use raw-TCP Stratum, so the pool speaks a small JSON protocol over secure
// WebSockets (Phase 1B). This header defines strict validation of the untrusted CLIENT->SERVER
// messages so it can be fuzzed now, before the transport exists. It builds no server, socket,
// worker, Docker, or Firebase code. The server must still recompute every share (spec/threat T1);
// this validator only rejects malformed or oversized input early.
#ifndef MEEPPOOL_POOL_MESSAGE_HPP
#define MEEPPOOL_POOL_MESSAGE_HPP

#include <cstdint>
#include <string>

#include "json_mini.hpp"  // reused minimal JSON reader (meepow/tests)

namespace meppool {

// Hard limits (untrusted input). Enforced before and during parsing.
constexpr size_t MAX_MESSAGE_BYTES = 4096;
constexpr size_t MAX_ID_LEN = 64;       // jobId / workerId
constexpr size_t MAX_ADDR_LEN = 128;    // wallet address
constexpr size_t MAX_VERSION_LEN = 32;  // client version string
constexpr size_t MAX_HASH_HEX = 64;     // optional client-computed hash (32 bytes)

enum class MsgType {
    unknown,
    client_hello,
    authorize_address,
    submit_share,
    ping,
    pong,
    // server->client types are validated elsewhere; listed for completeness
    server_hello,
    job,
    set_difficulty,
    share_accepted,
    share_rejected,
    new_block,
    error,
};

struct SubmitShare {
    std::string jobId;
    uint32_t nonce = 0;
    std::string workerId;
    std::string clientVersion;   // optional
    std::string resultHashHex;   // optional; NEVER trusted, server recomputes
};

struct ParseResult {
    bool ok = false;
    MsgType type = MsgType::unknown;
    std::string error;           // set when !ok
    SubmitShare share;           // valid only when type == submit_share
    std::string address;         // valid only when type == authorize_address
};

namespace detail {

inline bool is_lower_hex(const std::string& s) {
    if (s.empty() || (s.size() % 2) != 0) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

// Wallet-address shape check only (format sanity, NOT ownership/validity — that is consensus).
inline bool plausible_address(const std::string& s) {
    if (s.empty() || s.size() > MAX_ADDR_LEN) return false;
    for (char c : s)
        if (!(std::isalnum((unsigned char)c))) return false;  // base58-ish charset, permissive
    return true;
}

inline const meepow_test::JsonValue* find(const meepow_test::JsonValue& o, const char* k) {
    auto it = o.obj.find(k);
    return it == o.obj.end() ? nullptr : &it->second;
}

}  // namespace detail

// Parse and strictly validate one CLIENT->SERVER message. Never throws; returns ok=false with a
// structured reason on any malformed, oversized, or schema-violating input.
inline ParseResult parse_client_message(const uint8_t* data, size_t len) {
    using namespace meepow_test;
    ParseResult r;
    if (data == nullptr && len != 0) { r.error = "null data"; return r; }
    if (len > MAX_MESSAGE_BYTES) { r.error = "message too large"; return r; }

    JsonValue root;
    try {
        root = json_parse(std::string(reinterpret_cast<const char*>(data), len));
    } catch (const std::exception& e) {
        r.error = std::string("json: ") + e.what();
        return r;
    }
    if (root.type != JsonValue::Obj) { r.error = "root not an object"; return r; }

    const JsonValue* typ = detail::find(root, "type");
    if (!typ || typ->type != JsonValue::Str) { r.error = "missing type"; return r; }
    const std::string& t = typ->s;

    auto req_str = [&](const char* k, size_t maxlen, std::string& out) -> bool {
        const JsonValue* v = detail::find(root, k);
        if (!v || v->type != JsonValue::Str) { r.error = std::string("missing/invalid ") + k; return false; }
        if (v->s.size() > maxlen) { r.error = std::string("oversized ") + k; return false; }
        out = v->s;
        return true;
    };

    if (t == "client_hello") {
        // Requires a protocolVersion integer >= 0.
        const JsonValue* pv = detail::find(root, "protocolVersion");
        if (!pv || pv->type != JsonValue::Int || pv->i < 0) { r.error = "bad protocolVersion"; return r; }
        r.ok = true; r.type = MsgType::client_hello; return r;
    }
    if (t == "authorize_address") {
        if (!req_str("address", MAX_ADDR_LEN, r.address)) return r;
        if (!detail::plausible_address(r.address)) { r.error = "address shape invalid"; return r; }
        r.ok = true; r.type = MsgType::authorize_address; return r;
    }
    if (t == "submit_share") {
        SubmitShare s;
        if (!req_str("jobId", MAX_ID_LEN, s.jobId)) return r;
        if (!req_str("workerId", MAX_ID_LEN, s.workerId)) return r;
        const JsonValue* n = detail::find(root, "nonce");
        if (!n || n->type != JsonValue::Str || n->s.size() != 8 || !detail::is_lower_hex(n->s)) {
            r.error = "nonce must be 8 lowercase hex chars"; return r;
        }
        s.nonce = (uint32_t)std::stoul(n->s, nullptr, 16);
        const JsonValue* cv = detail::find(root, "clientVersion");
        if (cv) {
            if (cv->type != JsonValue::Str || cv->s.size() > MAX_VERSION_LEN) { r.error = "bad clientVersion"; return r; }
            s.clientVersion = cv->s;
        }
        const JsonValue* rh = detail::find(root, "resultHash");  // optional, never trusted
        if (rh) {
            if (rh->type != JsonValue::Str || rh->s.size() > MAX_HASH_HEX || !detail::is_lower_hex(rh->s)) {
                r.error = "bad resultHash"; return r;
            }
            s.resultHashHex = rh->s;
        }
        r.ok = true; r.type = MsgType::submit_share; r.share = std::move(s); return r;
    }
    if (t == "ping") { r.ok = true; r.type = MsgType::ping; return r; }
    if (t == "pong") { r.ok = true; r.type = MsgType::pong; return r; }

    r.error = "unknown or non-client message type";
    return r;
}

}  // namespace meppool

#endif  // MEEPPOOL_POOL_MESSAGE_HPP
