// Minimal recursive-descent JSON reader for the test-vector subset (objects, arrays, strings,
// integers, booleans, null). Purpose-built to avoid an external dependency; strict enough to
// reject malformed structure. Wide values are hex strings validated by hex_util (spec §11).
#ifndef MEEPOW_JSON_MINI_HPP
#define MEEPOW_JSON_MINI_HPP

#include <cstdint>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace meepow_test {

struct JsonValue {
    enum Type { Null, Bool, Int, Str, Arr, Obj } type = Null;
    bool b = false;
    int64_t i = 0;
    std::string s;
    std::vector<JsonValue> arr;
    std::map<std::string, JsonValue> obj;

    const JsonValue& at(const std::string& k) const {
        auto it = obj.find(k);
        if (it == obj.end()) throw std::runtime_error("json: missing key '" + k + "'");
        return it->second;
    }
    const std::string& as_str() const {
        if (type != Str) throw std::runtime_error("json: expected string");
        return s;
    }
    bool as_bool() const {
        if (type != Bool) throw std::runtime_error("json: expected bool");
        return b;
    }
    int64_t as_int() const {
        if (type != Int) throw std::runtime_error("json: expected int");
        return i;
    }
};

class JsonParser {
   public:
    explicit JsonParser(const std::string& text) : t_(text), p_(0) {}
    JsonValue parse() {
        JsonValue v = value();
        skip_ws();
        if (p_ != t_.size()) throw std::runtime_error("json: trailing data");
        return v;
    }

   private:
    const std::string& t_;
    size_t p_;

    void skip_ws() {
        while (p_ < t_.size()) {
            char c = t_[p_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
                ++p_;
            else
                break;
        }
    }
    char peek() {
        skip_ws();
        if (p_ >= t_.size()) throw std::runtime_error("json: unexpected end");
        return t_[p_];
    }
    void expect(char c) {
        if (peek() != c) throw std::runtime_error(std::string("json: expected '") + c + "'");
        ++p_;
    }

    JsonValue value() {
        char c = peek();
        if (c == '{') return object();
        if (c == '[') return array();
        if (c == '"') return string_val();
        if (c == 't' || c == 'f') return bool_val();
        if (c == 'n') { literal("null"); return JsonValue(); }
        return int_val();
    }
    void literal(const char* lit) {
        for (const char* q = lit; *q; ++q) {
            if (p_ >= t_.size() || t_[p_] != *q) throw std::runtime_error("json: bad literal");
            ++p_;
        }
    }
    JsonValue bool_val() {
        JsonValue v;
        v.type = JsonValue::Bool;
        if (peek() == 't') { literal("true"); v.b = true; }
        else { literal("false"); v.b = false; }
        return v;
    }
    JsonValue int_val() {
        skip_ws();
        size_t start = p_;
        if (p_ < t_.size() && (t_[p_] == '-' || t_[p_] == '+')) ++p_;
        bool any = false;
        while (p_ < t_.size() && t_[p_] >= '0' && t_[p_] <= '9') { ++p_; any = true; }
        if (!any) throw std::runtime_error("json: invalid value");
        JsonValue v;
        v.type = JsonValue::Int;
        v.i = std::stoll(t_.substr(start, p_ - start));
        return v;
    }
    JsonValue string_val() {
        expect('"');
        std::string out;
        while (p_ < t_.size()) {
            char c = t_[p_++];
            if (c == '"') {
                JsonValue v;
                v.type = JsonValue::Str;
                v.s = out;
                return v;
            }
            if (c == '\\') {
                if (p_ >= t_.size()) break;
                char e = t_[p_++];
                switch (e) {
                    case '"': out += '"'; break;
                    case '\\': out += '\\'; break;
                    case '/': out += '/'; break;
                    case 'n': out += '\n'; break;
                    case 't': out += '\t'; break;
                    case 'r': out += '\r'; break;
                    default: throw std::runtime_error("json: unsupported escape");
                }
            } else {
                out += c;
            }
        }
        throw std::runtime_error("json: unterminated string");
    }
    JsonValue array() {
        expect('[');
        JsonValue v;
        v.type = JsonValue::Arr;
        if (peek() == ']') { ++p_; return v; }
        while (true) {
            v.arr.push_back(value());
            char c = peek();
            if (c == ',') { ++p_; continue; }
            if (c == ']') { ++p_; break; }
            throw std::runtime_error("json: expected ',' or ']'");
        }
        return v;
    }
    JsonValue object() {
        expect('{');
        JsonValue v;
        v.type = JsonValue::Obj;
        if (peek() == '}') { ++p_; return v; }
        while (true) {
            std::string key = string_val().s;
            expect(':');
            v.obj[key] = value();
            char c = peek();
            if (c == ',') { ++p_; continue; }
            if (c == '}') { ++p_; break; }
            throw std::runtime_error("json: expected ',' or '}'");
        }
        return v;
    }
};

inline JsonValue json_parse(const std::string& text) { return JsonParser(text).parse(); }

}  // namespace meepow_test

#endif  // MEEPOW_JSON_MINI_HPP
