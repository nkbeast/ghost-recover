#include "ghost/json.h"

#include <climits>
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace ghost {
namespace json {

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

std::string escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (size_t i = 0; i < s.size(); i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            case '\b': o += "\\b";  break;
            case '\f': o += "\\f";  break;
            default:
                if (c < 0x20 || c == 0x7F) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    o += buf;
                } else if (c < 0x80) {
                    o += (char)c;
                } else {
                    // Filenames recovered from a damaged volume are frequently
                    // not valid UTF-8. Emit well-formed sequences as-is and
                    // escape anything else so the document still parses.
                    int extra = (c >= 0xF0) ? 3 : (c >= 0xE0) ? 2 : (c >= 0xC0) ? 1 : -1;
                    bool ok = extra > 0 && i + (size_t)extra < s.size();
                    for (int k = 1; ok && k <= extra; k++)
                        if (((unsigned char)s[i + k] & 0xC0) != 0x80) ok = false;
                    if (ok) {
                        o.append(s, i, (size_t)extra + 1);
                        i += (size_t)extra;
                    } else {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04x", 0xFFFD);
                        o += buf;
                    }
                }
        }
    }
    return o;
}

void Writer::comma() {
    if (want_value_) { want_value_ = false; return; }
    if (need_comma_) out_ += ',';
    need_comma_ = true;
}

Writer& Writer::beginObject() { comma(); out_ += '{'; stack_.push_back('o'); need_comma_ = false; return *this; }
Writer& Writer::beginArray()  { comma(); out_ += '['; stack_.push_back('a'); need_comma_ = false; return *this; }

Writer& Writer::endObject() {
    if (!stack_.empty() && stack_.back() == 'o') { stack_.pop_back(); out_ += '}'; need_comma_ = true; }
    return *this;
}
Writer& Writer::endArray() {
    if (!stack_.empty() && stack_.back() == 'a') { stack_.pop_back(); out_ += ']'; need_comma_ = true; }
    return *this;
}

Writer& Writer::key(const std::string& k) {
    comma();
    out_ += '"';
    out_ += escape(k);
    out_ += "\":";
    want_value_ = true;
    return *this;
}

Writer& Writer::value(const std::string& s) { comma(); out_ += '"'; out_ += escape(s); out_ += '"'; return *this; }
Writer& Writer::value(i64 v)  { comma(); out_ += std::to_string(v); return *this; }
Writer& Writer::value(u64 v)  { comma(); out_ += std::to_string(v); return *this; }
Writer& Writer::value(bool v) { comma(); out_ += (v ? "true" : "false"); return *this; }
Writer& Writer::null()        { comma(); out_ += "null"; return *this; }
Writer& Writer::raw(const std::string& f) { comma(); out_ += f; return *this; }

Writer& Writer::value(double v) {
    comma();
    if (!std::isfinite(v)) { out_ += '0'; return *this; }
    char buf[40];
    snprintf(buf, sizeof(buf), "%.6g", v);
    out_ += buf;
    return *this;
}

Writer& Writer::finish() {
    if (want_value_) { out_ += "null"; want_value_ = false; need_comma_ = true; }
    while (!stack_.empty()) {
        char c = stack_.back();
        stack_.pop_back();
        out_ += (c == 'o' ? '}' : ']');
    }
    return *this;
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------
namespace {

struct P {
    const std::string& s;
    size_t i = 0;
    int depth = 0;
    bool bad = false;

    explicit P(const std::string& in) : s(in) {}

    void ws() {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++;
    }
    bool eof() const { return i >= s.size(); }
    char peek() const { return i < s.size() ? s[i] : '\0'; }

    void utf8(std::string& out, unsigned cp) {
        if (cp < 0x80) { out += (char)cp; }
        else if (cp < 0x800) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) {
            out += (char)(0xE0 | (cp >> 12));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        } else {
            out += (char)(0xF0 | (cp >> 18));
            out += (char)(0x80 | ((cp >> 12) & 0x3F));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        }
    }

    unsigned hex4() {
        unsigned v = 0;
        for (int k = 0; k < 4 && i < s.size(); k++, i++) {
            char c = s[i];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
            else { bad = true; return 0; }
        }
        return v;
    }

    std::string string() {
        std::string out;
        if (peek() != '"') { bad = true; return out; }
        i++;
        while (i < s.size()) {
            char c = s[i++];
            if (c == '"') return out;
            if (c != '\\') { out += c; continue; }
            if (i >= s.size()) break;
            char e = s[i++];
            switch (e) {
                case '"':  out += '"';  break;
                case '\\': out += '\\'; break;
                case '/':  out += '/';  break;
                case 'n':  out += '\n'; break;
                case 'r':  out += '\r'; break;
                case 't':  out += '\t'; break;
                case 'b':  out += '\b'; break;
                case 'f':  out += '\f'; break;
                case 'u': {
                    unsigned cp = hex4();
                    if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < s.size() && s[i] == '\\' && s[i+1] == 'u') {
                        i += 2;
                        unsigned lo = hex4();
                        if (lo >= 0xDC00 && lo <= 0xDFFF)
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        else
                            cp = 0xFFFD;   // unpaired high surrogate
                    } else if (cp >= 0xD800 && cp <= 0xDFFF) {
                        cp = 0xFFFD;       // unpaired low surrogate
                    }
                    utf8(out, cp);
                    break;
                }
                default: out += e;
            }
        }
        bad = true;
        return out;
    }

    Value value() {
        Value v;
        if (++depth > 64) { bad = true; return v; }   // reject pathological nesting
        ws();
        if (eof()) { bad = true; depth--; return v; }
        char c = peek();
        if (c == '{') {
            i++;
            v.type = Value::Type::Object;
            ws();
            if (peek() == '}') { i++; depth--; return v; }
            while (!eof() && !bad) {
                ws();
                std::string k = string();
                ws();
                if (peek() != ':') { bad = true; break; }
                i++;
                v.obj.emplace_back(k, value());
                ws();
                if (peek() == ',') { i++; continue; }
                if (peek() == '}') { i++; break; }
                bad = true;
                break;
            }
        } else if (c == '[') {
            i++;
            v.type = Value::Type::Array;
            ws();
            if (peek() == ']') { i++; depth--; return v; }
            while (!eof() && !bad) {
                v.arr.push_back(value());
                ws();
                if (peek() == ',') { i++; continue; }
                if (peek() == ']') { i++; break; }
                bad = true;
                break;
            }
        } else if (c == '"') {
            v.type = Value::Type::String;
            v.s = string();
        } else if (s.compare(i, 4, "true") == 0) {
            i += 4; v.type = Value::Type::Bool; v.b = true;
        } else if (s.compare(i, 5, "false") == 0) {
            i += 5; v.type = Value::Type::Bool; v.b = false;
        } else if (s.compare(i, 4, "null") == 0) {
            i += 4; v.type = Value::Type::Null;
        } else {
            size_t start = i;
            if (peek() == '-' || peek() == '+') i++;
            while (i < s.size() && (isdigit((unsigned char)s[i]) || s[i] == '.' || s[i] == 'e' ||
                                    s[i] == 'E' || s[i] == '+' || s[i] == '-'))
                i++;
            if (i == start) { bad = true; depth--; return v; }
            // A 64 MiB payload of digits would allocate a 64 MiB substring
            // and make strtod scan it — cap the token to avoid DoS.
            if (i - start > 65536) { bad = true; depth--; return v; }
            v.type = Value::Type::Number;
            v.num  = strtod(s.substr(start, i - start).c_str(), nullptr);
        }
        depth--;
        return v;
    }
};

}  // namespace

Value parse(const std::string& text) {
    if (text.empty()) return {};
    P p(text);
    Value v = p.value();
    if (p.bad) return {};
    return v;
}

const Value* Value::find(const std::string& k) const {
    if (type != Type::Object) return nullptr;
    for (const auto& kv : obj)
        if (kv.first == k) return &kv.second;
    return nullptr;
}

std::string Value::asStr() const {
    switch (type) {
        case Type::String: return s;
        case Type::Number: {
            // Casting a double beyond int64's range to i64 is undefined
            // behaviour; only take the integer path when it actually fits.
            if (num >= -9.2233720368547758e18 && num <= 9.2233720368547758e18 &&
                num == (double)(i64)num)
                return std::to_string((i64)num);
            char tmp[40];
            snprintf(tmp, sizeof(tmp), "%.6g", num);
            return tmp;
        }
        case Type::Bool: return b ? "true" : "false";
        default: return {};
    }
}

i64 Value::asInt() const {
    switch (type) {
        case Type::Number:
            // Casting a double outside int64's range (or NaN) to i64 is
            // undefined behaviour; clamp first instead.
            if (num != num) return 0;                                  // NaN
            if (num >= 9.2233720368547757e18) return INT64_MAX;
            if (num <= -9.2233720368547758e18) return INT64_MIN;
            return (i64)num;
        case Type::Bool:   return b ? 1 : 0;
        case Type::String: {
            try { return std::stoll(s); } catch (...) { return 0; }
        }
        default: return 0;
    }
}

std::string Value::getStr(const std::string& k, const std::string& def) const {
    const Value* v = find(k);
    if (!v || v->type == Type::Null) return def;
    return v->asStr();
}

i64 Value::getInt(const std::string& k, i64 def) const {
    const Value* v = find(k);
    if (!v || v->type == Type::Null) return def;
    return v->asInt();
}

double Value::getNum(const std::string& k, double def) const {
    const Value* v = find(k);
    if (!v || v->type != Type::Number) return def;
    return v->num;
}

bool Value::getBool(const std::string& k, bool def) const {
    const Value* v = find(k);
    if (!v) return def;
    if (v->type == Type::Bool) return v->b;
    if (v->type == Type::Number) return v->num != 0;
    if (v->type == Type::String) return v->s == "true" || v->s == "1";
    return def;
}

const Value* Value::getArray(const std::string& k) const {
    const Value* v = find(k);
    return (v && v->type == Type::Array) ? v : nullptr;
}

}  // namespace json
}  // namespace ghost
