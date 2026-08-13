// GHOST RECOVER — JSON writer and parser.
//
// The previous engine built JSON by hand with ostringstream and pulled request
// fields out with a substring search, which mis-parsed any body where a key
// name also appeared inside a string value and emitted unbalanced braces on
// some error paths. Both directions are now real implementations.
#pragma once

#include "ghost/types.h"

namespace ghost {
namespace json {

// ---------------------------------------------------------------------------
// Writer — tracks container nesting so commas and closing braces are always
// correct regardless of which branches the caller takes.
// ---------------------------------------------------------------------------
class Writer {
public:
    Writer() { out_.reserve(4096); }

    Writer& beginObject();
    Writer& endObject();
    Writer& beginArray();
    Writer& endArray();

    Writer& key(const std::string& k);

    Writer& value(const std::string& s);
    Writer& value(const char* s) { return value(std::string(s ? s : "")); }
    Writer& value(i64 v);
    Writer& value(int v) { return value((i64)v); }
    Writer& value(u64 v);
    Writer& value(double v);
    Writer& value(bool v);
    Writer& null();
    Writer& raw(const std::string& jsonFragment);

    // key + value shorthand
    template <typename T> Writer& kv(const std::string& k, const T& v) { key(k); return value(v); }
    Writer& kv(const std::string& k, const char* v) { key(k); return value(std::string(v ? v : "")); }

    // Close every open container. Called before str() so a partially built
    // document is still parseable.
    Writer& finish();

    const std::string& str() { finish(); return out_; }

private:
    void comma();
    std::string       out_;
    std::vector<char> stack_;      // 'o' object, 'a' array
    bool              need_comma_ = false;
    bool              want_value_ = false;   // a key was just written
};

std::string escape(const std::string& s);

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------
struct Value {
    enum class Type { Null, Bool, Number, String, Array, Object };

    Type        type = Type::Null;
    bool        b    = false;
    double      num  = 0;
    std::string s;
    std::vector<Value>                   arr;
    std::vector<std::pair<std::string, Value>> obj;

    bool isNull()   const { return type == Type::Null; }
    bool isObject() const { return type == Type::Object; }
    bool isArray()  const { return type == Type::Array; }

    const Value* find(const std::string& k) const;

    std::string getStr (const std::string& k, const std::string& def = "") const;
    i64         getInt (const std::string& k, i64 def = 0) const;
    double      getNum (const std::string& k, double def = 0) const;
    bool        getBool(const std::string& k, bool def = false) const;
    const Value* getArray(const std::string& k) const;

    std::string asStr() const;
    i64         asInt() const;
};

// Returns a Null value when the text is not valid JSON.
Value parse(const std::string& text);

}  // namespace json
}  // namespace ghost
