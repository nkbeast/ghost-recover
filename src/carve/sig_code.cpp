// GHOST RECOVER — carver signature specs and validators for Source and config.
//
// Part of the per-category split of the former monolithic signatures.cpp.
// Shared plumbing (mk, withConfirm, cross-category validators) lives in
// sig_common.h / sig_common.cpp; the registry aggregator is signatures.cpp.
#include "ghost/carve.h"
#include "ghost/util.h"
#include "sig_common.h"

#include <algorithm>
#include <cstring>

namespace ghost {



void registerCode(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("JSON", "json", "code", S("{\""), 64*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("SHEBANG_SH", "sh", "code", S("#!/bin/sh"), 8*MB, SizeMode::Text, vText);
      c.min_size = 16; add(c); }
    { auto c = mk("SHEBANG_BASH", "sh", "code", S("#!/bin/bash"), 8*MB, SizeMode::Text, vText);
      c.min_size = 16; add(c); }
    { auto c = mk("SHEBANG_ENV", "sh", "code", S("#!/usr/bin/env "), 8*MB, SizeMode::Text, vText);
      c.min_size = 16; add(c); }
    { auto c = mk("PYTHON", "py", "code", S("import "), 8*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("PYTHON_DEF", "py", "code", S("def "), 8*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("C_INCLUDE", "c", "code", S("#include "), 8*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("C_IFNDEF", "h", "code", S("#ifndef "), 8*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("GO", "go", "code", S("package main"), 8*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("JAVA", "java", "code", S("package "), 8*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("PHP", "php", "code", S("<?php"), 8*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("RUST", "rs", "code", S("fn main("), 8*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("SQL", "sql", "code", S("CREATE TABLE"), 64*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("SQL_DUMP", "sql", "code", S("-- MySQL dump"), 512*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("DOCKERFILE", "dockerfile", "code", S("FROM "), 1*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("YAML_DOC", "yaml", "code", S("---\n"), 8*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("TOML", "toml", "code", S("[package]"), 4*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("INI_UNIT", "service", "code", S("[Unit]\n"), 1*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("GIT_CONFIG", "gitconfig", "code", S("[core]\n"), 1*MB, SizeMode::Text, vText);
      c.min_size = 16; add(c); }
    { auto c = mk("CMAKE", "cmake", "code", S("cmake_minimum_required"), 4*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("CSV_HEADER", "csv", "code", S("id,name,"), 512*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("VCARD", "vcf", "code", S("BEGIN:VCARD"), 16*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("ICAL", "ics", "code", S("BEGIN:VCALENDAR"), 16*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("GPX", "gpx", "code", S("<gpx "), 64*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("KML", "kml", "code", S("<kml "), 64*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
}

}  // namespace ghost
