//
// revocation_db.cpp — flat text 形式の失効 DB を読み書き。
//
#include "revocation_db.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include "error.hpp"

namespace tee_anchor::ca {

namespace {

std::string trim(const std::string& s) {
    auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

}  // namespace

std::string default_db_path(const std::string& ca_cert_path) {
    std::filesystem::path p(ca_cert_path);
    auto parent = p.parent_path();
    if (parent.empty()) parent = std::filesystem::path(".");
    return (parent / "revocations.txt").string();
}

RevocationDb load_revocation_db(const std::string& path) {
    RevocationDb db;

    std::ifstream f(path);
    if (!f) return db;  // 未作成 = 空 DB として扱う

    std::string line;
    size_t lineno = 0;
    while (std::getline(f, line)) {
        ++lineno;
        std::string s = trim(line);
        if (s.empty() || s[0] == '#') continue;

        // crl-number ヘッダ
        if (s.rfind("crl-number", 0) == 0) {
            std::istringstream iss(s);
            std::string tag;
            uint64_t n = 0;
            iss >> tag >> n;
            if (!iss && !iss.eof()) {
                throw TeeAnchorError(path + ":" + std::to_string(lineno) +
                                     ": invalid 'crl-number' line");
            }
            db.crl_number = n;
            continue;
        }

        // 通常エントリ: <serial> <date> [<reason>]
        RevocationEntry e;
        std::istringstream iss(s);
        if (!(iss >> e.serial_hex >> e.revocation_date)) {
            throw TeeAnchorError(path + ":" + std::to_string(lineno) +
                                 ": expected '<serial> <date> [<reason>]'");
        }
        // 残りを reason として吸収 (trim)
        std::string rest;
        std::getline(iss, rest);
        e.reason = trim(rest);

        // serial は小文字 hex に正規化
        std::transform(e.serial_hex.begin(), e.serial_hex.end(),
                       e.serial_hex.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        db.entries.push_back(std::move(e));
    }
    return db;
}

void save_revocation_db(const std::string& path, const RevocationDb& db) {
    const std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp);
        if (!f) throw TeeAnchorError("cannot open for writing: " + tmp);
        f << "# TEE Anchor revocation database (v1)\n";
        f << "# format: <serial-hex> <YYYYMMDDHHMMSSZ> [<reason>]\n";
        f << "crl-number " << db.crl_number << "\n";
        for (const auto& e : db.entries) {
            f << e.serial_hex << " " << e.revocation_date;
            if (!e.reason.empty()) f << " " << e.reason;
            f << "\n";
        }
        if (!f) throw TeeAnchorError("write failed: " + tmp);
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        throw TeeAnchorError("rename failed: " + tmp + " -> " + path);
    }
}

}  // namespace tee_anchor::ca
