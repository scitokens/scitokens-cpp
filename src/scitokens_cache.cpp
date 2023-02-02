
#include <cstdint>
#include <memory>
#include <string>

#include <pwd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PICOJSON_USE_INT64
#define PICOJSON_USE_INT64
#endif
#include <picojson/picojson.h>
#include <sqlite3.h>

#include "scitokens_internal.h"

namespace {

void initialize_cachedb(const std::string &keycache_file) {

    sqlite3 *db;
    int rc = sqlite3_open(keycache_file.c_str(), &db);
    if (rc != SQLITE_OK) {
        std::cerr << "SQLite key cache creation failed." << std::endl;
        sqlite3_close(db);
        return;
    }
    char *err_msg = nullptr;
    rc = sqlite3_exec(db,
                      "CREATE TABLE IF NOT EXISTS keycache ("
                      "issuer text UNIQUE PRIMARY KEY NOT NULL,"
                      "keys text NOT NULL)",
                      NULL, 0, &err_msg);
    if (rc) {
        std::cerr << "Sqlite table creation failed: " << err_msg << std::endl;
        sqlite3_free(err_msg);
    }
    sqlite3_close(db);
}

/**
 * Get the Cache file location
 *
 *  1. $XDG_CACHE_HOME
 *  2. .cache subdirectory of home directory as returned by the password
 * database
 */
std::string get_cache_file() {

    const char *xdg_cache_home = getenv("XDG_CACHE_HOME");

    auto bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    bufsize = (bufsize == -1) ? 16384 : bufsize;

    std::unique_ptr<char[]> buf(new char[bufsize]);

    std::string home_dir;
    struct passwd pwd, *result = NULL;
    getpwuid_r(geteuid(), &pwd, buf.get(), bufsize, &result);
    if (result && result->pw_dir) {
        home_dir = result->pw_dir;
        home_dir += "/.cache";
    }

    std::string cache_dir(xdg_cache_home ? xdg_cache_home : home_dir.c_str());
    if (cache_dir.size() == 0) {
        return "";
    }

    int r = mkdir(cache_dir.c_str(), 0700);
    if ((r < 0) && errno != EEXIST) {
        return "";
    }

    std::string keycache_dir = cache_dir + "/scitokens";
    r = mkdir(keycache_dir.c_str(), 0700);
    if ((r < 0) && errno != EEXIST) {
        return "";
    }

    std::string keycache_file = keycache_dir + "/scitokens_cpp.sqllite";
    initialize_cachedb(keycache_file);

    return keycache_file;
}

void remove_issuer_entry(sqlite3 *db, const std::string &issuer,
                         bool new_transaction) {

    if (new_transaction)
        sqlite3_exec(db, "BEGIN", 0, 0, 0);

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, "DELETE FROM keycache WHERE issuer = ?", -1,
                                &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return;
    }

    if (sqlite3_bind_text(stmt, 1, issuer.c_str(), issuer.size(),
                          SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return;
    }

    sqlite3_finalize(stmt);

    if (new_transaction)
        sqlite3_exec(db, "COMMIT", 0, 0, 0);
}

} // namespace

bool scitokens::Validator::get_public_keys_from_db(const std::string issuer,
                                                   int64_t now,
                                                   picojson::value &keys,
                                                   int64_t &next_update) {
    auto cache_fname = get_cache_file();
    if (cache_fname.size() == 0) {
        return false;
    }

    sqlite3 *db;
    int rc = sqlite3_open(cache_fname.c_str(), &db);
    if (rc) {
        sqlite3_close(db);
        return false;
    }

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "SELECT keys from keycache where issuer = ?",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }

    if (sqlite3_bind_text(stmt, 1, issuer.c_str(), issuer.size(),
                          SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const unsigned char *data = sqlite3_column_text(stmt, 0);
        std::string metadata(reinterpret_cast<const char *>(data));
        sqlite3_finalize(stmt);
        picojson::value json_obj;
        auto err = picojson::parse(json_obj, metadata);
        if (!err.empty() || !json_obj.is<picojson::object>()) {
            remove_issuer_entry(db, issuer, true);
            sqlite3_close(db);
            return false;
        }
        auto top_obj = json_obj.get<picojson::object>();
        auto iter = top_obj.find("jwks");
        if (iter == top_obj.end() || !iter->second.is<picojson::object>()) {
            remove_issuer_entry(db, issuer, true);
            sqlite3_close(db);
            return false;
        }
        auto keys_local = iter->second;
        iter = top_obj.find("expires");
        if (iter == top_obj.end() || !iter->second.is<int64_t>()) {
            remove_issuer_entry(db, issuer, true);
            sqlite3_close(db);
            return false;
        }
        auto expiry = iter->second.get<int64_t>();
        if (now > expiry) {
            remove_issuer_entry(db, issuer, true);
            sqlite3_close(db);
            return false;
        }
        sqlite3_close(db);
        iter = top_obj.find("next_update");
        if (iter == top_obj.end() || !iter->second.is<int64_t>()) {
            next_update = expiry - 4 * 3600;
        } else {
            next_update = iter->second.get<int64_t>();
        }
        keys = keys_local;
        return true;
    } else if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    } else {
        // TODO: log error?
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
}

bool scitokens::Validator::store_public_keys(const std::string &issuer,
                                             const picojson::value &keys,
                                             int64_t next_update,
                                             int64_t expires) {
    picojson::object top_obj;
    top_obj["jwks"] = keys;
    top_obj["next_update"] = picojson::value(next_update);
    top_obj["expires"] = picojson::value(expires);
    picojson::value db_value(top_obj);
    std::string db_str = db_value.serialize();

    auto cache_fname = get_cache_file();
    if (cache_fname.size() == 0) {
        return false;
    }

    sqlite3 *db;
    int rc = sqlite3_open(cache_fname.c_str(), &db);
    if (rc) {
        sqlite3_close(db);
        return false;
    }

    sqlite3_exec(db, "BEGIN", 0, 0, 0);

    remove_issuer_entry(db, issuer, false);

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "INSERT INTO keycache VALUES (?, ?)", -1, &stmt,
                            NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }

    if (sqlite3_bind_text(stmt, 1, issuer.c_str(), issuer.size(),
                          SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    if (sqlite3_bind_text(stmt, 2, db_str.c_str(), db_str.size(),
                          SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    sqlite3_exec(db, "COMMIT", 0, 0, 0);

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return true;
}
