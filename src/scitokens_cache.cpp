
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

// Remove issuer_entry function and other namespace functions remain here
// Remove a given issuer from the database.  Starts a new transaction
// if `new_transaction` is true.
// If a failure occurs, then this function returns nonzero and closes
// the database handle.
int remove_issuer_entry(sqlite3 *db, const std::string &issuer,
                        bool new_transaction) {

    int rc;
    if (new_transaction) {
        if ((rc = sqlite3_exec(db, "BEGIN", 0, 0, 0)) != SQLITE_OK) {
            sqlite3_close(db);
            return -1;
        }
    }

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "DELETE FROM keycache WHERE issuer = ?", -1,
                            &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }

    if (sqlite3_bind_text(stmt, 1, issuer.c_str(), issuer.size(),
                          SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }

    sqlite3_finalize(stmt);

    if (new_transaction) {
        if ((rc = sqlite3_exec(db, "COMMIT", 0, 0, 0)) != SQLITE_OK) {
            sqlite3_close(db);
            return -1;
        }
    }

    return 0;
}

} // namespace

/**
 * @brief Determines the location of the SciTokens key cache file.
 *
 * This function checks environment variables and configuration settings to find
 * the appropriate directory for the key cache file. It prioritizes the following:
 *   1. SCITOKENS_KEYCACHE_FILE environment variable (direct file path).
 *   2. Configured cache directory via Configuration::get_cache_home().
 *   3. XDG_CACHE_HOME environment variable.
 *   4. Default to $HOME/.cache if none of the above are set.
 *
 * The function ensures the cache directory exists, creates it if necessary,
 * initializes the SQLite database if needed, and returns the full path to the
 * cache file. Returns an empty string on failure.
 *
 * @return std::string Full path to the key cache file, or empty string on error.
 */
std::string scitokens::get_cache_file() {
    // Check for direct cache file location first (offline support)
    const char *direct_cache_file = getenv("SCITOKENS_KEYCACHE_FILE");
    if (direct_cache_file && strlen(direct_cache_file) > 0) {
        std::string keycache_file(direct_cache_file);
        initialize_cachedb(keycache_file);
        return keycache_file;
    }

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

    // Figure out where to plop the cache based on priority
    std::string cache_dir;
    std::string configured_cache_dir =
        configurer::Configuration::get_cache_home();
    if (configured_cache_dir.length() > 0) { // The variable has been configured
        cache_dir = configured_cache_dir;
    } else {
        cache_dir = xdg_cache_home ? xdg_cache_home : home_dir.c_str();
    }

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
            if (remove_issuer_entry(db, issuer, true) != 0) {
                return false;
            }
            sqlite3_close(db);
            return false;
        }
        auto top_obj = json_obj.get<picojson::object>();
        auto iter = top_obj.find("jwks");
        if (iter == top_obj.end() || !iter->second.is<picojson::object>()) {
            if (remove_issuer_entry(db, issuer, true) != 0) {
                return false;
            }
            sqlite3_close(db);
            return false;
        }
        auto keys_local = iter->second;
        iter = top_obj.find("expires");
        if (iter == top_obj.end() || !iter->second.is<int64_t>()) {
            if (remove_issuer_entry(db, issuer, true) != 0) {
                return false;
            }
            sqlite3_close(db);
            return false;
        }
        auto expiry = iter->second.get<int64_t>();
        if (now > expiry) {
            if (remove_issuer_entry(db, issuer, true) != 0) {
                return false;
            }
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

    if ((rc = sqlite3_exec(db, "BEGIN", 0, 0, 0)) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }

    if (remove_issuer_entry(db, issuer, false) != 0) {
        return false;
    }

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
    sqlite3_finalize(stmt);

    if (sqlite3_exec(db, "COMMIT", 0, 0, 0) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }

    sqlite3_close(db);
    return true;
}
