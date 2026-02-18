
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

// Timeout in milliseconds to wait when database is locked
// This handles concurrent access from multiple threads/processes
constexpr int SQLITE_BUSY_TIMEOUT_MS = 5000;

// Default time before expiry when next_update should occur (4 hours)
constexpr int64_t DEFAULT_NEXT_UPDATE_OFFSET_S = 4 * 3600;

// URI for the shared in-memory SQLite database used as fallback when
// the file-based keycache is not writable
const std::string IN_MEMORY_DB_URI =
    "file:scitokens_keycache?mode=memory&cache=shared";

// Persistent connection that keeps the shared in-memory database alive.
// Without this anchor, the database would be destroyed when the last
// connection is closed between cache operations.
sqlite3 *g_inmem_anchor = nullptr;

// Open a SQLite database, using URI mode so that shared in-memory
// databases are supported.
int open_cachedb(const std::string &db_path, sqlite3 **db) {
    return sqlite3_open_v2(db_path.c_str(), db,
                           SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                               SQLITE_OPEN_URI,
                           nullptr);
}

// Ensure the in-memory anchor connection is open and the table exists.
void ensure_inmem_anchor() {
    if (g_inmem_anchor) {
        return;
    }
    int rc = open_cachedb(IN_MEMORY_DB_URI, &g_inmem_anchor);
    if (rc != SQLITE_OK) {
        if (g_inmem_anchor) {
            sqlite3_close(g_inmem_anchor);
            g_inmem_anchor = nullptr;
        }
        return;
    }
    sqlite3_busy_timeout(g_inmem_anchor, SQLITE_BUSY_TIMEOUT_MS);
    char *err_msg = nullptr;
    rc = sqlite3_exec(g_inmem_anchor,
                      "CREATE TABLE IF NOT EXISTS keycache ("
                      "issuer text UNIQUE PRIMARY KEY NOT NULL,"
                      "keys text NOT NULL)",
                      NULL, 0, &err_msg);
    if (rc) {
        sqlite3_free(err_msg);
    }
}

void initialize_cachedb(const std::string &keycache_file) {

    sqlite3 *db;
    int rc = open_cachedb(keycache_file, &db);
    if (rc != SQLITE_OK) {
        std::cerr << "SQLite key cache creation failed." << std::endl;
        sqlite3_close(db);
        return;
    }
    // Set busy timeout to handle concurrent access
    sqlite3_busy_timeout(db, SQLITE_BUSY_TIMEOUT_MS);
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
 *  1. User-defined through config api
 *  2. $XDG_CACHE_HOME
 *  3. .cache subdirectory of home directory as returned by the password
 * database
 *  4. If all of the above fail and keycache.allow_in_memory is true,
 *     fall back to a shared in-memory SQLite database
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
        if (configurer::Configuration::get_allow_in_memory()) {
            ensure_inmem_anchor();
            return IN_MEMORY_DB_URI;
        }
        return "";
    }

    int r = mkdir(cache_dir.c_str(), 0700);
    if ((r < 0) && errno != EEXIST) {
        if (configurer::Configuration::get_allow_in_memory()) {
            ensure_inmem_anchor();
            return IN_MEMORY_DB_URI;
        }
        return "";
    }

    std::string keycache_dir = cache_dir + "/scitokens";
    r = mkdir(keycache_dir.c_str(), 0700);
    if ((r < 0) && errno != EEXIST) {
        if (configurer::Configuration::get_allow_in_memory()) {
            ensure_inmem_anchor();
            return IN_MEMORY_DB_URI;
        }
        return "";
    }

    std::string keycache_file = keycache_dir + "/scitokens_cpp.sqllite";
    initialize_cachedb(keycache_file);

    return keycache_file;
}

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

bool scitokens::Validator::get_public_keys_from_db(const std::string issuer,
                                                   int64_t now,
                                                   picojson::value &keys,
                                                   int64_t &next_update) {
    auto cache_fname = get_cache_file();
    if (cache_fname.size() == 0) {
        throw std::runtime_error(
            "Failed to open the keycache; unable to determine the "
            "cache directory");
    }

    sqlite3 *db;
    int rc = open_cachedb(cache_fname, &db);
    if (rc) {
        sqlite3_close(db);
        throw std::runtime_error("Failed to open the keycache at " +
                                 cache_fname);
    }
    // Set busy timeout to handle concurrent access
    sqlite3_busy_timeout(db, SQLITE_BUSY_TIMEOUT_MS);

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

        // Check if this is a negative cache entry (empty keys array)
        if (keys_local.is<picojson::object>()) {
            auto jwks_obj = keys_local.get<picojson::object>();
            auto keys_iter = jwks_obj.find("keys");
            if (keys_iter != jwks_obj.end() &&
                keys_iter->second.is<picojson::array>()) {
                auto keys_array = keys_iter->second.get<picojson::array>();
                if (keys_array.empty()) {
                    // Check if negative cache has expired
                    iter = top_obj.find("expires");
                    if (iter != top_obj.end() && iter->second.is<int64_t>()) {
                        auto expiry = iter->second.get<int64_t>();
                        if (now > expiry) {
                            // Negative cache expired, remove and return false
                            if (remove_issuer_entry(db, issuer, true) != 0) {
                                return false;
                            }
                            sqlite3_close(db);
                            return false;
                        }
                    }
                    // Negative cache still valid - throw exception
                    sqlite3_close(db);
                    throw NegativeCacheHitException(issuer);
                }
            }
        }

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
            next_update = expiry - DEFAULT_NEXT_UPDATE_OFFSET_S;
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
        throw std::runtime_error(
            "Failed to open the keycache for writing; unable to determine the "
            "cache directory");
    }

    sqlite3 *db;
    int rc = open_cachedb(cache_fname, &db);
    if (rc) {
        sqlite3_close(db);
        throw std::runtime_error(
            "Failed to open the keycache for writing at " + cache_fname);
    }
    // Set busy timeout to handle concurrent access
    sqlite3_busy_timeout(db, SQLITE_BUSY_TIMEOUT_MS);

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

std::vector<std::pair<std::string, int64_t>>
scitokens::Validator::get_all_issuers_from_db(int64_t now) {
    std::vector<std::pair<std::string, int64_t>> result;

    auto cache_fname = get_cache_file();
    if (cache_fname.size() == 0) {
        return result;
    }

    sqlite3 *db;
    int rc = open_cachedb(cache_fname, &db);
    if (rc) {
        sqlite3_close(db);
        return result;
    }

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "SELECT issuer, keys FROM keycache", -1, &stmt,
                            NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return result;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const unsigned char *issuer_data = sqlite3_column_text(stmt, 0);
        const unsigned char *keys_data = sqlite3_column_text(stmt, 1);

        if (!issuer_data || !keys_data) {
            continue;
        }

        std::string issuer(reinterpret_cast<const char *>(issuer_data));
        std::string metadata(reinterpret_cast<const char *>(keys_data));

        // Parse the metadata to get next_update and check expiry
        picojson::value json_obj;
        auto err = picojson::parse(json_obj, metadata);
        if (!err.empty() || !json_obj.is<picojson::object>()) {
            continue;
        }

        auto top_obj = json_obj.get<picojson::object>();

        // Get expiry time
        auto expires_iter = top_obj.find("expires");
        if (expires_iter == top_obj.end() ||
            !expires_iter->second.is<int64_t>()) {
            continue;
        }
        auto expiry = expires_iter->second.get<int64_t>();

        // Get next_update time
        auto next_update_iter = top_obj.find("next_update");
        int64_t next_update;
        if (next_update_iter == top_obj.end() ||
            !next_update_iter->second.is<int64_t>()) {
            // If next_update is not set, default to 4 hours before expiry
            next_update = expiry - DEFAULT_NEXT_UPDATE_OFFSET_S;
        } else {
            next_update = next_update_iter->second.get<int64_t>();
        }

        // Include expired entries - they should be refreshed after a long
        // downtime If expired, set next_update to now so they get refreshed
        // immediately
        if (now > expiry) {
            next_update = now;
        }

        result.push_back({issuer, next_update});
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

std::string scitokens::Validator::load_jwks(const std::string &issuer) {
    auto now = std::time(NULL);
    picojson::value jwks;
    int64_t next_update;

    try {
        // Try to get from cache
        if (get_public_keys_from_db(issuer, now, jwks, next_update)) {
            // Check if refresh is needed (expired based on next_update)
            if (now <= next_update) {
                // Still valid, return cached version
                return jwks.serialize();
            }
            // Past next_update, need to refresh
        }
    } catch (const NegativeCacheHitException &) {
        // Negative cache hit - return empty keys
        return std::string("{\"keys\": []}");
    }

    // Either not in cache or past next_update - refresh
    if (!refresh_jwks(issuer)) {
        throw CurlException("Failed to load JWKS for issuer: " + issuer);
    }

    // Get the newly refreshed JWKS
    return get_jwks(issuer);
}

std::string scitokens::Validator::get_jwks_metadata(const std::string &issuer) {
    auto now = std::time(NULL);
    int64_t next_update = -1;
    int64_t expires = -1;

    // Get the metadata from database without expiry check
    auto cache_fname = get_cache_file();
    if (cache_fname.size() == 0) {
        throw std::runtime_error(
            "Failed to open the keycache; unable to determine the "
            "cache directory");
    }

    sqlite3 *db;
    int rc = open_cachedb(cache_fname, &db);
    if (rc) {
        sqlite3_close(db);
        throw std::runtime_error("Failed to open the keycache at " +
                                 cache_fname);
    }
    sqlite3_busy_timeout(db, SQLITE_BUSY_TIMEOUT_MS);

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "SELECT keys from keycache where issuer = ?",
                            -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        throw std::runtime_error("Failed to prepare database query");
    }

    if (sqlite3_bind_text(stmt, 1, issuer.c_str(), issuer.size(),
                          SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        throw std::runtime_error("Failed to bind issuer to query");
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const unsigned char *data = sqlite3_column_text(stmt, 0);
        std::string metadata(reinterpret_cast<const char *>(data));
        sqlite3_finalize(stmt);
        sqlite3_close(db);

        picojson::value json_obj;
        auto err = picojson::parse(json_obj, metadata);
        if (!err.empty() || !json_obj.is<picojson::object>()) {
            throw JsonException("Invalid JSON in cache entry");
        }

        auto top_obj = json_obj.get<picojson::object>();

        // Extract expires
        auto iter = top_obj.find("expires");
        if (iter != top_obj.end() && iter->second.is<int64_t>()) {
            expires = iter->second.get<int64_t>();
        }

        // Extract next_update
        iter = top_obj.find("next_update");
        if (iter != top_obj.end() && iter->second.is<int64_t>()) {
            next_update = iter->second.get<int64_t>();
        } else if (expires != -1) {
            // Default next_update to 4 hours before expiry
            next_update = expires - DEFAULT_NEXT_UPDATE_OFFSET_S;
        }

        // Build metadata JSON (add future keys at top level if needed)
        picojson::object metadata_obj;
        if (expires != -1) {
            metadata_obj["expires"] = picojson::value(expires);
        }
        if (next_update != -1) {
            metadata_obj["next_update"] = picojson::value(next_update);
        }

        return picojson::value(metadata_obj).serialize();
    } else {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        throw std::runtime_error("Issuer not found in cache");
    }
}

bool scitokens::Validator::delete_jwks(const std::string &issuer) {
    auto cache_fname = get_cache_file();
    if (cache_fname.size() == 0) {
        return false;
    }

    sqlite3 *db;
    int rc = open_cachedb(cache_fname, &db);
    if (rc) {
        sqlite3_close(db);
        return false;
    }
    sqlite3_busy_timeout(db, SQLITE_BUSY_TIMEOUT_MS);

    // Use the existing remove_issuer_entry function
    // Note: remove_issuer_entry closes the database on error
    if (remove_issuer_entry(db, issuer, true) != 0) {
        // Database already closed by remove_issuer_entry
        return false;
    }

    sqlite3_close(db);
    return true;
}
