
#include <chrono>
#include <memory>
#include <mutex>
#include <sstream>
#include <unordered_map>

#include <atomic>
#include <condition_variable>
#include <curl/curl.h>
#include <jwt-cpp/jwt.h>
#include <thread>
#include <uuid/uuid.h>

#if defined(__GNUC__)
#define WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#else
#define WARN_UNUSED_RESULT
#endif

namespace {

struct FixedClock {
    jwt::date m_now;
    jwt::date now() const { return m_now; }
};

} // namespace

namespace jwt {
template <typename json_traits> class decoded_jwt;
namespace traits {
struct kazuho_picojson;
}
} // namespace jwt

namespace configurer {
class Configuration {
  public:
    Configuration() {}
    static void set_next_update_delta(int _next_update_delta) {
        m_next_update_delta = _next_update_delta;
    }
    static int get_next_update_delta() { return m_next_update_delta; }
    static void set_expiry_delta(int _expiry_delta) {
        m_expiry_delta = _expiry_delta;
    }
    static int get_expiry_delta() { return m_expiry_delta; }
    static std::pair<bool, std::string>
    set_cache_home(const std::string cache_home);
    static std::string get_cache_home();
    static void set_tls_ca_file(const std::string ca_file);
    static std::string get_tls_ca_file();

    // Monitoring file configuration
    static void set_monitoring_file(const std::string &path);
    static std::string get_monitoring_file();
    static void set_monitoring_file_interval(int seconds);
    static int get_monitoring_file_interval();
    // Fast-path check: returns true if monitoring file might be configured
    static bool is_monitoring_file_configured() {
        return m_monitoring_file_configured.load(std::memory_order_relaxed);
    }

    // Background refresh configuration
    static void set_background_refresh_enabled(bool enabled) {
        m_background_refresh_enabled = enabled;
    }
    static bool get_background_refresh_enabled() {
        return m_background_refresh_enabled;
    }
    static void set_refresh_interval(int interval_ms) {
        m_refresh_interval = interval_ms;
    }
    static int get_refresh_interval() { return m_refresh_interval; }
    static void set_refresh_threshold(int threshold_ms) {
        m_refresh_threshold = threshold_ms;
    }
    static int get_refresh_threshold() { return m_refresh_threshold; }

  private:
    static std::atomic_int m_next_update_delta;
    static std::atomic_int m_expiry_delta;
    static std::shared_ptr<std::string> m_cache_home;
    static std::shared_ptr<std::string> m_tls_ca_file;
    static std::string m_monitoring_file;
    static std::mutex m_monitoring_file_mutex;
    static std::atomic<bool> m_monitoring_file_configured; // Fast-path flag
    static std::atomic_int m_monitoring_file_interval; // In seconds, default 60
    static std::atomic_bool m_background_refresh_enabled;
    static std::atomic_int m_refresh_interval;  // N milliseconds
    static std::atomic_int m_refresh_threshold; // M milliseconds
    // static bool check_dir(const std::string dir_path);
    static std::pair<bool, std::string>
    mkdir_and_parents_if_needed(const std::string dir_path);
    static std::vector<std::string> path_split(const std::string dir_path);
};
} // namespace configurer

namespace scitokens {

namespace internal {

// Forward declaration
class MonitoringStats;

/**
 * Manages the background thread for refreshing JWKS.
 * This is a singleton that starts/stops a background thread which periodically
 * checks if any known issuers need their JWKS refreshed.
 */
class BackgroundRefreshManager {
  public:
    static BackgroundRefreshManager &get_instance() {
        static BackgroundRefreshManager instance;
        return instance;
    }

    // Start the background refresh thread (can be called multiple times)
    void start();

    // Stop the background refresh thread (can be called multiple times)
    void stop();

    // Check if the background refresh thread is running
    bool is_running() const {
        return m_running.load(std::memory_order_acquire);
    }

  private:
    BackgroundRefreshManager() = default;
    ~BackgroundRefreshManager() { stop(); }
    BackgroundRefreshManager(const BackgroundRefreshManager &) = delete;
    BackgroundRefreshManager &
    operator=(const BackgroundRefreshManager &) = delete;

    void refresh_loop();

    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::unique_ptr<std::thread> m_thread;
    std::atomic_bool m_shutdown{false};
    std::atomic_bool m_running{false};
};

class SimpleCurlGet {

    int m_maxbytes{1048576};
    unsigned m_timeout;
    std::vector<char> m_data;
    size_t m_len{0};
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> m_curl;
    std::unique_ptr<CURLM, decltype(&curl_multi_cleanup)> m_curl_multi;
    fd_set m_read_fd_set[FD_SETSIZE];
    fd_set m_write_fd_set[FD_SETSIZE];
    fd_set m_exc_fd_set[FD_SETSIZE];
    int m_max_fd{-1};
    long m_timeout_ms{0};

  public:
    static const unsigned default_timeout = 4;
    static const unsigned extended_timeout = 30;

    SimpleCurlGet(int maxbytes = 1024 * 1024, unsigned timeout = 30)
        : m_maxbytes(maxbytes), m_timeout(timeout),
          m_curl(nullptr, &curl_easy_cleanup),
          m_curl_multi(nullptr, &curl_multi_cleanup) {}

    struct GetStatus {
        bool m_done{false};
        int m_status_code{-1};
    };

    GetStatus perform_start(const std::string &url);
    GetStatus perform_continue();
    int perform(const std::string &url, time_t expiry_time);
    void get_data(char *&buffer, size_t &len);
    std::string get_url() const;

    long get_timeout_ms() const { return m_timeout_ms; }
    int get_max_fd() const { return m_max_fd; }
    fd_set *get_read_fd_set() { return m_read_fd_set; }
    fd_set *get_write_fd_set() { return m_write_fd_set; }
    fd_set *get_exc_fd_set() { return m_exc_fd_set; }

  private:
    static size_t write_data(void *buffer, size_t size, size_t nmemb,
                             void *userp);
};

/**
 * Statistics for monitoring token validation per issuer.
 * All counters are atomic for thread-safe access.
 * Time values are stored in nanoseconds internally for atomic operations.
 */
struct IssuerStats {
    // Validation result counters
    std::atomic<uint64_t> successful_validations{0};
    std::atomic<uint64_t> unsuccessful_validations{0};
    std::atomic<uint64_t> expired_tokens{0};

    // Validation started counters (separate from results)
    std::atomic<uint64_t> sync_validations_started{
        0}; // Started via blocking verify()
    std::atomic<uint64_t> async_validations_started{
        0}; // Started via verify_async()

    // Duration tracking (nanoseconds)
    // sync_total_time_ns is updated periodically during blocking verify()
    std::atomic<uint64_t> sync_total_time_ns{0};
    // async_total_time_ns is only updated on completion
    std::atomic<uint64_t> async_total_time_ns{0};

    // Key lookup statistics
    std::atomic<uint64_t> successful_key_lookups{0};
    std::atomic<uint64_t> failed_key_lookups{0};
    std::atomic<uint64_t> failed_key_lookup_time_ns{0}; // In nanoseconds

    // Key refresh statistics
    std::atomic<uint64_t> expired_keys{0};
    std::atomic<uint64_t> failed_refreshes{0};
    std::atomic<uint64_t> stale_key_uses{0};

    // Background refresh statistics (tracked by background thread)
    std::atomic<uint64_t> background_successful_refreshes{0};
    std::atomic<uint64_t> background_failed_refreshes{0};

    // Increment methods for atomic counters
    void inc_successful_validation() { successful_validations++; }
    void inc_unsuccessful_validation() { unsuccessful_validations++; }
    void inc_expired_token() { expired_tokens++; }
    void inc_sync_validation_started() { sync_validations_started++; }
    void inc_async_validation_started() { async_validations_started++; }
    void inc_stale_key_use() { stale_key_uses++; }
    void inc_failed_refresh() { failed_refreshes++; }
    void inc_expired_key() { expired_keys++; }
    void inc_successful_key_lookup() { successful_key_lookups++; }
    void inc_failed_key_lookup() { failed_key_lookups++; }
    void inc_background_successful_refresh() {
        background_successful_refreshes++;
    }
    void inc_background_failed_refresh() { background_failed_refreshes++; }

    // Time setters that accept std::chrono::duration
    template <typename Rep, typename Period>
    void add_sync_time(std::chrono::duration<Rep, Period> duration) {
        auto ns =
            std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
        sync_total_time_ns += static_cast<uint64_t>(ns.count());
    }

    template <typename Rep, typename Period>
    void add_async_time(std::chrono::duration<Rep, Period> duration) {
        auto ns =
            std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
        async_total_time_ns += static_cast<uint64_t>(ns.count());
    }

    template <typename Rep, typename Period>
    void
    add_failed_key_lookup_time(std::chrono::duration<Rep, Period> duration) {
        auto ns =
            std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
        failed_key_lookup_time_ns += static_cast<uint64_t>(ns.count());
    }

    void inc_failed_key_lookup(std::chrono::nanoseconds duration) {
        failed_key_lookups++;
        failed_key_lookup_time_ns += static_cast<uint64_t>(duration.count());
    }

    // Time getters that return seconds as double
    double get_sync_time_s() const {
        return static_cast<double>(sync_total_time_ns.load()) / 1e9;
    }

    double get_async_time_s() const {
        return static_cast<double>(async_total_time_ns.load()) / 1e9;
    }

    double get_total_time_s() const {
        return get_sync_time_s() + get_async_time_s();
    }

    double get_failed_key_lookup_time_s() const {
        return static_cast<double>(failed_key_lookup_time_ns.load()) / 1e9;
    }
};

/**
 * Statistics for failed (unknown) issuer lookups.
 */
struct FailedIssuerStats {
    uint64_t count{0};
    double total_time_s{0.0};
};

/**
 * Monitoring statistics singleton.
 * Tracks per-issuer validation statistics and protects against
 * resource exhaustion from invalid issuers.
 */
class MonitoringStats {
  public:
    static MonitoringStats &instance();

    /**
     * Get a reference to an issuer's statistics, creating the entry if needed.
     * The returned reference remains valid for the lifetime of the singleton.
     * All IssuerStats fields are atomic, so concurrent access is safe.
     */
    IssuerStats &get_issuer_stats(const std::string &issuer) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_issuer_stats[issuer];
    }

    /**
     * Record a failed issuer lookup (for unknown/invalid issuers).
     * This uses a separate map with DDoS protection.
     */
    void record_failed_issuer_lookup(const std::string &issuer,
                                     double duration_s);

    std::string get_json() const;
    void reset();

    /**
     * Check if the monitoring file should be written and write it if so.
     * This method is thread-safe and uses relaxed atomic operations for
     * the fast path (checking if write is needed). Only one thread will
     * actually perform the write.
     *
     * Does not throw exceptions - file write errors are silently ignored.
     */
    void maybe_write_monitoring_file() noexcept;

    /**
     * Same as maybe_write_monitoring_file(), but skips if background refresh
     * thread is running. This should be called from verify() routines to
     * avoid redundant writes when the background thread is handling them.
     */
    void maybe_write_monitoring_file_from_verify() noexcept;

  private:
    MonitoringStats() = default;
    ~MonitoringStats() = default;
    MonitoringStats(const MonitoringStats &) = delete;
    MonitoringStats &operator=(const MonitoringStats &) = delete;

    // Limit the number of failed issuer entries to prevent DDoS
    static constexpr size_t MAX_FAILED_ISSUERS = 100;

    mutable std::mutex m_mutex;
    std::unordered_map<std::string, IssuerStats> m_issuer_stats;
    std::unordered_map<std::string, FailedIssuerStats> m_failed_issuer_lookups;

    // Atomic timestamp for last monitoring file write (seconds since epoch)
    // Uses relaxed memory ordering for fast-path checks
    std::atomic<int64_t> m_last_file_write_time{0};

    std::string sanitize_issuer_for_json(const std::string &issuer) const;
    void prune_failed_issuers();
    void write_monitoring_file_impl() noexcept;
};

} // namespace internal

class UnsupportedKeyException : public std::runtime_error {
  public:
    explicit UnsupportedKeyException(const std::string &msg)
        : std::runtime_error(msg) {}
};

class JWTVerificationException : public std::runtime_error {
  public:
    explicit JWTVerificationException(const std::string &msg)
        : std::runtime_error("token verification failed: " + msg) {}
};

class CurlException : public std::runtime_error {
  public:
    explicit CurlException(const std::string &msg) : std::runtime_error(msg) {}
};

class IssuerLookupException : public CurlException {
  public:
    explicit IssuerLookupException(const std::string &msg)
        : CurlException(msg) {}
};

class TokenExpiredException : public JWTVerificationException {
  public:
    explicit TokenExpiredException(const std::string &msg)
        : JWTVerificationException(msg) {}
};

class MissingIssuerException : public std::runtime_error {
  public:
    MissingIssuerException()
        : std::runtime_error("Issuer not specified in claims") {}
};

class InvalidIssuerException : public std::runtime_error {
  public:
    InvalidIssuerException(const std::string &msg) : std::runtime_error(msg) {}
};

class JsonException : public std::runtime_error {
  public:
    JsonException(const std::string &msg) : std::runtime_error(msg) {}
};

class SciTokenKey {

  public:
    SciTokenKey() : m_kid("none"), m_name("none") {}

    SciTokenKey(const std::string &key_id, const std::string &algorithm,
                const std::string &public_contents,
                const std::string &private_contents)
        : m_kid(key_id), m_name(algorithm), m_public(public_contents),
          m_private(private_contents) {}

    std::string serialize(jwt::builder<jwt::default_clock,
                                       jwt::traits::kazuho_picojson> &builder) {
        if (m_kid != "none") {
            builder.set_key_id(m_kid);
        }
        return builder.sign(*this);
    }

    std::string sign(const std::string &data, std::error_code &ec) const {
        if (m_name == "RS256") {
            return jwt::algorithm::rs256(m_public, m_private).sign(data, ec);
        } else if (m_name == "ES256") {
            return jwt::algorithm::es256(m_public, m_private).sign(data, ec);
        }
        throw UnsupportedKeyException(
            "Provided algorithm name is not supported");
    }

    std::string name() const { return m_name; }

    void verify(const std::string &data, const std::string &signature,
                std::error_code &ec) const {
        if (m_name == "RS256") {
            jwt::algorithm::rs256(m_public, m_private)
                .verify(data, signature, ec);
        } else if (m_name == "ES256") {
            jwt::algorithm::es256(m_public, m_private)
                .verify(data, signature, ec);
        } else {
            throw UnsupportedKeyException(
                "Provided algorithm is not supported.");
        }
    }

  private:
    std::string m_kid;
    std::string m_name;
    std::string m_public;
    std::string m_private;
};

class Validator;

class AsyncStatus {
  public:
    AsyncStatus() = default;
    AsyncStatus(const AsyncStatus &) = delete;
    AsyncStatus &operator=(const AsyncStatus &) = delete;

    enum AsyncState { DOWNLOAD_METADATA, DOWNLOAD_PUBLIC_KEY, DONE };

    bool m_done{false};
    bool m_continue_fetch{false};
    bool m_ignore_error{false};
    bool m_do_store{true};
    bool m_has_metadata{false};
    bool m_oauth_fallback{false};
    bool m_is_refresh{false}; // True if this is a refresh of an existing key
    AsyncState m_state{DOWNLOAD_METADATA};
    std::unique_lock<std::mutex> m_refresh_lock;

    int64_t m_next_update{-1};
    int64_t m_expires{-1};
    picojson::value m_keys;
    std::string m_issuer;
    std::string m_kid;
    std::string m_oauth_metadata_url;
    std::unique_ptr<internal::SimpleCurlGet> m_cget;
    std::string m_jwt_string;
    std::string m_public_pem;
    std::string m_algorithm;
    std::chrono::steady_clock::time_point m_start_time;
    bool m_monitoring_started{false};
    bool m_is_sync{
        false}; // True if called from blocking verify(), false for pure async

    struct timeval get_timeout_val(time_t expiry_time) const {
        auto now = time(NULL);
        long timeout_ms = 100 * (expiry_time - now);
        if (m_cget && (m_cget->get_timeout_ms() < timeout_ms))
            timeout_ms = m_cget->get_timeout_ms();
        struct timeval timeout;
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        return timeout;
    }

    int get_max_fd() const { return m_cget ? m_cget->get_max_fd() : -1; }
    fd_set *get_read_fd_set() {
        return m_cget ? m_cget->get_read_fd_set() : nullptr;
    }
    fd_set *get_write_fd_set() {
        return m_cget ? m_cget->get_write_fd_set() : nullptr;
    }
    fd_set *get_exc_fd_set() {
        return m_cget ? m_cget->get_exc_fd_set() : nullptr;
    }
};

class SciTokenAsyncStatus {
  public:
    SciTokenAsyncStatus() = default;
    SciTokenAsyncStatus(const SciTokenAsyncStatus &) = delete;
    SciTokenAsyncStatus &operator=(const SciTokenAsyncStatus &) = delete;

    std::unique_ptr<Validator> m_validator;
    std::unique_ptr<AsyncStatus> m_status;
};

class SciToken {

    friend class scitokens::Validator;

  public:
    enum class Profile {
        COMPAT = 0,
        SCITOKENS_1_0,
        SCITOKENS_2_0,
        WLCG_1_0,
        AT_JWT
    };

    SciToken(SciTokenKey &signing_algorithm) : m_key(signing_algorithm) {}

    void set_claim(const std::string &key, const jwt::claim &value) {
        m_claims[key] = value;
        if (key == "iss") {
            m_issuer_set = true;
        }
    }

    void set_serialize_mode(Profile profile) { m_serialize_profile = profile; }

    void set_deserialize_mode(Profile profile) {
        m_deserialize_profile = profile;
    }

    const jwt::claim get_claim(const std::string &key) { return m_claims[key]; }

    bool has_claim(const std::string &key) const {
        return m_claims.find(key) != m_claims.end();
    }

    void set_claim_list(const std::string &claim,
                        std::vector<std::string> &claim_list) {
        picojson::array array;
        array.reserve(claim_list.size());
        for (const auto &entry : claim_list) {
            array.emplace_back(entry);
        }
        m_claims[claim] = jwt::claim(picojson::value(array));
    }

    // Return a claim as a string
    // If the claim is not a string, it can throw
    // a std::bad_cast() exception.
    const std::string get_claim_string(const std::string &key) {
        return m_claims[key].as_string();
    }

    const std::vector<std::string> get_claim_list(const std::string &key) {
        picojson::array array;
        try {
            array = m_claims[key].as_array();
        } catch (std::bad_cast &) {
            throw JsonException("Claim's value is not a JSON list");
        }
        std::vector<std::string> result;
        for (const auto &value : array) {
            result.emplace_back(value.get<std::string>());
        }
        return result;
    }

    void set_lifetime(int lifetime) { m_lifetime = lifetime; }

    std::string serialize() {
        auto builder(jwt::create());

        if (!m_issuer_set) {
            throw MissingIssuerException();
        }
        auto time = std::chrono::system_clock::now();
        builder.set_issued_at(time);
        builder.set_not_before(time);
        builder.set_expires_at(time + std::chrono::seconds(m_lifetime));
        if (m_serialize_profile == Profile::AT_JWT) {
            builder.set_type("at+jwt");
        }

        uuid_t uuid;
        uuid_generate(uuid);
        char uuid_str[37];
        uuid_unparse_lower(uuid, uuid_str);
        m_claims["jti"] = jwt::claim(std::string(uuid_str));

        if (m_serialize_profile == Profile::SCITOKENS_2_0) {
            m_claims["ver"] = jwt::claim(std::string("scitoken:2.0"));
            auto iter = m_claims.find("aud");
            if (iter == m_claims.end()) {
                m_claims["aud"] = jwt::claim(std::string("ANY"));
            }
        } else if (m_serialize_profile == Profile::WLCG_1_0) {
            m_claims["wlcg.ver"] = jwt::claim(std::string("1.0"));
            auto iter = m_claims.find("aud");
            if (iter == m_claims.end()) {
                m_claims["aud"] =
                    jwt::claim(std::string("https://wlcg.cern.ch/jwt/v1/any"));
            }
        }

        // Set all the payload claims
        for (auto it : m_claims) {
            builder.set_payload_claim(it.first, it.second);
        }

        return m_key.serialize(builder);
    }

    void deserialize(const std::string &data,
                     std::vector<std::string> allowed_issuers = {});

    std::unique_ptr<SciTokenAsyncStatus>
    deserialize_start(const std::string &data,
                      std::vector<std::string> allowed_issuers = {});

    std::unique_ptr<SciTokenAsyncStatus>
    deserialize_continue(std::unique_ptr<SciTokenAsyncStatus> status);

  private:
    bool m_issuer_set{false};
    int m_lifetime{600};
    Profile m_profile{Profile::SCITOKENS_1_0};
    Profile m_serialize_profile{Profile::COMPAT};
    Profile m_deserialize_profile{Profile::COMPAT};
    std::unordered_map<std::string, jwt::claim> m_claims;
    std::unique_ptr<jwt::decoded_jwt<jwt::traits::kazuho_picojson>> m_decoded;
    SciTokenKey &m_key;
};

class Validator {

    friend class internal::BackgroundRefreshManager;

    typedef int (*StringValidatorFunction)(const char *value, char **err_msg);
    typedef bool (*ClaimValidatorFunction)(const jwt::claim &claim_value,
                                           void *data);
    typedef std::map<std::string, std::vector<StringValidatorFunction>>
        ClaimStringValidatorMap;
    typedef std::map<std::string,
                     std::vector<std::pair<ClaimValidatorFunction, void *>>>
        ClaimValidatorMap;

  public:
    Validator() : m_now(std::chrono::system_clock::now()) {}

    void set_now(std::chrono::system_clock::time_point now) { m_now = now; }

    // Maximum timeout for select() in microseconds for periodic checks
    static constexpr long MAX_SELECT_TIMEOUT_US = 50000; // 50ms

    std::unique_ptr<AsyncStatus> verify_async(const SciToken &scitoken) {
        const jwt::decoded_jwt<jwt::traits::kazuho_picojson> *jwt_decoded =
            scitoken.m_decoded.get();
        if (!jwt_decoded) {
            throw JWTVerificationException(
                "Token is not deserialized from string.");
        }
        return verify_async(*jwt_decoded);
    }

    void verify(const SciToken &scitoken, time_t expiry_time) {
        // Check if monitoring file should be written (fast-path, relaxed
        // atomic). Skip if background thread is running.
        internal::MonitoringStats::instance()
            .maybe_write_monitoring_file_from_verify();

        std::string issuer = "";
        auto start_time = std::chrono::steady_clock::now();
        auto last_duration_update = start_time;
        internal::IssuerStats *issuer_stats = nullptr;

        try {
            auto result = verify_async(scitoken);

            // Extract issuer from the result's JWT string after decoding starts
            const jwt::decoded_jwt<jwt::traits::kazuho_picojson> *jwt_decoded =
                scitoken.m_decoded.get();
            if (jwt_decoded && jwt_decoded->has_payload_claim("iss")) {
                issuer = jwt_decoded->get_issuer();
                // Record sync validation started and get stats reference
                issuer_stats =
                    &internal::MonitoringStats::instance().get_issuer_stats(
                        issuer);
                issuer_stats->inc_sync_validation_started();
            }

            while (!result->m_done) {
                auto timeout_val = result->get_timeout_val(expiry_time);
                // Limit select to MAX_SELECT_TIMEOUT_US for periodic checks
                if (timeout_val.tv_sec > 0 ||
                    timeout_val.tv_usec > MAX_SELECT_TIMEOUT_US) {
                    timeout_val.tv_sec = 0;
                    timeout_val.tv_usec = MAX_SELECT_TIMEOUT_US;
                }

                int select_result =
                    select(result->get_max_fd() + 1, result->get_read_fd_set(),
                           result->get_write_fd_set(), result->get_exc_fd_set(),
                           &timeout_val);

                // Update duration periodically on each select return
                if (issuer_stats) {
                    auto now = std::chrono::steady_clock::now();
                    auto delta =
                        std::chrono::duration_cast<std::chrono::nanoseconds>(
                            now - last_duration_update);
                    issuer_stats->add_sync_time(delta);
                    last_duration_update = now;
                }

                if (time(NULL) >= expiry_time) {
                    throw CurlException(
                        "Timeout when loading the OIDC metadata.");
                }

                // Only continue if select returned due to I/O activity (not
                // timeout)
                if (select_result > 0) {
                    result = verify_async_continue(std::move(result));
                }
                // If select_result == 0 (timeout) or -1 (error/interrupt),
                // just loop back to update duration and check expiry
            }

            // Record successful validation (final duration update)
            if (issuer_stats) {
                auto end_time = std::chrono::steady_clock::now();
                auto delta =
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        end_time - last_duration_update);
                issuer_stats->add_sync_time(delta);
                issuer_stats->inc_successful_validation();
            }
        } catch (const std::exception &e) {
            // Record failure (final duration update)
            if (issuer_stats) {
                auto end_time = std::chrono::steady_clock::now();
                auto delta =
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        end_time - last_duration_update);
                issuer_stats->add_sync_time(delta);
                record_validation_error_stats(*issuer_stats, e);
            } else if (!issuer.empty()) {
                // Issuer known but stats not yet retrieved
                auto &stats =
                    internal::MonitoringStats::instance().get_issuer_stats(
                        issuer);
                auto duration =
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::steady_clock::now() - start_time);
                stats.add_sync_time(duration);
                record_validation_error_stats(stats, e);
            }
            throw;
        }
    }

    void verify(const jwt::decoded_jwt<jwt::traits::kazuho_picojson> &jwt) {
        // Check if monitoring file should be written (fast-path, relaxed
        // atomic). Skip if background thread is running.
        internal::MonitoringStats::instance()
            .maybe_write_monitoring_file_from_verify();

        std::string issuer = "";
        auto start_time = std::chrono::steady_clock::now();
        internal::IssuerStats *issuer_stats = nullptr;

        try {
            // Try to extract issuer for monitoring
            if (jwt.has_payload_claim("iss")) {
                issuer = jwt.get_issuer();
                // Record sync validation started and get stats reference
                issuer_stats =
                    &internal::MonitoringStats::instance().get_issuer_stats(
                        issuer);
                issuer_stats->inc_sync_validation_started();
            }

            auto result = verify_async(jwt);
            while (!result->m_done) {
                result = verify_async_continue(std::move(result));
            }

            // Record successful validation
            if (issuer_stats) {
                auto end_time = std::chrono::steady_clock::now();
                auto duration =
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        end_time - start_time);
                issuer_stats->add_sync_time(duration);
                issuer_stats->inc_successful_validation();
            }
        } catch (const std::exception &e) {
            // Record failure if we have an issuer
            if (issuer_stats) {
                auto end_time = std::chrono::steady_clock::now();
                auto duration =
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        end_time - start_time);
                issuer_stats->add_sync_time(duration);
                record_validation_error_stats(*issuer_stats, e);
            } else if (!issuer.empty()) {
                // Issuer known but stats not yet retrieved
                auto &stats =
                    internal::MonitoringStats::instance().get_issuer_stats(
                        issuer);
                auto duration =
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::steady_clock::now() - start_time);
                stats.add_sync_time(duration);
                record_validation_error_stats(stats, e);
            }
            throw;
        }
    }

    std::unique_ptr<AsyncStatus>
    verify_async(const jwt::decoded_jwt<jwt::traits::kazuho_picojson> &jwt) {
        // Start background refresh thread if configured on first verification
        std::call_once(m_background_refresh_once, []() {
            if (configurer::Configuration::get_background_refresh_enabled()) {
                internal::BackgroundRefreshManager::get_instance().start();
            }
        });

        // If token has a typ header claim (RFC8725 Section 3.11), trust that in
        // COMPAT mode.
        if (jwt.has_type()) {
            std::string t_type = jwt.get_type();
            if (m_validate_profile == SciToken::Profile::COMPAT) {
                if (t_type == "at+jwt" || t_type == "application/at+jwt") {
                    m_profile = SciToken::Profile::AT_JWT;
                }
            } else if (m_validate_profile == SciToken::Profile::AT_JWT) {
                if (t_type != "at+jwt" && t_type != "application/at+jwt") {
                    throw JWTVerificationException(
                        "'typ' header claim must be at+jwt");
                }
                m_profile = SciToken::Profile::AT_JWT;
            }
        } else {
            if (m_validate_profile == SciToken::Profile::AT_JWT) {
                throw JWTVerificationException(
                    "'typ' header claim must be set for at+jwt tokens");
            }
        }
        if (!jwt.has_payload_claim("iat")) {
            throw JWTVerificationException("'iat' claim is mandatory");
        }
        if (m_profile == SciToken::Profile::SCITOKENS_1_0 ||
            m_profile == SciToken::Profile::SCITOKENS_2_0) {
            if (!jwt.has_payload_claim("nbf")) {
                throw JWTVerificationException("'nbf' claim is mandatory");
            }
        }
        if (!jwt.has_payload_claim("exp")) {
            throw JWTVerificationException("'exp' claim is mandatory");
        }
        if (!jwt.has_payload_claim("iss")) {
            throw JWTVerificationException("'iss' claim is mandatory");
        }
        if (!m_allowed_issuers.empty()) {
            std::string issuer = jwt.get_issuer();
            bool permitted = false;
            for (const auto &allowed_issuer : m_allowed_issuers) {
                if (issuer == allowed_issuer) {
                    permitted = true;
                    break;
                }
            }
            if (!permitted) {
                std::string safe_issuer = format_issuer_for_error(jwt);
                throw JWTVerificationException(
                    "Token issuer " + safe_issuer +
                    " is not in list of allowed issuers.");
            }
        }

        for (const auto &claim : m_critical_claims) {
            if (!jwt.has_payload_claim(claim)) {
                std::stringstream ss;
                ss << "'" << claim << "' claim is mandatory";
                throw JWTVerificationException(ss.str());
            }
        }

        std::string public_pem;
        std::string algorithm;
        // Key id is optional in the RFC, set to blank if it doesn't exist
        std::string key_id;
        if (jwt.has_key_id()) {
            key_id = jwt.get_key_id();
        }
        auto status =
            get_public_key_pem(jwt.get_issuer(), key_id, public_pem, algorithm);
        status->m_jwt_string = jwt.get_token();
        status->m_public_pem = public_pem;
        status->m_algorithm = algorithm;
        // Start monitoring timing and record async validation started
        status->m_start_time = std::chrono::steady_clock::now();
        status->m_monitoring_started = true;
        auto &stats = internal::MonitoringStats::instance().get_issuer_stats(
            jwt.get_issuer());
        stats.inc_async_validation_started();

        return verify_async_continue(std::move(status));
    }

    std::unique_ptr<AsyncStatus>
    verify_async_continue(std::unique_ptr<AsyncStatus> status) {
        if (!status->m_done) {
            std::string public_pem, algorithm;
            status = get_public_key_pem_continue(std::move(status), public_pem,
                                                 algorithm);
            status->m_public_pem = public_pem;
            status->m_algorithm = algorithm;
            if (!status->m_done) {
                return std::move(status);
            }
        }

        // std::cout << "Public PEM: " << public_pem << std::endl << "Algorithm:
        // " << algorithm << std::endl;
        SciTokenKey key(status->m_kid, status->m_algorithm,
                        status->m_public_pem, "");

        auto verifier =
            jwt::verify<FixedClock, jwt::traits::kazuho_picojson>({m_now})
                .allow_algorithm(key);

        const jwt::decoded_jwt<jwt::traits::kazuho_picojson> jwt(
            status->m_jwt_string);
        try {
            verifier.verify(jwt);
        } catch (const std::exception &e) {
            // Check if this is an expiration error from jwt-cpp
            std::string error_msg = e.what();
            if (error_msg.find("exp") != std::string::npos ||
                error_msg.find("expir") != std::string::npos) {
                throw TokenExpiredException(error_msg);
            }
            throw;
        }

        bool must_verify_everything = true;
        if (jwt.has_payload_claim("ver")) {
            const jwt::claim &claim = jwt.get_payload_claim("ver");
            if (claim.get_type() != jwt::json::type::string) {
                throw JWTVerificationException(
                    "'ver' claim value must be a string (if present)");
            }
            std::string ver_string = claim.as_string();
            if ((ver_string == "scitokens:2.0") ||
                (ver_string == "scitoken:2.0")) {
                must_verify_everything = false;
                if ((m_validate_profile != SciToken::Profile::COMPAT) &&
                    (m_validate_profile != SciToken::Profile::SCITOKENS_2_0)) {
                    throw JWTVerificationException(
                        "Invalidate token type; not expecting a SciToken 2.0.");
                }
                m_profile = SciToken::Profile::SCITOKENS_2_0;
                if (!jwt.has_payload_claim("aud")) {
                    throw JWTVerificationException(
                        "'aud' claim required for SciTokens 2.0 profile");
                }
            } else if (ver_string == "scitokens:1.0") {
                must_verify_everything = m_validate_all_claims;
                if ((m_validate_profile != SciToken::Profile::COMPAT) &&
                    (m_validate_profile != SciToken::Profile::SCITOKENS_1_0)) {
                    throw JWTVerificationException(
                        "Invalidate token type; not expecting a SciToken 1.0.");
                }
                m_profile = SciToken::Profile::SCITOKENS_1_0;
            } else {
                std::stringstream ss;
                ss << "Unknown profile version in token: " << ver_string;
                throw JWTVerificationException(ss.str());
            }
            // Handle WLCG common JWT profile.
        } else if (jwt.has_payload_claim("wlcg.ver")) {
            if ((m_validate_profile != SciToken::Profile::COMPAT) &&
                (m_validate_profile != SciToken::Profile::WLCG_1_0)) {
                throw JWTVerificationException(
                    "Invalidate token type; not expecting a WLCG 1.0.");
            }

            m_profile = SciToken::Profile::WLCG_1_0;
            must_verify_everything = false;
            const jwt::claim &claim = jwt.get_payload_claim("wlcg.ver");
            if (claim.get_type() != jwt::json::type::string) {
                throw JWTVerificationException(
                    "'ver' claim value must be a string (if present)");
            }
            std::string ver_string = claim.as_string();
            if (ver_string != "1.0") {
                std::stringstream ss;
                ss << "Unknown WLCG profile version in token: " << ver_string;
                throw JWTVerificationException(ss.str());
            }
            if (!jwt.has_payload_claim("aud")) {
                throw JWTVerificationException(
                    "Malformed token: 'aud' claim required for WLCG profile");
            }
        } else if (m_profile == SciToken::Profile::AT_JWT) {
            // detected early above from typ header claim.
            must_verify_everything = false;
        } else {
            if ((m_validate_profile != SciToken::Profile::COMPAT) &&
                (m_validate_profile != SciToken::Profile::SCITOKENS_1_0)) {
                throw JWTVerificationException(
                    "Invalidate token type; not expecting a SciToken 1.0.");
            }

            m_profile = SciToken::Profile::SCITOKENS_1_0;
            must_verify_everything = m_validate_all_claims;
        }

        auto claims = jwt.get_payload_json();
        for (const auto &claim_pair : claims) {
            if (claim_pair.first == "iat" || claim_pair.first == "nbf" ||
                claim_pair.first == "exp" || claim_pair.first == "ver") {
                continue;
            }
            auto iter = m_validators.find(claim_pair.first);
            auto iter_claim = m_claim_validators.find(claim_pair.first);
            if ((iter == m_validators.end() || iter->second.empty()) &&
                (iter_claim == m_claim_validators.end() ||
                 iter_claim->second.empty())) {
                bool is_issuer = claim_pair.first == "iss";
                if (is_issuer && !m_allowed_issuers.empty()) {
                    // skip; we verified it above
                } else if (must_verify_everything) {
                    std::stringstream ss;
                    ss << "'" << claim_pair.first
                       << "' claim verification is mandatory";
                    // std::cout << ss.str() << std::endl;
                    throw JWTVerificationException(ss.str());
                }
            }
            // std::cout << "Running claim " << claim_pair.first << " through
            // validation." << std::endl;
            if (iter != m_validators.end())
                for (const auto &verification_func : iter->second) {
                    const jwt::claim &claim =
                        jwt.get_payload_claim(claim_pair.first);
                    if (claim.get_type() != jwt::json::type::string) {
                        std::stringstream ss;
                        ss << "'" << claim_pair.first
                           << "' claim value must be a string to verify.";
                        throw JWTVerificationException(ss.str());
                    }
                    std::string value = claim.as_string();
                    char *err_msg = nullptr;
                    if (verification_func(value.c_str(), &err_msg)) {
                        if (err_msg) {
                            throw JWTVerificationException(err_msg);
                        } else {
                            std::stringstream ss;
                            ss << "'" << claim_pair.first
                               << "' claim verification failed.";
                            throw JWTVerificationException(ss.str());
                        }
                    }
                }
            if (iter_claim != m_claim_validators.end())
                for (const auto &verification_pair : iter_claim->second) {
                    const jwt::claim &claim =
                        jwt.get_payload_claim(claim_pair.first);
                    if (verification_pair.first(
                            claim, verification_pair.second) == false) {
                        std::stringstream ss;
                        ss << "'" << claim_pair.first
                           << "' claim verification failed.";
                        throw JWTVerificationException(ss.str());
                    }
                }
        }

        // Record successful validation (only for async API, sync handles its
        // own)
        if (status->m_monitoring_started && !status->m_is_sync) {
            auto end_time = std::chrono::steady_clock::now();
            auto duration =
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    end_time - status->m_start_time);
            auto &stats =
                internal::MonitoringStats::instance().get_issuer_stats(
                    status->m_issuer);
            stats.inc_successful_validation();
            stats.add_async_time(duration);
        }

        std::unique_ptr<AsyncStatus> result(new AsyncStatus());
        result->m_done = true;
        return result;
    }

    void add_critical_claims(const std::vector<std::string> &claims) {
        std::copy(claims.begin(), claims.end(),
                  std::back_inserter(m_critical_claims));
    }

    void add_allowed_issuers(const std::vector<std::string> &allowed_issuers) {
        std::copy(allowed_issuers.begin(), allowed_issuers.end(),
                  std::back_inserter(m_allowed_issuers));
    }

    void add_string_validator(const std::string &claim,
                              StringValidatorFunction func) {
        auto result = m_validators.insert(
            {claim, std::vector<StringValidatorFunction>()});
        result.first->second.push_back(func);
    }

    void add_claim_validator(const std::string &claim,
                             ClaimValidatorFunction func, void *data) {
        auto result = m_claim_validators.insert(
            {claim, std::vector<std::pair<ClaimValidatorFunction, void *>>()});
        result.first->second.push_back({func, data});
    }

    void set_validate_all_claims_scitokens_1(bool new_val) {
        m_validate_all_claims = new_val;
    }

    /**
     * Get the profile of the last validated token.
     *
     * If there has been no validation - or the validation failed,
     * then the return value is unspecified.
     *
     * Will not return Profile::COMPAT.
     */
    SciToken::Profile get_profile() const {
        if (m_profile == SciToken::Profile::COMPAT) {
            throw JWTVerificationException("Token profile has not been set.");
        }
        return m_profile;
    }

    /**
     * Set the profile that will be used for validation; COMPAT indicates any
     * supported profile is allowable.
     */
    void set_validate_profile(SciToken::Profile profile) {
        m_validate_profile = profile;
    }

    /**
     * Store the contents of a public EC key for a given issuer.
     */
    static bool store_public_ec_key(const std::string &issuer,
                                    const std::string &kid,
                                    const std::string &key);

    /**
     * Store the contents of a JWKS for a given issuer.
     */
    static bool store_jwks(const std::string &issuer, const std::string &jwks);

    /**
     * Trigger a refresh of the JWKS or a given issuer.
     */
    static bool refresh_jwks(const std::string &issuer);

    /**
     * Fetch the contents of fa JWKS for a given issuer (do not trigger a
     * refresh). Will return an empty JWKS if no valid JWKS is available.
     */
    static std::string get_jwks(const std::string &issuer);

    /**
     * Get all issuers from the database along with their next_update times.
     * Returns a vector of pairs (issuer, next_update).
     * Only returns non-expired entries.
     */
    static std::vector<std::pair<std::string, int64_t>>
    get_all_issuers_from_db(int64_t now);

  private:
    static std::unique_ptr<AsyncStatus>
    get_public_key_pem(const std::string &issuer, const std::string &kid,
                       std::string &public_pem, std::string &algorithm);
    static std::unique_ptr<AsyncStatus>
    get_public_key_pem_continue(std::unique_ptr<AsyncStatus> status,
                                std::string &public_pem,
                                std::string &algorithm);
    static std::unique_ptr<AsyncStatus>
    get_public_keys_from_web(const std::string &issuer, unsigned timeout);
    static std::unique_ptr<AsyncStatus>
    get_public_keys_from_web_continue(std::unique_ptr<AsyncStatus> status);
    static bool get_public_keys_from_db(const std::string issuer, int64_t now,
                                        picojson::value &keys,
                                        int64_t &next_update);
    static bool store_public_keys(const std::string &issuer,
                                  const picojson::value &keys,
                                  int64_t next_update, int64_t expires);

    /**
     * Safely format an issuer for error messages.
     * Serializes the issuer claim back to JSON format and limits the size
     * to prevent malicious issuers from causing problems in error output.
     */
    static std::string format_issuer_for_error(
        const jwt::decoded_jwt<jwt::traits::kazuho_picojson> &jwt) {
        try {
            if (!jwt.has_payload_claim("iss")) {
                return "<missing issuer>";
            }
            // Get the raw claim and serialize it back to JSON
            const auto &claim = jwt.get_payload_claim("iss");
            std::string serialized = claim.to_json().serialize();
            // Limit the size to prevent abuse
            const size_t max_issuer_length = 256;
            if (serialized.length() > max_issuer_length) {
                serialized =
                    serialized.substr(0, max_issuer_length - 3) + "...";
            }
            return serialized;
        } catch (...) {
            // If anything goes wrong, return a safe fallback
            return "<invalid issuer>";
        }
    }

    /**
     * Helper method to record monitoring statistics for validation errors.
     * This version operates on an IssuerStats reference and does NOT update
     * time (caller is responsible for time tracking).
     */
    void record_validation_error_stats(internal::IssuerStats &stats,
                                       const std::exception &e) {
        if (dynamic_cast<const TokenExpiredException *>(&e)) {
            stats.inc_expired_token();
        }

        stats.inc_unsuccessful_validation();
    }

    bool m_validate_all_claims{true};
    SciToken::Profile m_profile{SciToken::Profile::COMPAT};
    SciToken::Profile m_validate_profile{SciToken::Profile::COMPAT};
    ClaimStringValidatorMap m_validators;
    ClaimValidatorMap m_claim_validators;

    std::chrono::system_clock::time_point m_now;

    std::vector<std::string> m_critical_claims;
    std::vector<std::string> m_allowed_issuers;

    // Once flag for starting background refresh on first verification
    static std::once_flag m_background_refresh_once;
};

class Enforcer {

  public:
    typedef std::vector<std::pair<std::string, std::string>> AclsList;

    Enforcer(std::string issuer, std::vector<std::string> audience_list)
        : m_issuer(issuer), m_audiences(audience_list) {
        m_validator.add_allowed_issuers({m_issuer});
        m_validator.add_claim_validator("jti", &Enforcer::str_validator,
                                        nullptr);
        m_validator.add_claim_validator("sub", &Enforcer::str_validator,
                                        nullptr);
        m_validator.add_claim_validator("opt", &Enforcer::all_validator,
                                        nullptr);
        m_validator.add_claim_validator("aud", &Enforcer::aud_validator, this);
        m_validator.add_claim_validator("scope", &Enforcer::scope_validator,
                                        this);
        std::vector<std::string> critical_claims = {"scope"};

        // If any audiences are in the given to us, then force the validator to
        // check it.
        if (!m_audiences.empty()) {
            critical_claims.push_back("aud");
        }
        m_validator.add_critical_claims(critical_claims);
    }

    void set_now(std::chrono::system_clock::time_point now) {
        m_validator.set_now(now);
    }

    void set_validate_profile(SciToken::Profile profile) {
        m_validate_profile = profile;
    }

    bool test(const SciToken &scitoken, const std::string &authz,
              const std::string &path) {
        reset_state();
        m_test_path = path;
        m_test_authz = authz;
        try {
            m_validator.verify(scitoken, time(NULL) + 20);
            return true;
        } catch (std::runtime_error &) {
            throw;
        }
    }

    AclsList generate_acls(const SciToken &scitoken) {
        reset_state();
        m_validator.verify(scitoken, time(NULL) + 20);
        return m_gen_acls;
    }

    std::unique_ptr<AsyncStatus> generate_acls_start(const SciToken &scitoken,
                                                     AclsList &acls) {
        reset_state();
        auto status = m_validator.verify_async(scitoken);
        if (status->m_done) {
            acls = m_gen_acls;
        }
        return status;
    }

    std::unique_ptr<AsyncStatus>
    generate_acls_continue(std::unique_ptr<AsyncStatus> status,
                           AclsList &acls) {
        auto result = m_validator.verify_async_continue(std::move(status));
        if (result->m_done) {
            acls = m_gen_acls;
        }
        return result;
    }

  private:
    static bool all_validator(const jwt::claim &, void *) { return true; }

    static bool str_validator(const jwt::claim &claim, void *) {
        return claim.get_type() == jwt::json::type::string;
    }

    static bool scope_validator(const jwt::claim &claim, void *myself);

    static bool aud_validator(const jwt::claim &claim, void *myself) {
        auto me = reinterpret_cast<scitokens::Enforcer *>(myself);
        std::vector<std::string> jwt_audiences;
        if (claim.get_type() == jwt::json::type::string) {
            const std::string &audience = claim.as_string();
            jwt_audiences.push_back(audience);
        } else if (claim.get_type() == jwt::json::type::array) {
            const picojson::array &audiences = claim.as_array();
            for (const auto &aud_value : audiences) {
                const std::string &audience = aud_value.get<std::string>();
                jwt_audiences.push_back(audience);
            }
        }
        for (const auto &aud_value : jwt_audiences) {
            if (((me->m_validator.get_profile() ==
                  SciToken::Profile::SCITOKENS_2_0) &&
                 (aud_value == "ANY")) ||
                ((me->m_validator.get_profile() ==
                  SciToken::Profile::WLCG_1_0) &&
                 (aud_value == "https://wlcg.cern.ch/jwt/v1/any"))) {
                return true;
            }
            for (const auto &aud : me->m_audiences) {
                if (aud == aud_value) {
                    return true;
                }
            }
        }
        return false;
    }

    void reset_state() {
        m_test_path = "";
        m_test_authz = "";
        m_gen_acls.clear();
        m_validator.set_validate_profile(m_validate_profile);
    }

    SciToken::Profile m_validate_profile{SciToken::Profile::COMPAT};

    std::string m_test_path;
    std::string m_test_authz;
    AclsList m_gen_acls;

    std::string m_issuer;
    std::vector<std::string> m_audiences;
    scitokens::Validator m_validator;
};

} // namespace scitokens
