#include "scitokens_internal.h"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>

#ifndef PICOJSON_USE_INT64
#define PICOJSON_USE_INT64
#endif
#include <picojson/picojson.h>

namespace scitokens {
namespace internal {

MonitoringStats &MonitoringStats::instance() {
    static MonitoringStats instance;
    return instance;
}

void MonitoringStats::record_failed_issuer_lookup(const std::string &issuer,
                                                  double duration_s) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Limit the number of failed issuer entries to prevent resource exhaustion
    if (m_failed_issuer_lookups.size() >= MAX_FAILED_ISSUERS) {
        prune_failed_issuers();
    }

    // Only track if we still have room or issuer is already tracked
    if (m_failed_issuer_lookups.size() < MAX_FAILED_ISSUERS ||
        m_failed_issuer_lookups.find(issuer) != m_failed_issuer_lookups.end()) {
        auto &stats = m_failed_issuer_lookups[issuer];
        stats.count++;
        stats.total_time_s += duration_s;
    }
}

std::string
MonitoringStats::sanitize_issuer_for_json(const std::string &issuer) const {
    // Limit issuer length to prevent abuse
    const size_t max_length = 256;
    std::string sanitized = issuer;
    if (sanitized.length() > max_length) {
        sanitized = sanitized.substr(0, max_length - 3) + "...";
    }
    return sanitized;
}

void MonitoringStats::prune_failed_issuers() {
    // Remove entries with the lowest counts to make room for new ones
    if (m_failed_issuer_lookups.empty()) {
        return;
    }

    // Find the minimum count
    uint64_t min_count = UINT64_MAX;
    for (const auto &entry : m_failed_issuer_lookups) {
        uint64_t count = entry.second.count;
        if (count < min_count) {
            min_count = count;
        }
    }

    // Remove all entries with the minimum count
    for (auto it = m_failed_issuer_lookups.begin();
         it != m_failed_issuer_lookups.end();) {
        if (it->second.count == min_count) {
            it = m_failed_issuer_lookups.erase(it);
        } else {
            ++it;
        }
    }
}

std::string MonitoringStats::get_json() const {
    std::lock_guard<std::mutex> lock(m_mutex);

    picojson::object root;
    picojson::object issuers_obj;

    // Add per-issuer statistics
    for (const auto &entry : m_issuer_stats) {
        const std::string &issuer = entry.first;
        const IssuerStats &stats = entry.second;

        picojson::object issuer_obj;
        issuer_obj["successful_validations"] =
            picojson::value(static_cast<int64_t>(
                stats.successful_validations.load(std::memory_order_relaxed)));
        issuer_obj["unsuccessful_validations"] = picojson::value(
            static_cast<int64_t>(stats.unsuccessful_validations.load(
                std::memory_order_relaxed)));
        issuer_obj["expired_tokens"] = picojson::value(static_cast<int64_t>(
            stats.expired_tokens.load(std::memory_order_relaxed)));

        // Validation started counters
        issuer_obj["sync_validations_started"] = picojson::value(
            static_cast<int64_t>(stats.sync_validations_started.load(
                std::memory_order_relaxed)));
        issuer_obj["async_validations_started"] = picojson::value(
            static_cast<int64_t>(stats.async_validations_started.load(
                std::memory_order_relaxed)));

        // Duration tracking
        issuer_obj["sync_total_time_s"] =
            picojson::value(stats.get_sync_time_s());
        issuer_obj["async_total_time_s"] =
            picojson::value(stats.get_async_time_s());
        issuer_obj["total_validation_time_s"] =
            picojson::value(stats.get_total_time_s());

        // Web lookup statistics
        issuer_obj["successful_key_lookups"] =
            picojson::value(static_cast<int64_t>(
                stats.successful_key_lookups.load(std::memory_order_relaxed)));
        issuer_obj["failed_key_lookups"] = picojson::value(static_cast<int64_t>(
            stats.failed_key_lookups.load(std::memory_order_relaxed)));
        issuer_obj["failed_key_lookup_time_s"] =
            picojson::value(stats.get_failed_key_lookup_time_s());

        // Key refresh statistics
        issuer_obj["expired_keys"] = picojson::value(static_cast<int64_t>(
            stats.expired_keys.load(std::memory_order_relaxed)));
        issuer_obj["failed_refreshes"] = picojson::value(static_cast<int64_t>(
            stats.failed_refreshes.load(std::memory_order_relaxed)));
        issuer_obj["stale_key_uses"] = picojson::value(static_cast<int64_t>(
            stats.stale_key_uses.load(std::memory_order_relaxed)));

        // Background refresh statistics
        issuer_obj["background_successful_refreshes"] = picojson::value(
            static_cast<int64_t>(stats.background_successful_refreshes.load(
                std::memory_order_relaxed)));
        issuer_obj["background_failed_refreshes"] = picojson::value(
            static_cast<int64_t>(stats.background_failed_refreshes.load(
                std::memory_order_relaxed)));

        // Negative cache statistics
        issuer_obj["negative_cache_hits"] =
            picojson::value(static_cast<int64_t>(
                stats.negative_cache_hits.load(std::memory_order_relaxed)));

        // System cache statistics
        issuer_obj["system_cache_hits"] = picojson::value(static_cast<int64_t>(
            stats.system_cache_hits.load(std::memory_order_relaxed)));
        issuer_obj["system_cache_expired"] =
            picojson::value(static_cast<int64_t>(
                stats.system_cache_expired.load(std::memory_order_relaxed)));

        std::string sanitized_issuer = sanitize_issuer_for_json(issuer);
        issuers_obj[sanitized_issuer] = picojson::value(issuer_obj);
    }

    root["issuers"] = picojson::value(issuers_obj);

    // Add failed issuer lookups with duration
    if (!m_failed_issuer_lookups.empty()) {
        picojson::object failed_obj;
        for (const auto &entry : m_failed_issuer_lookups) {
            std::string sanitized_issuer =
                sanitize_issuer_for_json(entry.first);
            picojson::object lookup_stats;
            lookup_stats["count"] =
                picojson::value(static_cast<int64_t>(entry.second.count));
            lookup_stats["total_time_s"] =
                picojson::value(entry.second.total_time_s);
            failed_obj[sanitized_issuer] = picojson::value(lookup_stats);
        }
        root["failed_issuer_lookups"] = picojson::value(failed_obj);
    }

    return picojson::value(root).serialize();
}

void MonitoringStats::reset() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_issuer_stats.clear();
    m_failed_issuer_lookups.clear();
}

void MonitoringStats::maybe_write_monitoring_file() noexcept {
    try {
        // Fast path: check atomic flag first (relaxed load, no mutex)
        if (!configurer::Configuration::is_monitoring_file_configured()) {
            return;
        }

        // Get current time and interval (relaxed loads for fast path)
        auto now = std::chrono::steady_clock::now();
        auto now_seconds = std::chrono::duration_cast<std::chrono::seconds>(
                               now.time_since_epoch())
                               .count();
        int64_t last_write =
            m_last_file_write_time.load(std::memory_order_relaxed);
        int interval =
            configurer::Configuration::get_monitoring_file_interval();

        // Check if enough time has passed since last write
        if (now_seconds - last_write < interval) {
            return;
        }

        // Try to atomically claim the write (compare-and-swap)
        // Only one thread will succeed in updating the timestamp
        if (!m_last_file_write_time.compare_exchange_strong(
                last_write, now_seconds, std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            // Another thread beat us to it, they will do the write
            return;
        }

        // We successfully claimed the write, do it
        write_monitoring_file_impl();
    } catch (...) {
        // Silently ignore any errors - this is best-effort
    }
}

void MonitoringStats::maybe_write_monitoring_file_from_verify() noexcept {
    // If background refresh thread is running, it will handle the writes
    // This avoids redundant writes and potential contention
    if (BackgroundRefreshManager::get_instance().is_running()) {
        return;
    }
    maybe_write_monitoring_file();
}

void MonitoringStats::write_monitoring_file_impl() noexcept {
    try {
        std::string monitoring_file =
            configurer::Configuration::get_monitoring_file();
        if (monitoring_file.empty()) {
            return;
        }

        // Get the JSON content
        std::string json_content = get_json();

        // Write to a temporary file first, then rename for atomicity
        std::string tmp_file = monitoring_file + ".tmp";

        {
            std::ofstream ofs(tmp_file, std::ios::out | std::ios::trunc);
            if (!ofs) {
                return; // Cannot open file, silently fail
            }
            ofs << json_content;
            if (!ofs) {
                return; // Write failed, silently fail
            }
        } // Close file before rename

        // Atomic rename (on POSIX systems)
        if (std::rename(tmp_file.c_str(), monitoring_file.c_str()) != 0) {
            // Rename failed, try to clean up temp file
            std::remove(tmp_file.c_str());
        }
    } catch (...) {
        // Silently ignore any errors - this is best-effort
    }
}

} // namespace internal
} // namespace scitokens
