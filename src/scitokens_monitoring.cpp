#include "scitokens_internal.h"
#include <algorithm>
#include <chrono>
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

void MonitoringStats::record_validation_success(const std::string &issuer,
                                                double duration_s) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto &stats = m_issuer_stats[issuer];
    stats.successful_validations++;
    // Add to the total time (accumulate across all validations)
    // No atomic needed - protected by mutex
    stats.total_time_s += duration_s;
}

void MonitoringStats::record_validation_failure(const std::string &issuer,
                                                double duration_s) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto &stats = m_issuer_stats[issuer];
    stats.unsuccessful_validations++;
    // Add to the total time (accumulate across all validations)
    // No atomic needed - protected by mutex
    stats.total_time_s += duration_s;
}

void MonitoringStats::record_expired_token(const std::string &issuer) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto &stats = m_issuer_stats[issuer];
    stats.expired_tokens++;
}

void MonitoringStats::record_failed_issuer_lookup(const std::string &issuer) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Limit the number of failed issuer entries to prevent resource exhaustion
    if (m_failed_issuer_lookups.size() >= MAX_FAILED_ISSUERS) {
        prune_failed_issuers();
    }

    // Only track if we still have room or issuer is already tracked
    if (m_failed_issuer_lookups.size() < MAX_FAILED_ISSUERS ||
        m_failed_issuer_lookups.find(issuer) != m_failed_issuer_lookups.end()) {
        m_failed_issuer_lookups[issuer]++;
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
        uint64_t count = entry.second;
        if (count < min_count) {
            min_count = count;
        }
    }

    // Remove all entries with the minimum count
    for (auto it = m_failed_issuer_lookups.begin();
         it != m_failed_issuer_lookups.end();) {
        if (it->second == min_count) {
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
        issuer_obj["successful_validations"] = picojson::value(
            static_cast<double>(stats.successful_validations.load()));
        issuer_obj["unsuccessful_validations"] = picojson::value(
            static_cast<double>(stats.unsuccessful_validations.load()));
        issuer_obj["expired_tokens"] =
            picojson::value(static_cast<double>(stats.expired_tokens.load()));
        issuer_obj["total_validation_time_s"] =
            picojson::value(stats.total_time_s);

        std::string sanitized_issuer = sanitize_issuer_for_json(issuer);
        issuers_obj[sanitized_issuer] = picojson::value(issuer_obj);
    }

    root["issuers"] = picojson::value(issuers_obj);

    // Add failed issuer lookups
    if (!m_failed_issuer_lookups.empty()) {
        picojson::object failed_obj;
        for (const auto &entry : m_failed_issuer_lookups) {
            std::string sanitized_issuer =
                sanitize_issuer_for_json(entry.first);
            failed_obj[sanitized_issuer] =
                picojson::value(static_cast<double>(entry.second));
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

} // namespace internal
} // namespace scitokens
