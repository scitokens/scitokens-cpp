#ifndef SCITOKENS_TEST_UTILS_H
#define SCITOKENS_TEST_UTILS_H

#include <climits>
#include <cstdlib>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace scitokens_test {

/**
 * Helper class to create and manage secure temporary directories.
 * Uses mkdtemp for security and cleans up on destruction.
 *
 * Example usage:
 *   SecureTempDir temp_dir("my_test_");
 *   ASSERT_TRUE(temp_dir.valid());
 *   std::string cache_path = temp_dir.path() + "/cache";
 *   // ... use the directory ...
 *   // Directory is automatically cleaned up when temp_dir goes out of scope
 */
class SecureTempDir {
  public:
    /**
     * Create a temp directory under the specified base path.
     * @param prefix Prefix for the directory name (default: "scitokens_test_")
     * @param base_path Base path for the temp directory. If empty, uses
     *                  BINARY_DIR/tests (from CMake) or falls back to cwd/tests
     */
    explicit SecureTempDir(const std::string &prefix = "scitokens_test_",
                           const std::string &base_path = "") {
        std::string base = base_path;
        if (base.empty()) {
            // Try to use build/tests directory (set by CMake)
            const char *binary_dir = std::getenv("BINARY_DIR");
            if (binary_dir) {
                base = std::string(binary_dir) + "/tests";
            } else {
                // Fallback: use current working directory + tests
                char *cwd = getcwd(nullptr, 0);
                if (cwd) {
                    base = std::string(cwd) + "/tests";
                    free(cwd);
                } else {
                    base = "/tmp"; // Last resort fallback
                }
            }
        }

        // Ensure base directory exists
        mkdir(base.c_str(), 0700);

        // Create template for mkdtemp
        std::string tmpl = base + "/" + prefix + "XXXXXX";
        std::vector<char> tmpl_buf(tmpl.begin(), tmpl.end());
        tmpl_buf.push_back('\0');

        char *result = mkdtemp(tmpl_buf.data());
        if (result) {
            path_ = result;
        }
    }

    ~SecureTempDir() { cleanup(); }

    // Delete copy constructor and assignment
    SecureTempDir(const SecureTempDir &) = delete;
    SecureTempDir &operator=(const SecureTempDir &) = delete;

    // Allow move
    SecureTempDir(SecureTempDir &&other) noexcept
        : path_(std::move(other.path_)) {
        other.path_.clear();
    }

    SecureTempDir &operator=(SecureTempDir &&other) noexcept {
        if (this != &other) {
            cleanup();
            path_ = std::move(other.path_);
            other.path_.clear();
        }
        return *this;
    }

    /** Get the path to the temporary directory */
    const std::string &path() const { return path_; }

    /** Check if the directory was created successfully */
    bool valid() const { return !path_.empty(); }

    /** Manually trigger cleanup (also called by destructor) */
    void cleanup() {
        if (!path_.empty()) {
            remove_directory_recursive(path_);
            path_.clear();
        }
    }

  private:
    std::string path_;

    /**
     * Safely remove a directory recursively using fork/execv.
     * This prevents shell injection attacks that could occur with system().
     */
    static void remove_directory_recursive(const std::string &path) {
        pid_t pid = fork();
        if (pid == 0) {
            // Child process: exec rm -rf with path as direct argument
            // Using execv prevents any shell interpretation of the path
            char *const args[] = {const_cast<char *>("rm"),
                                  const_cast<char *>("-rf"),
                                  const_cast<char *>(path.c_str()), nullptr};
            execv("/bin/rm", args);
            _exit(1); // execv failed
        } else if (pid > 0) {
            // Parent: wait for child to complete
            int status;
            waitpid(pid, &status, 0);
        }
        // If fork failed, silently ignore (cleanup is best-effort)
    }
};

} // namespace scitokens_test

#endif // SCITOKENS_TEST_UTILS_H
