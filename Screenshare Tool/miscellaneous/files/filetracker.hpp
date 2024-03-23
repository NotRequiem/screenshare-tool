#ifndef FILETRACKER_HPP
#define FILETRACKER_HPP

/**
 * @file FileTracker.hpp
 * @brief Declaration of the FileTracker class for managing processed file paths.
 */

#include <unordered_set>    // std::unordered_set
#include <string>           // std::wstring
#include <string_view>      // std::wstring_view
#include <filesystem>       // std::filesystem

namespace screenshare_tool {

    namespace fs = std::filesystem;

    /**
     * @brief A utility class for tracking processed file paths.
     *
     * This class provides functionality to track processed file paths
     * to avoid redundant processing.
     */
    class FileTracker {
    public:
        // Prevent copying and moving
        FileTracker(const FileTracker&) = delete;
        FileTracker& operator=(const FileTracker&) = delete;
        FileTracker(FileTracker&&) = delete;
        FileTracker& operator=(FileTracker&&) = delete;

        /**
         * @brief Initializes the FileTracker with an expected number of files.
         * @param expected_files The expected number of files to be processed.
         * @note This function can be used to reserve memory for efficient storage.
         */
        static void initialize(std::size_t expected_files = 0) noexcept {
            // Reserve memory for expected number of files
            processedFiles.reserve(expected_files);
        }

        /**
         * @brief Adds a processed file path to the tracker.
         * @param filename The file path to be added.
         */
        static void addProcessedFile(const std::wstring& filename) {
            // Add the filename to the set of processed files
            processedFiles.emplace(filename);
        }

        /**
         * @brief Checks if a file path has been processed.
         * @param filename The file path to be checked.
         * @return true if the file path has been processed, false otherwise.
         */
        static bool isFileProcessed(std::wstring_view filename) noexcept {
            // Check if the filename is in the set of processed files
            return processedFiles.find(std::wstring(filename)) != processedFiles.end();
        }

    private:
        static std::unordered_set<std::wstring> processedFiles;
    };

}

#endif