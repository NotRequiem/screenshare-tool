#include "xray.hpp"

// https://github.com/Chamzis/SimpleSSTool/blob/main/Checks/impl/Xray_check.cpp

enum class log_type { INFO, ERR, WARNING }; // Defines an enumeration for different types of log messages

static void set_global(log_type type) {} // Declares a function to set the global log type, but the implementation is empty

static void log(const std::string& message) { // Declares a function to log a message
    std::cout << message << std::endl; // Prints the message to the console
}

static std::vector<std::string> files_in_folder(const char* folder_path) { // Declares a function to retrieve files in a folder
    std::vector<std::string> files; // Declares a vector to store file names
    for (const auto& entry : std::filesystem::directory_iterator(folder_path)) { // Iterates through the folder
        if (entry.is_regular_file()) { // Checks if the entry is a regular file
            files.push_back(entry.path().string()); // Adds the file path to the vector
        }
    }
    return files; // Returns the vector of file paths
}

int passed = 0; // Declares a global variable to count the number of passed checks

void XRay(bool imp) { // Defines the main function XRay, which takes a boolean parameter imp
    set_global(log_type::INFO); // Sets the global log type to INFO

    if (!imp) {
        setConsoleTextColor(BrightMagenta);
        std::wcout << "[Mods Scanner] Running checks for xray texture packs...\n";
        resetConsoleTextColor();
    }

    const char* appdata_path;
    char* temp_appdata_path;
    errno_t err = _dupenv_s(&temp_appdata_path, nullptr, "APPDATA");
    if (err == 0 && temp_appdata_path != nullptr) {
        appdata_path = temp_appdata_path;
    }
    else {
        // Handle error case
        appdata_path = nullptr;
    }
    if (appdata_path != nullptr) { // Checks if the path is valid
        std::string res_path = std::string(appdata_path) + "\\.minecraft\\resourcepacks"; // Constructs the path to the resource packs directory
        std::vector<std::string> listFiles = files_in_folder(res_path.c_str()); // Retrieves the list of files in the resource packs directory

        bool p1 = true; // Initializes a boolean flag for the first check
        for (const std::string& s : listFiles) { // Iterates through the list of files
            if (s.find("xray") != std::string::npos || s.find("Xray") != std::string::npos || s.find("XRay") != std::string::npos) { // Checks if the file name contains "xray", "Xray", or "XRay"
                set_global(log_type::ERR); // Sets the global log type to ERR
                log("[#] Found possible XRay texture pack in %appdata% (.zip)\n"); // Logs a message indicating the presence of XRay
                p1 = false; // Sets the flag to false
                break; // Exits the loop
            }
        }

        // Similar check for directories
        if (p1) {
            for (const auto& entry : std::filesystem::directory_iterator(res_path)) {
                if (entry.is_directory() && (entry.path().string().find("xray") != std::string::npos || entry.path().string().find("Xray") != std::string::npos || entry.path().string().find("XRay") != std::string::npos)) {
                    set_global(log_type::ERR);
                    log("[#] Found possible XRay texture pack in %appdata% (folder)\n");
                    p1 = false;
                    break;
                }
            }
        }

        if (p1)
            passed++; // Increments the passed counter if the first check passed

        bool p2 = true; // Initializes a boolean flag for the second check

        // Check the content of files in the directory
        if (listFiles.size() != 0) { // Checks if the list of files is not empty
            for (std::string s : listFiles) { // Iterates through the list of files
                std::string path = res_path + "\\" + s; // Constructs the full path to the file

                // Using miniz library to read zip files
                mz_zip_archive zipArchive; // Declares a variable for the zip archive
                mz_bool status; // Declares a variable for the status of zip operations
                mz_zip_archive_file_stat fileStat; // Declares a variable for file statistics

                memset(&zipArchive, 0, sizeof(zipArchive)); // Clears the memory for the zip archive variable

                status = mz_zip_reader_init_file(&zipArchive, path.c_str(), 0); // Initializes the zip archive with the file path
                if (!status) { // Checks if initialization failed
                    return; // Exits the function
                }

                int numFiles = mz_zip_reader_get_num_files(&zipArchive); // Retrieves the number of files in the zip archive
                for (int i = 0; i < numFiles; ++i) { // Iterates through the files in the zip archive
                    status = mz_zip_reader_file_stat(&zipArchive, i, &fileStat); // Retrieves statistics for the file
                    if (!status) { // Checks if retrieval failed
                        set_global(log_type::ERR); // Sets the global log type to ERR
                        mz_zip_reader_end(&zipArchive); // Ends the zip archive reading
                        return; // Exits the function
                    }

                    std::string fileName = fileStat.m_filename; // Retrieves the file name
                    if (fileStat.m_uncomp_size < 1000000 && (fileName.size() > 5 && fileName.substr(fileName.size() - 5) == ".json")) { // Checks if the file is smaller than 1MB and ends with ".json"
                        set_global(log_type::WARNING); // Sets the global log type to WARNING
                        log("[#] Found possible XRay texture pack in %appdata% (file size): " + s + "\n"); // Logs a warning message
                        break; // Exits the loop
                    }
                }

                mz_zip_reader_end(&zipArchive); // Ends the zip archive reading
            }
        }

        if (p2)
            passed++; // Increments the passed counter if the second check passed
    }
}
