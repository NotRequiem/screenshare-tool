#include "prefetch.hpp"
#include "prefetch_parser.hh"

void Prefetch() {
    setConsoleTextColor(Magenta);
    std::wcout << "[Minecraft Scanner] Running checks to detect executed files with Prefetch...\n";
    resetConsoleTextColor();

    // Specify the path to the Prefetch directory
    std::wstring prefetchDir = L"C:\\Windows\\Prefetch\\";

    // Ensure the directory path ends with a backslash
    if (prefetchDir.back() != L'\\') {
        prefetchDir += L'\\';
    }

    std::filesystem::path lastModifiedFile;
    std::time_t lastModifiedTime = 0;

    try {
        // Iterate through files in the Prefetch directory
        for (const auto& entry : std::filesystem::directory_iterator(prefetchDir)) {
            if (entry.is_regular_file() && entry.path().extension() == L".pf") {
                try {
                    const auto parser = prefetch_parser(entry.path().string());

                    // Check if parsing was successful and file names are retrieved
                    if (parser.success() && !parser.get_filenames_strings().empty()) {
                        // Check if the file starts with "JAVAW.EXE-" or "MINECRAFT.WINDOWS.EXE"
                        if (entry.path().filename().wstring().rfind(L"JAVAW.EXE-", 0) == 0 ||
                            entry.path().filename().wstring().rfind(L"MINECRAFT.WINDOWS.EXE", 0) == 0) {

                            // Check if the current file has a later modification time
                            auto lastWriteTime = std::filesystem::last_write_time(entry.path());
                            auto lastWriteTimeT = std::chrono::duration_cast<std::chrono::system_clock::duration>(
                                lastWriteTime.time_since_epoch()).count();
                            if (lastWriteTimeT > lastModifiedTime) {
                                lastModifiedTime = lastWriteTimeT;
                                lastModifiedFile = entry.path();
                            }
                        }
                    }
                }
                catch (...) {
                    // Handle exceptions as needed
                }
            }
        }

        // Print information from the last modified file
        if (!lastModifiedFile.empty()) {
            const auto parser = prefetch_parser(lastModifiedFile.string());
            std::wcout << L"Jar files loaded in the last Minecraft instance (check for any suspicious jar file):" << std::endl;
            for (const auto& filename : parser.get_filenames_strings())
                std::wcout << L"\t" << filename << std::endl;

            std::wcout << std::endl;
        }
    }
    catch (...) {
        // Handle exceptions as needed
    }
}