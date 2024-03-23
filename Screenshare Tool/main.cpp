#include "main.hpp"

int main(int argc, char* argv[]) {
    using namespace Checks;

    StartTool();

    std::vector<std::shared_ptr<Check>> checks = []() {
        return std::vector<std::shared_ptr<Check>> {
            std::make_shared<MacroStringsCheck>(),
                std::make_shared<ExecutedFilesCheck>(),
                std::make_shared<USNJournalClearedCheck>(),
                std::make_shared<SystemTimeChangeCheck>(),
                std::make_shared<SystemInformerCheck>(),
                std::make_shared<RestartedProcessesCheck>(),
                std::make_shared<EventlogBypassCheck>(),
                std::make_shared<LocalHostCheck>(),
                std::make_shared<BamCheck>(),
                std::make_shared<ReplacedDisksCheck>(),
                std::make_shared<TaskSchedulerCheck>(),
                std::make_shared<PrefetchCheck>(),
                std::make_shared<RecentFilesCheck>(),
                std::make_shared<AppCrashCheck>(),
                std::make_shared<JavawCheck>(),
                std::make_shared<XRayCheck>(),
                std::make_shared<ImportCodeCheck>(),
                std::make_shared<UnpluggedDevicesCheck>(),
                std::make_shared<MouseKeysCheck>(),
                std::make_shared<MiceCheck>(),
                std::make_shared<VirtualMachineCheck>(),
                std::make_shared<CsrssCheck>(),
                std::make_shared<USNJournalCheck>(),
                std::make_shared<MacrosCheck>()
        };
        }();

        auto findImpFlag = [&argc, &argv]() {
            return std::find_if(argv, argv + argc, [](const char* arg) {
                return std::strcmp(arg, "-i") == 0 || std::strcmp(arg, "-I") == 0;
                }) != argv + argc;
            };

        bool imp = findImpFlag();

        for (const auto& check : checks) {
            check->runCheck(imp);
        }

        ExecuteHookCode();

        return 0;
}
