#include "stdafx.h"

#include "utils/logger.h"
#include "injector/memory.h"
#include "injector/files.h"
#include "utils/access.h"
#include "locale/locale.h"

#define COMPILATION_DATE __DATE__ " " __TIME__

int start() {

    const char* GAME_NAME = "Sea of Thieves";
    std::string dll_name;
    DWORD processID = 0;
    HANDLE process;
    HRESULT hr = S_OK;
    HWND hwndproc = FindWindowA(NULL, GAME_NAME);

    LPVOID allocatedMem;
    HANDLE thread;

    std::vector<std::string> dlls;

    SetConsoleTitle(L"Sea of Thieves DLL Loader - " COMPILATION_DATE);

    if (!std::filesystem::exists("logs")) {
        std::filesystem::create_directory("logs");
    }

    if (!std::filesystem::exists("locale")) {
        logger::error("The \"locale\" directory is missing, please download the latest release from https://github.com/holasoyender/SoTLoader");
        system("pause");
        return 0;
    }

    std::string langCode = getSystemLang();
    logger::info("Detected system language: ", langCode);
    Locale lang(langCode);

    if (!std::filesystem::exists("libs")) {
        std::filesystem::create_directory("libs");
        logger::info(lang.get("created_libs_folder"));
        goto EXIT;
    }

    dlls = GetFilesInDirectoryWithExtension(CurrentPath() + "\\libs", ".dll");

    switch (dlls.size()) {
        {
    case 0:
        logger::error(lang.get("no_dlls_found"));
        goto EXIT;
        }
    case 1:
        logger::info(lang.get("found_one"), dlls[0]);
        dll_name = dlls[0];
        break;
    default:
        std::string dlls_names_list = "";

        for (int i = 0; i < dlls.size(); i++) {
            std::string dll_name = dlls[i].substr(dlls[i].find_last_of("\\") + 1);
            std::string pos = std::to_string(i + 1);
            dlls_names_list += pos + ". " + dll_name + "\n";
        }

        logger::warn(lang.get("found_multiple"), dlls_names_list);

        std::cout << lang.get("input_index");

        int dll_index = 0;
        std::cin >> dll_index;
        dll_name = dlls[dll_index - 1];
        break;
    }

    logger::info(lang.get("loading_dll"), dll_name.substr(dll_name.find_last_of("\\") + 1), "...");

    if (hwndproc == NULL)
    {
        logger::error(lang.get("fail_game_not_found"));
        goto EXIT;
    }

    hr = GetWindowThreadProcessId(hwndproc, &processID);
    if (FAILED(hr)) {
        logger::error(lang.get("fail_process_id"), hr);
        goto EXIT;
    }

    logger::info(lang.get("found_process_id"), processID, " (", GAME_NAME, ")");

    if (!IsAdmin()) {
        logger::error(lang.get("fail_admin"));
        goto EXIT;
    }

    process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processID);
    if (process == NULL) {
        auto Error = GetLastError();
        logger::error(lang.get("fail_open_process"), ", HRESULT: ", hr, " Error: ", Error);
        goto EXIT;
    }

    if (IsModuleInProcess(process, dll_name)) {
        logger::error(lang.get("fail_already_loaded"), " (y/n)");
        char unload;
        std::cin >> unload;

        if (unload == 'y' || unload == 'Y' || unload == 's' || unload == 'S') {
            if (!UnloadModuleFromProcess(process, dll_name)) {
                logger::error(lang.get("fail_unload"), ", HRESULT: ", hr);
                goto EXIT;
            }

            logger::info(lang.get("dll_unloaded"), " (y/n)");
            char load;
            std::cin >> load;

            if (load != 'y' && load != 'Y' && load != 's' && load != 'S') {
                goto EXIT;
            }
        }
        else {
            logger::info(lang.get("dll_not_unloaded"));
            goto EXIT;
        }
    }

    char dll_name_char[256];
    strcpy_s(dll_name_char, dll_name.c_str());

    if (SetAccessControl(dll_name.c_str(), L"S-1-15-2-1") == false) {
        logger::error(lang.get("fail_set_access_control"), ", HRESULT: ", hr);
    }

    allocatedMem = VirtualAllocEx(process, NULL, sizeof(dll_name_char), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (allocatedMem == NULL) {
        logger::error(lang.get("fail_malloc"), ", HRESULT: ", hr);
        goto EXIT;
    }

    if (!WriteProcessMemory(process, allocatedMem, dll_name_char, sizeof(dll_name_char), NULL)) {
        logger::error(lang.get("fail_write_memory"), ", HRESULT: ", hr);
        goto EXIT;
    }

    thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocatedMem, 0, NULL);
    if (thread == NULL) {
        logger::error(lang.get("fail_create_thread"), ", HRESULT: ", hr);
        goto EXIT;
    }

    if (WaitForSingleObject(thread, INFINITE) == WAIT_FAILED) {
        logger::error(lang.get("fail_thread_wait"), ", HRESULT: ", hr);
        goto EXIT;
    }

    if (VirtualFreeEx(process, allocatedMem, 0, MEM_RELEASE) == 0) {
        logger::error(lang.get("fail_free_memory"), ", HRESULT: ", hr);
        goto EXIT;
    }

    logger::info(lang.get("dll_loaded"));

    if (thread != NULL)
        CloseHandle(thread);
    if (process != NULL)
        CloseHandle(process);
    if (hwndproc != NULL)
        CloseHandle(hwndproc);

    goto EXIT;

EXIT:
    system("pause");
    return 0;
}

int main(int argc, char* argv[])
{
    __security_init_cookie();
    start();
}