#include "stdafx.h"

#include "utils/logger.h"
#include "injector/memory.h"
#include "injector/files.h"
#include "utils/access.h"

#define COMPILATION_DATE __DATE__ " " __TIME__

int main(int argc, char* argv[])
{

    const char* GAME_NAME = "Sea of Thieves";
    std::string dll_name;
    DWORD processID = 0;
    HANDLE process;
    HRESULT hr = S_OK;
    HWND hwndproc = FindWindowA(NULL, GAME_NAME);

    LPVOID allocatedMem;
    HANDLE thread;

    SetConsoleTitle(L"Sea of Thieves DLL Loader - " COMPILATION_DATE);

    std::vector<std::string> dlls = GetFilesInDirectoryWithExtension(CurrentPath(), ".dll");

    switch (dlls.size()) {
        {
    case 0:
        logger::error("No DLLs found in current directory, please place DLLs in the same directory as this executable.");
        goto EXIT;
        }
    case 1:
        logger::info("Found 1 DLL: ", dlls[0]);
        dll_name = dlls[0];
        break;
    default:
        std::string dlls_names_list = "";

        for (int i = 0; i < dlls.size(); i++) {
            std::string dll_name = dlls[i].substr(dlls[i].find_last_of("\\") + 1);
            std::string pos = std::to_string(i + 1);
            dlls_names_list += pos + ". " + dll_name + "\n";
        }

        logger::warn("Found more than 1 DLL, please select one:\n", dlls_names_list);

        std::cout << "Enter DLL index: ";

        int dll_index = 0;
        std::cin >> dll_index;
        dll_name = dlls[dll_index - 1];
        break;
    }

    logger::info("Loading DLL: ", dll_name.substr(dll_name.find_last_of("\\") + 1), "...");

    if (hwndproc == NULL)
    {
        logger::error("Game not found, please check that the game is running and try again.");
        goto EXIT;
    }

    hr = GetWindowThreadProcessId(hwndproc, &processID);
    if (FAILED(hr)) {
        logger::error("Failed to get process ID, HRESULT: ", hr);
        goto EXIT;
    }

    logger::info("Process \"", GAME_NAME, "\" found with ID: ", processID);

    if (!IsAdmin()) {
		logger::error("Please run this program as administrator.");
		goto EXIT;
	}

    process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processID);
    if (process == NULL) {
        auto Error = GetLastError();
        logger::error("Failed to open process, HRESULT: ", hr, " Error: ", Error);
        goto EXIT;
    }

    if (IsModuleInProcess(process, dll_name)) {
        logger::error("That DLL is already loaded in the process. Do you want to unload it? (y/n)");
        char unload;
        std::cin >> unload;

        if (unload == 'y' || unload == 'Y' || unload == 's' || unload == 'S') {
            if (!UnloadModuleFromProcess(process, dll_name)) {
				logger::error("Failed to unload DLL, HRESULT: ", hr);
				goto EXIT;
			}
            logger::info("DLL unloaded successfully, reloading...");
		}
        else {
			logger::info("DLL not loaded.");
			goto EXIT;
		}
    }

    char dll_name_char[256];
    strcpy_s(dll_name_char, dll_name.c_str());

    allocatedMem = VirtualAllocEx(process, NULL, sizeof(dll_name_char), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (allocatedMem == NULL) {
        logger::error("Failed to allocate memory in process, HRESULT: ", hr);
        goto EXIT;
    }

    if (!WriteProcessMemory(process, allocatedMem, dll_name_char, sizeof(dll_name_char), NULL)) {
        logger::error("Failed to write to process memory, HRESULT: ", hr);
        goto EXIT;
    }

    thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocatedMem, 0, NULL);
    if (thread == NULL) {
        logger::error("Failed to create remote thread, HRESULT: ", hr);
        goto EXIT;
    }

    if (WaitForSingleObject(thread, INFINITE) == WAIT_FAILED) {
		logger::error("Failed to wait for thread, HRESULT: ", hr);
		goto EXIT;
	}

    logger::info("DLL loaded successfully!");
    
    if (thread != NULL)
        CloseHandle(thread);
    if (process != NULL)
		CloseHandle(process);
    if (hwndproc != NULL)
        CloseHandle(hwndproc);
    if (allocatedMem != NULL)
        CloseHandle(allocatedMem);

    goto EXIT;

EXIT:
    system("pause");
    return 0;
}