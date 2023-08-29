#pragma once

bool IsModuleInProcess(DWORD processID, const wchar_t* moduleName) {
    unsigned char isModulePresent = 0;
    HANDLE snapshotHandle;
    MODULEENTRY32 moduleEntry;

    snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processID);
    if (snapshotHandle != INVALID_HANDLE_VALUE) {
        if (Module32Next(snapshotHandle, &moduleEntry)) {
            while (wcscmp(moduleEntry.szModule, moduleName)) {
                if (!Module32Next(snapshotHandle, &moduleEntry)) {
                    break;
                }
            }
            isModulePresent = 1;
        }
        CloseHandle(snapshotHandle);
    }

    return isModulePresent != 0;
}

bool IsModuleInProcess(HANDLE handle, std::string moduleName) {
	unsigned char isModulePresent = 0;
	HMODULE hMods[1024];
	DWORD cbNeeded;
	unsigned int i;

	if (EnumProcessModules(handle, hMods, sizeof(hMods), &cbNeeded)) {
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			TCHAR szModName[MAX_PATH];
			if (GetModuleFileNameEx(handle, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
				std::wstring modNameW(szModName);
				std::string modName(modNameW.begin(), modNameW.end());
				if (modName.find(moduleName) != std::string::npos) {
					isModulePresent = 1;
					break;
				}
			}
		}
	}

	return isModulePresent != 0;
}

bool UnloadModuleFromProcess(HANDLE process, std::string moduleName) {
	/*HMODULE hMods[1024];
	DWORD cbNeeded;
	unsigned int i;

	if (EnumProcessModules(process, hMods, sizeof(hMods), &cbNeeded)) {
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			TCHAR szModName[MAX_PATH];
			if (GetModuleFileNameEx(process, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
				std::wstring modNameW(szModName);
				std::string modName(modNameW.begin(), modNameW.end());
				if (modName.find(moduleName) != std::string::npos) {
					FreeLibrary(hMods[i]);
					return true;
				}
			}
		}
	}

	return false;*/

	
	HMODULE hMods[1024];
	DWORD cbNeeded;
	unsigned int i;

	if (EnumProcessModules(process, hMods, sizeof(hMods), &cbNeeded)) {
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			TCHAR szModName[MAX_PATH];
			if (GetModuleFileNameEx(process, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
				std::wstring modNameW(szModName);
				std::string modName(modNameW.begin(), modNameW.end());
				if (modName.find(moduleName) != std::string::npos) {
					HMODULE hModule = hMods[i];
					FARPROC procAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FreeLibrary");
					HANDLE thread = CreateRemoteThread(process, NULL, NULL, (LPTHREAD_START_ROUTINE)procAddress, hModule, NULL, NULL);
					if (thread != NULL) {
						WaitForSingleObject(thread, INFINITE);
						CloseHandle(thread);
						return true;
					}
				}
			}
		}
	}

	return false;
}