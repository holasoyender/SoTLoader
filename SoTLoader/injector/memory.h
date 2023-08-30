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

bool SetAccessControl(const char* path, const wchar_t* access)
{
	PSECURITY_DESCRIPTOR sec = nullptr;
	PACL currentAcl = nullptr;
	PSID sid = nullptr;
	PACL newAcl = nullptr;
	bool status = false;
	EXPLICIT_ACCESSW desc = { 0 };
	const wchar_t* file = reinterpret_cast<const wchar_t*>(path);

	if (GetNamedSecurityInfoW(file, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &currentAcl, nullptr, &sec) != ERROR_SUCCESS) goto EXIT;
	if (!ConvertStringSidToSidW(access, &sid)) goto EXIT;
	desc.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE | GENERIC_WRITE;
	desc.grfAccessMode = SET_ACCESS;
	desc.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	desc.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	desc.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	desc.Trustee.ptstrName = reinterpret_cast<wchar_t*>(sid);
	if (SetEntriesInAclW(1, &desc, currentAcl, &newAcl) != ERROR_SUCCESS) goto EXIT;
	if (SetNamedSecurityInfoW(const_cast<wchar_t*>(file), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, newAcl, nullptr) != ERROR_SUCCESS) goto EXIT;
	status = true;
	goto EXIT;

EXIT:
	if (newAcl) LocalFree(newAcl);
	if (sid) LocalFree(sid);
	if (sec) LocalFree(sec);
	return status;
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