#pragma once

inline std::string CurrentPath() {
	TCHAR buffer[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, buffer, MAX_PATH);
	std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
	
	std::wstring path = std::wstring(buffer).substr(0, pos);
	return std::string(path.begin(), path.end());
}

inline std::vector<std::string> GetFilesInDirectory( const std::string& directory ) {
	std::vector<std::string> files;
	for (const auto& entry : std::filesystem::directory_iterator(directory)) {
		files.push_back(entry.path().string());
	}
	return files;
}

inline std::vector<std::string> GetFilesInDirectoryWithExtension(const std::string& directory, const std::string& extension) {
	std::vector<std::string> files;
	for (const auto& entry : std::filesystem::directory_iterator(directory)) {
		if (entry.path().extension() == extension) {
			files.push_back(entry.path().string());
		}
	}
	return files;
}