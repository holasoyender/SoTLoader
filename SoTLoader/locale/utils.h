#pragma once

inline std::string getSystemLang() {
    LCID lcid = GetThreadLocale();
    wchar_t name[LOCALE_NAME_MAX_LENGTH];
    wchar_t parentLocateName[LOCALE_NAME_MAX_LENGTH];
    LCIDToLocaleName(lcid, name, LOCALE_NAME_MAX_LENGTH, 0);
    GetLocaleInfoEx(name, LOCALE_SPARENT, parentLocateName, LOCALE_NAME_MAX_LENGTH);

	std::wstring langCode = std::wstring(parentLocateName);
    return std::string(langCode.begin(), langCode.end());
}