#pragma once

inline BOOL IsAdmin()
{
    BOOL fRet = FALSE;
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize))
        {
            fRet = elevation.TokenIsElevated;
        }
    }
    if (hToken)
    {
        CloseHandle(hToken);
    }
    return fRet;
}