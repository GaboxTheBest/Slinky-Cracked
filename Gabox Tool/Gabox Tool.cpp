#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <urlmon.h>
#include <shlwapi.h>
#include <string>
#include <thread>
#include <chrono>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "shlwapi.lib")

DWORD GetProcessIdByName(const wchar_t* processName) {
    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (wcscmp(processEntry.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

bool InjectDLL(DWORD processId, const wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) return false;

    LPVOID allocMem = VirtualAllocEx(hProcess, NULL, (wcslen(dllPath) + 1) * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
    if (!allocMem) {
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, allocMem, dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t), NULL)) {
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC loadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocMem, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}

bool DeleteFileWithRetry(const wchar_t* filePath) {
    for (int i = 0; i < 5; ++i) {
        if (DeleteFileW(filePath)) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return false;
}

void SetConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

int main() {
    SetConsoleTitleW(L"Injector Cheat Minecraft - By gab0x");
    system("cls");
    SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);

    std::wcout << L"    ____           ______      __              " << std::endl;
    std::wcout << L"   / __ )__  __   / ____/___ _/ /_  ____  _  __" << std::endl;
    std::wcout << L"  / __  / / / /  / / __/ __ `/ __ \\/ __ \\| |/_/" << std::endl;
    std::wcout << L" / /_/ / /_/ /  / /_/ / /_/ / /_/ / /_/ />  <  " << std::endl;
    std::wcout << L"/_____/_\\__, /   \\____/_\\__,_/_.___/\\____/_/|_|  " << std::endl;
    std::wcout << L"      /____/                                  " << std::endl;

    std::wcout << L"Injectando cheats..." << std::endl;
    std::wcout << L"Espera unos segundos" << std::endl;

    wchar_t wDllPath1[MAX_PATH];
    wchar_t wDllPath2[MAX_PATH];
    wchar_t hiddenDir[MAX_PATH];
    GetModuleFileNameW(NULL, hiddenDir, MAX_PATH);
    PathRemoveFileSpecW(hiddenDir);
    wcscat_s(hiddenDir, MAX_PATH, L"\\.");
    CreateDirectoryW(hiddenDir, NULL);
    SetFileAttributesW(hiddenDir, FILE_ATTRIBUTE_HIDDEN);

    wcscpy_s(wDllPath1, hiddenDir);
    wcscpy_s(wDllPath2, hiddenDir);
    wcscat_s(wDllPath1, MAX_PATH, L"\\gcapi.dll");
    wcscat_s(wDllPath2, MAX_PATH, L"\\slinky_library.dll");

    const wchar_t* dllUrl1 = L"https://gaboxtv.com/gcapi.dll"; // Reemplaza con la URL correcta
    const wchar_t* dllUrl2 = L"https://gaboxtv.com/slinky_library.dll"; // Reemplaza con la URL correcta

    // Descargar las DLLs
    HRESULT hr1 = URLDownloadToFileW(NULL, dllUrl1, wDllPath1, 0, NULL);
    HRESULT hr2 = URLDownloadToFileW(NULL, dllUrl2, wDllPath2, 0, NULL);

    if (hr1 != S_OK) {
        std::wcout << L"Error al descargar gcapi.dll. Contactar a gab0x. Código de error: " << hr1 << std::endl;
        return 1;
    }
    if (hr2 != S_OK) {
        std::wcout << L"Error al descargar slinky_library.dll. Contactar a gab0x. Código de error: " << hr2 << std::endl;
        return 1;
    }

    DWORD processId = GetProcessIdByName(L"javaw.exe");
    if (processId == 0) {
        std::wcout << L"No se encontró el proceso javaw.exe." << std::endl;
        return 1;
    }
    bool injectSuccess1 = InjectDLL(processId, wDllPath1);
    bool injectSuccess2 = InjectDLL(processId, wDllPath2);

    if (injectSuccess1 && injectSuccess2) {
        std::wcout << L"Se han inyectado los cheats correctamente." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));

        // Intentar eliminar las DLLs
        if (DeleteFileWithRetry(wDllPath1)) {
            std::wcout << L"gcapi.dll eliminada exitosamente." << std::endl;
        }
        else {
            std::wcout << L"Error al eliminar gcapi.dll: " << GetLastError() << std::endl;
        }

        if (DeleteFileWithRetry(wDllPath2)) {
            std::wcout << L"slinky_library.dll eliminada exitosamente." << std::endl;
        }
        else {
            std::wcout << L"Error al eliminar slinky_library.dll: " << GetLastError() << std::endl;
        }
    }
    else {
        std::wcout << L"Error al inyectar las DLLs." << std::endl;
    }

    return 0;
}
