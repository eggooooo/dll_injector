#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <chrono>

bool inject_dll(HANDLE h_process, const std::wstring& dll_path, DWORD wait_ms) {
    std::wcout << L"\n=== Injecting DLL: " << dll_path << L" ===" << std::endl;

    if (wait_ms > 0) {
        Sleep(wait_ms);
    }

    SIZE_T alloc_size = (dll_path.length() + 1) * sizeof(wchar_t);
    std::wcout << L"[+] Allocating " << alloc_size << L" bytes in target process..." << std::endl;
    LPVOID p_dll_path = VirtualAllocEx(h_process, NULL, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p_dll_path) {
        std::wcerr << L"[-] Failed to allocate memory. Error: " << GetLastError() << std::endl;
        system("pause");
        return false;
    }
    std::wcout << L"[+] Memory allocated at address: 0x" << std::hex << (DWORD_PTR)p_dll_path << std::dec << std::endl;

    std::wcout << L"[+] Writing DLL path to target process memory..." << std::endl;
    if (!WriteProcessMemory(h_process, p_dll_path, dll_path.c_str(), alloc_size, NULL)) {
        std::wcerr << L"[-] Failed to write DLL path. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(h_process, p_dll_path, 0, MEM_RELEASE);
        system("pause");
        return false;
    }
    std::wcout << L"[+] DLL path written successfully." << std::endl;

    HMODULE h_kernel32 = GetModuleHandle(L"kernel32.dll");
    LPVOID p_load_library_w = GetProcAddress(h_kernel32, "LoadLibraryW");
    if (!p_load_library_w) {
        std::wcerr << L"[-] Failed to get LoadLibraryW address. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(h_process, p_dll_path, 0, MEM_RELEASE);
        system("pause");
        return false;
    }
    std::wcout << L"[+] LoadLibraryW address: 0x" << std::hex << (DWORD_PTR)p_load_library_w << std::dec << std::endl;

    std::wcout << L"[+] Creating remote thread..." << std::endl;
    auto start_time = std::chrono::high_resolution_clock::now();
    HANDLE h_thread = CreateRemoteThread(h_process, NULL, 0,
        (LPTHREAD_START_ROUTINE)p_load_library_w,
        p_dll_path, 0, NULL);
    if (!h_thread) {
        std::wcerr << L"[-] Failed to create remote thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(h_process, p_dll_path, 0, MEM_RELEASE);
        system("pause");
        return false;
    }

    std::wcout << L"[+] Remote thread created. Waiting for it to complete..." << std::endl;
    WaitForSingleObject(h_thread, INFINITE);
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end_time - start_time;
    std::wcout << L"[+] Remote thread finished in " << duration.count() << L" seconds." << std::endl;

    CloseHandle(h_thread);
    VirtualFreeEx(h_process, p_dll_path, 0, MEM_RELEASE);
    std::wcout << L"[+] Memory released. DLL injection completed: " << dll_path << std::endl;

    return true;
}

DWORD get_process_id(const std::wstring& process_name) {
    std::wcout << L"[+] Searching for process: " << process_name << std::endl;
    DWORD process_id = 0;
    HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h_snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32{};
        pe32.dwSize = sizeof(pe32);
        if (Process32FirstW(h_snapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, process_name.c_str()) == 0) {
                    process_id = pe32.th32ProcessID;
                    std::wcout << L"[+] Found process ID: " << process_id << std::endl;
                    break;
                }
            } while (Process32NextW(h_snapshot, &pe32));
        }
        CloseHandle(h_snapshot);
    }

    if (process_id == 0) {
        std::wcout << L"[-] Process not found." << std::endl;
    }
    return process_id;
}

int wmain() {
    std::wifstream config("config.inj");
    if (!config) {
        std::wcerr << L"[-] Failed to open config.inj" << std::endl;
        std::wcerr << L"=============================" << std::endl;
        std::wcerr << L"Create a 'config.inj' file in the same directory as the injector executable, using these parameters:" << std::endl;
        std::wcerr << L"" << std::endl;
        std::wcerr << L"inject_wait=2000         ; wait before injecting each DLL (ms)" << std::endl;
        std::wcerr << L"init_wait=6000           ; wait after starting the target executable(ms)" << std::endl;
        std::wcerr << L"path\\to\\program.exe      ; target executable" << std::endl;
        std::wcerr << L"path\\to\\1.dll            ; DLLs to inject in line sequence" << std::endl;
		std::wcerr << L"path\\to\\2.dll" << std::endl;
        std::wcerr << L"path\\to\\3.dll" << std::endl;
        system("pause");
        return 1;
    }

    DWORD inject_wait = 0;
    DWORD init_wait = 6000;
    std::wstring game_path;
    std::vector<std::wstring> dll_paths;
    std::wstring line;

    while (std::getline(config, line)) {
        if (line.empty()) continue;

        if (line.rfind(L"inject_wait=", 0) == 0) {
            try { inject_wait = std::stoul(line.substr(12)); }
            catch (...) {}
        }
        else if (line.rfind(L"init_wait=", 0) == 0) {
            try { init_wait = std::stoul(line.substr(10)); }
            catch (...) {}
        }
        else if (game_path.empty()) {
            game_path = line;
        }
        else {
            dll_paths.push_back(line);
        }
    }

    if (game_path.empty()) {
        std::wcerr << L"[-] Target executable path not specified in config.inj" << std::endl;
        system("pause");
        return 1;
    }

    if (dll_paths.empty()) {
        std::wcerr << L"[-] No DLL paths specified in config.inj" << std::endl;
        system("pause");
        return 1;
    }

    size_t pos = game_path.find_last_of(L"\\/");
    std::wstring target_process_name = (pos != std::wstring::npos) ? game_path.substr(pos + 1) : game_path;

    DWORD process_id = get_process_id(target_process_name);

    if (process_id == 0) {
        std::wcout << L"[+] Process not running. Starting target executable: " << game_path << std::endl;
        STARTUPINFO si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof(si);

        if (!CreateProcessW(game_path.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            std::wcerr << L"[-] Failed to start target executable. Error: " << GetLastError() << std::endl;
            system("pause");
            return 1;
        }

        std::wcout << L"[+] Target executable started. Waiting " << init_wait << L" ms for initialization..." << std::endl;
        Sleep(init_wait);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        process_id = get_process_id(target_process_name);
        if (process_id == 0) {
            std::wcerr << L"[-] Could not find running process after wait." << std::endl;
            system("pause");
            return 1;
        }
    }

    std::wcout << L"[+] Opening handle to process ID " << process_id << std::endl;
    HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (!h_process) {
        std::wcerr << L"[-] Failed to open process. Error: " << GetLastError() << std::endl;
        system("pause");
        return 1;
    }

    std::wcout << L"[+] Starting DLL injections with inject_wait = " << inject_wait << L" ms..." << std::endl;
    for (const auto& dll : dll_paths) {
        if (!inject_dll(h_process, dll, inject_wait)) {
            std::wcerr << L"[-] Failed to inject DLL: " << dll << std::endl;
            system("pause");
            return 1;
        }
    }

    CloseHandle(h_process);
    std::wcout << L"[+] All DLLs processed. Exiting." << std::endl;
    return 0;
}
