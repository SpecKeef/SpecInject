#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <Windows.h>
#include <TlHelp32.h>
#include <conio.h>

enum class InjectionMethod {
    LoadLibrary,
    ManualMapping
};

struct InjectionInfo {
    DWORD processId;
    std::wstring dllPath;
};

bool InjectDLL(DWORD processId, const std::wstring& dllPath, InjectionMethod method) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        std::cout << "\033[1;35m[SpecInject]\033[0m \033[1;31m[ERROR]\033[0m Failed to open the target process. Error code: " << GetLastError() << std::endl;
        return false;
    }

    LPVOID dllPathAddress = VirtualAllocEx(hProcess, NULL, (dllPath.size() + 1) * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
    if (dllPathAddress == NULL) {
        std::cout << "\033[1;35m[SpecInject]\033[0m \033[1;31m[ERROR]\033[0m Failed to allocate memory in the target process. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, dllPathAddress, dllPath.c_str(), (dllPath.size() + 1) * sizeof(wchar_t), NULL)) {
        std::cout << "\033[1;35m[SpecInject]\033[0m \033[1;31m[ERROR]\033[0m Failed to write DLL path into the target process. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32 == NULL) {
        std::cout << "\033[1;35m[SpecInject]\033[0m \033[1;31m[ERROR]\033[0m Failed to load kernel32.dll. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    FARPROC loadLibraryAddress = GetProcAddress(kernel32, "LoadLibraryW");
    if (loadLibraryAddress == NULL) {
        std::cout << "\033[1;35m[SpecInject]\033[0m \033[1;31m[ERROR]\033[0m Failed to get the address of LoadLibraryW function. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hRemoteThread = nullptr;

    if (method == InjectionMethod::LoadLibrary) {
        hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddress), dllPathAddress, 0, NULL);
    }
    else {
        // Manual Mapping Injection

        // Read the DLL file
        std::ifstream dllFile(dllPath, std::ios::binary | std::ios::ate);
        if (!dllFile.is_open()) {
            std::wcout << L"[SpecInject] [ERROR] Failed to read the DLL file: " << dllPath << std::endl;
            VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        std::streamsize fileSize = dllFile.tellg();
        dllFile.seekg(0, std::ios::beg);

        std::vector<BYTE> dllBuffer(fileSize);
        if (!dllFile.read(reinterpret_cast<char*>(dllBuffer.data()), fileSize)) {
            std::wcout << L"[SpecInject] [ERROR] Failed to read the DLL file: " << dllPath << std::endl;
            dllFile.close();
            VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;

        }

        dllFile.close();

        // Allocate memory in the target process
        LPVOID dllMemory = VirtualAllocEx(hProcess, NULL, dllBuffer.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (dllMemory == NULL) {
            std::cout << "\033[1;35m[SpecInject]\033[0m \033[1;31m[ERROR]\033[0m Failed to allocate memory in the target process. Error code: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Write the DLL buffer into the target process
        if (!WriteProcessMemory(hProcess, dllMemory, dllBuffer.data(), dllBuffer.size(), NULL)) {
            std::cout << "\033[1;35m[SpecInject]\033[0m \033[1;31m[ERROR]\033[0m Failed to write the DLL buffer into the target process. Error code: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, dllMemory, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Create a new thread in the target process to execute the injected DLL
        hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(dllMemory), NULL, 0, NULL);
    }

    if (hRemoteThread == NULL) {
        std::cout << "\033[1;35m[SpecInject]\033[0m \033[1;31m[ERROR]\033[0m Failed to create a remote thread in the target process. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "\033[1;35m[SpecInject]\033[0m \033[1;32m[SUCCESS]\033[0m DLL injected successfully." << std::endl;

    WaitForSingleObject(hRemoteThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(hRemoteThread, &exitCode);
    CloseHandle(hRemoteThread);

    VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return exitCode != 0;
}

bool IsFileExists(const std::wstring& filePath) {
    DWORD fileAttributes = GetFileAttributesW(filePath.c_str());
    return (fileAttributes != INVALID_FILE_ATTRIBUTES && !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY));
}

void PrintFadingText(const std::string& text, int delay) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    int fadeColors[] = { 13, 10, 11, 14, 15, 7 }; // Gradient of fade colors
    int numColors = sizeof(fadeColors) / sizeof(fadeColors[0]);

    int textLength = text.length();
    for (int i = 0; i < textLength; i++) {
        int colorIndex = static_cast<int>((static_cast<double>(i) / textLength) * numColors);
        int color = fadeColors[colorIndex];

        SetConsoleTextAttribute(hConsole, color);
        std::cout << text[i];
        Sleep(delay);
    }

    SetConsoleTextAttribute(hConsole, 7); // Reset text color to default (white)
}
void ClearConsole() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD coord = { 0, 0 };
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD written;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    FillConsoleOutputCharacter(hConsole, ' ', csbi.dwSize.X * csbi.dwSize.Y, coord, &written);
    SetConsoleCursorPosition(hConsole, coord);
}

void ShowMenu() {
    std::cout << "\n\033[1;35m[SpecInject]\033[0m Select an option:\n";
    std::cout << "1. Inject DLL into a specific process\n";
    std::cout << "2. Inject DLL into all processes with matching names\n";
    std::cout << "3. Exit\n";
    std::cout << "\033[1;35m[SpecInject]\033[0m Enter your choice: ";
}

void PerformInjection(const InjectionInfo& injectionInfo, InjectionMethod method) {
    std::cout << "\033[1;35m------------------------------------------------------\033[0m" << std::endl;
    std::wcout << L"\033[1;35m[SpecInject]\033[0m Injecting DLL: " << injectionInfo.dllPath.c_str() << std::endl;


    if (InjectDLL(injectionInfo.processId, injectionInfo.dllPath, method)) {
        std::cout << "\033[1;35m[SpecInject]\033[0m \033[1;32m[SUCCESS]\033[0m DLL injected successfully!" << std::endl;
    }
    else {
        std::cout << "\033[1;35m[SpecInject]\033[0m \033[1;31m[ERROR]\033[0m DLL injection failed." << std::endl;
    }
}

void TypingAnimation(const std::string& text) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    std::string animatedText = text;
    animatedText += "_";

    for (char c : animatedText) {
        std::cout << c;
        Sleep(40);
        std::cout << "\b \b";
        Sleep(40);
    }
}

int main() {
    std::vector<InjectionInfo> injectionInfoList;
    InjectionMethod injectionMethod = InjectionMethod::LoadLibrary;

    // Print ASCII art
    PrintFadingText("    ____  _     _     _       ____                 \n", 30);
    PrintFadingText("   / ___|| |__ (_)_ _| |__   | __ ) _ __ __ _ _ __ \n", 30);
    PrintFadingText("   \\___ \\| '_ \\| | | | '_ \\  |  _ \\| '__/ _` | '__|\n", 30);
    PrintFadingText("    ___) | | | | | | | | | | | |_) | | | (_| | |   \n", 30);
    PrintFadingText("   |____/|_| |_|_|___|_| |_| |____/|_|  \\__,_|_|   \n", 30);
    std::cout << std::endl;

    // Print welcome message
    PrintFadingText("\033[1;35m[SpecInject]\033[0m Welcome to SpecInject - DLL Injector\n", 20);
    std::cout << std::endl;

    while (true) {
        ClearConsole();
        ShowMenu();

        char choice = _getch();
        std::cout << choice << std::endl;

        switch (choice) {
        case '1': {
            // Inject DLL into a specific process
            std::cout << "\033[1;35m[SpecInject]\033[0m Enter the process ID: ";
            std::string processIdStr;
            getline(std::cin, processIdStr);
            DWORD processId = std::stoi(processIdStr);

            std::cout << "\033[1;35m[SpecInject]\033[0m Enter the path of the DLL to inject: ";
            std::wstring dllPath;
            getline(std::wcin, dllPath);

            if (!IsFileExists(dllPath)) {
                std::cout << "\033[1;35m[SpecInject]\033[0m \033[1;31m[ERROR]\033[0m The specified DLL path does not exist." << std::endl;
                break;
            }

            InjectionInfo injectionInfo;
            injectionInfo.processId = processId;
            injectionInfo.dllPath = dllPath;

            std::cout << "\033[1;35m[SpecInject]\033[0m Select injection method:\n";
            std::cout << "1. LoadLibrary\n";
            std::cout << "2. Manual Mapping\n";
            std::cout << "Enter your choice: ";

            char methodChoice = _getch();
            std::cout << methodChoice << std::endl;

            if (methodChoice == '2') {
                injectionMethod = InjectionMethod::ManualMapping;
            }
            else {
                injectionMethod = InjectionMethod::LoadLibrary;
            }

            PerformInjection(injectionInfo, injectionMethod);
            break;
        }
        case '2': {
            // Inject DLL into all processes with matching names
            std::cout << "\033[1;35m[SpecInject]\033[0m Enter the name of the process to inject into: ";
            std::wstring processName;
            getline(std::wcin, processName);

            std::cout << "\033[1;35m[SpecInject]\033[0m Enter the path of the DLL to inject: ";
            std::wstring dllPath;
            getline(std::wcin, dllPath);

            if (!IsFileExists(dllPath)) {
                std::cout << "\033[1;35m[SpecInject]\033[0m \033[1;31m[ERROR]\033[0m The specified DLL path does not exist." << std::endl;
                break;
            }

            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                std::cout << "\033[1;35m[SpecInject]\033[0m \033[1;31m[ERROR]\033[0m Failed to create a snapshot of running processes." << std::endl;
                break;
            }

            PROCESSENTRY32 processEntry;
            processEntry.dwSize = sizeof(PROCESSENTRY32);

            if (Process32First(hSnapshot, &processEntry)) {
                do {
                    std::wstring currentProcessName = processEntry.szExeFile;
                    std::transform(currentProcessName.begin(), currentProcessName.end(), currentProcessName.begin(), ::towlower);

                    if (currentProcessName.find(processName) != std::wstring::npos) {
                        InjectionInfo injectionInfo;
                        injectionInfo.processId = processEntry.th32ProcessID;
                        injectionInfo.dllPath = dllPath;
                        injectionInfoList.push_back(injectionInfo);
                    }
                } while (Process32Next(hSnapshot, &processEntry));
            }

            CloseHandle(hSnapshot);

            if (injectionInfoList.empty()) {
                std::cout << "\033[1;35m[SpecInject]\033[0m \033[1;31m[ERROR]\033[0m No processes found with matching names." << std::endl;
                break;
            }

            std::cout << "\033[1;35m[SpecInject]\033[0m Select injection method:\n";
            std::cout << "1. LoadLibrary\n";
            std::cout << "2. Manual Mapping\n";
            std::cout << "Enter your choice: ";

            char methodChoice = _getch();
            std::cout << methodChoice << std::endl;

            if (methodChoice == '2') {
                injectionMethod = InjectionMethod::ManualMapping;
            }
            else {
                injectionMethod = InjectionMethod::LoadLibrary;
            }

            for (const auto& injectionInfo : injectionInfoList) {
                PerformInjection(injectionInfo, injectionMethod);
            }

            injectionInfoList.clear();
            break;
        }
        case '3':
            // Exit the program
            std::cout << "\033[1;35m[SpecInject]\033[0m Exiting SpecInject. Goodbye!" << std::endl;
            return 0;
        default:
            std::cout << "\033[1;35m[SpecInject]\033[0m \033[1;31m[ERROR]\033[0m Invalid choice. Please try again." << std::endl;
            break;
        }

        std::cout << "\033[1;35m[SpecInject]\033[0m Press any key to continue...";
        _getch();
    }

    return 0;
}
