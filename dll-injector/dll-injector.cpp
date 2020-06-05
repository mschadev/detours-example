// dll-injector.cpp : 이 파일에는 'main' 함수가 포함됩니다. 거기서 프로그램 실행이 시작되고 종료됩니다.
//

#include <iostream>
#include "windows.h"
#include <TlHelp32.h>
#include <tchar.h>
BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    HANDLE hToken;
    LUID luid;

    // 현재 프로세스의 핸들을 가져와 관련된 액세스토큰을 가져옴.
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken))
    {
        printf("OpenProcessToken error: %u\n", GetLastError());
        return FALSE;
    }

    // 로컬 시스템에 대한 LUID를 가져옴.
    if (!LookupPrivilegeValue(NULL,          // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup
        &luid))         // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;

    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.
    if (!AdjustTokenPrivileges(hToken,  // 액세스 토큰 핸들
        FALSE,  // TURE일 경우 모든 권한 비활성화
        &tp,        // TOKEN_PRIBILEGES 구조체 포인터
        sizeof(TOKEN_PRIVILEGES),   // 다음에 오는 버퍼의 사이즈
        (PTOKEN_PRIVILEGES)NULL,    // 이전 상태 없어도 됨
        (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}
BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
    HANDLE                  hProcess, hThread;
    LPVOID                  pRemoteBuf;
    DWORD                   dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
    LPTHREAD_START_ROUTINE  pThreadProc;

    // 파라미터로 받은 프로세스의 핸들을 받아옴.
    if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
    {
        printf("OpenProcess(%d) failed!!!\n", dwPID);
        return FALSE;
    }

    // 해당 프로세스의 가상메모리 공간을 할당 받음.
    // 대상 핸들, 할당할 메모리 번지 지정(NULL이면 시스템이 자동 지정), 할당할 메모리 양,
    // 할당 방법 지정, 할당한 페이지의 액세스 타입 지정
    // 할당한 메모리 번지 반환 / NULL 반환
    pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize,
        MEM_COMMIT, PAGE_READWRITE);

    // 해당 프로세스 메모리를 조작.
    // 조작할 대상 프로세스 핸들, 조작할 가상메모리 주소, 메모리에 적을 값(인젝션 시킬 DLL 경로),
    // 메모리에 쓸 크기, 특정 프로세스의 바뀔 바이트를 받는 변수(NULL 사용 안함)
    WriteProcessMemory(hProcess, pRemoteBuf,
        (LPVOID)szDllPath, dwBufSize, NULL);

    pThreadProc = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandle(L"kernel32.dll"),
            "LoadLibraryW");

    hThread = CreateRemoteThread(hProcess, NULL, 0,
        pThreadProc, pRemoteBuf, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}

// 삽입했던 Dll 제거
// 삽입과 역순
BOOL EjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
    BOOL                    bMore = FALSE, bFound = FALSE;
    HANDLE                  hSnapshot, hProcess, hThread;
    MODULEENTRY32           me = { sizeof(me) };
    LPTHREAD_START_ROUTINE  pThreadProc;

    if (INVALID_HANDLE_VALUE ==
        (hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID)))
        return FALSE;

    bMore = Module32First(hSnapshot, &me);
    for (; bMore; bMore = Module32Next(hSnapshot, &me))
    {
        if (!_tcsicmp(me.szModule, szDllPath) ||
            !_tcsicmp(me.szExePath, szDllPath))
        {
            bFound = TRUE;
            break;
        }
    }

    if (!bFound)
    {
        CloseHandle(hSnapshot);
        return FALSE;
    }

    if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
    {
        printf("OpenProcess(%d) failed!!!\n", dwPID);
        CloseHandle(hSnapshot);
        return FALSE;
    }

    pThreadProc = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandle(L"kernel32.dll"),
            "FreeLibrary");
    hThread = CreateRemoteThread(hProcess, NULL, 0,
        pThreadProc, me.modBaseAddr, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    CloseHandle(hSnapshot);

    return TRUE;
}
int main()
{
   
    SetPrivilege(SE_DEBUG_NAME, TRUE);
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (wcscmp(entry.szExeFile, L"detours-example.exe") == 0)
            {
               
                InjectDll(entry.th32ProcessID, L"test-dll.dll");
                std::cout << "Enter to exit";
                std::cin.get();
                EjectDll(entry.th32ProcessID, L"test-dll.dll");
                break;
            }
        }
    }

    CloseHandle(snapshot);
    
    return 0;
}

