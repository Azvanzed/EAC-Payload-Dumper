#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <intrin.h>

#include "utils.h"
#include "eac.h"

volatile LONG g_isDumped = 0;
PVOID g_VehHandle = NULL;

LONG WINAPI exception_handler(EXCEPTION_POINTERS* ExceptionInfo) {
    CONTEXT* ctx = ExceptionInfo->ContextRecord;
    EXCEPTION_RECORD* exception = ExceptionInfo->ExceptionRecord;

    if (exception->ExceptionCode == EXCEPTION_BREAKPOINT) {

        printf("decrypting payload\n");
        uint64_t addr = (uint64_t)exception->ExceptionAddress;

        /*        
        eax = image_size        mov     eax, [rsp+238h+image_size]
                                ...
        r8 = eax = image_size   mov     r8d, eax
        rdx = image_buffer      mov     rdx, [rsp+238h+image_buffer]
                trap here =>    call    sub_7FF8036AFBD0

        r8: image_size
        rdx: image_buffer
        */

        uint8_t* image_data = (uint8_t*)ctx->Rdx;
        uint32_t image_size = ctx->R8;
        if (image_size <= 0x1000) {
            printf("invalid payload\n");
            return EXCEPTION_CONTINUE_SEARCH;
        }

        uint8_t* buffer = (uint8_t*)malloc(image_size);
        ASSERT(buffer != NULL); // once again, WTF?
        ASSERT(IsBadReadPtr(image_data, image_size) == FALSE);
        
        memcpy(buffer, image_data, image_size);
        decrypt_module(buffer, image_size);

        // PE check
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buffer;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            printf("invalid payload\n");
            free(buffer);
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // remove trap
        printf("removing call trap\n");
        ASSERT(set_bytes((void*)addr, 0xE8, 1) == true);
        ASSERT(RemoveVectoredExceptionHandler(g_VehHandle) != 0);
            
        // dump to current directory with name of the address
        printf("saving payload\n");
        save_dump("eac_payload.dll", buffer, image_size);
        free(buffer);

        // report to thread
        InterlockedIncrement(&g_isDumped);
        printf("payload dumped!\n");

        // resume eac execution so no crash :)
        printf("resuming execution\n");
        ctx->Rip = addr;

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    printf("unknown exception, skipping\n");
    return EXCEPTION_CONTINUE_SEARCH;
}

DWORD WINAPI hook_thread(PVOID Param __attribute__((unused))) {
    printf("hook thread created!\n");

    while (InterlockedExchange(&g_isDumped, g_isDumped) == 0) {
        void* curr = NULL;
        MEMORY_BASIC_INFORMATION mbi = { 0 };   
        while (VirtualQuery(curr, &mbi, sizeof(mbi)) > 0) {
            if (mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.Type == MEM_PRIVATE) {
                uint64_t call = find_pattern((uint64_t)mbi.BaseAddress, mbi.RegionSize, EAC_CALL_PATTERN, EAC_CALL_MASK);
                if (call == 0) goto skip;

                // setup trap on the call
                ASSERT(g_VehHandle = AddVectoredExceptionHandler(1, exception_handler));
                ASSERT(set_bytes((void*)call, 0xCC, 1) == true);
                printf("trapped call @ 0x%llx\n", call);
            }

        skip:
            curr = mbi.BaseAddress + mbi.RegionSize;
        }

        Sleep(10);
    }
    
    return EXIT_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL __attribute__((unused)), DWORD fdwReason, LPVOID lpvReserved __attribute__((unused))) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        AllocConsole();
        freopen("CONOUT$", "w", stdout);

        SetConsoleTitleA("EAC Payload Dumper | by @wcscpy");
        CloseHandle(CreateThread(NULL, 0, hook_thread, NULL, 0, NULL));
    }

    return TRUE;
}
