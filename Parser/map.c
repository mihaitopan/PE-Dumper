#include "map.h"

int MapFile(__in char *FileName,
		    __in DWORD AccessRights,
			__out PMAP Map)
{
    // local data
    int status;
    DWORD access;

    // initializations
    status = 0;
    access = 0;

    // validations
    if (NULL == FileName)
    {
        printf("Invalid param 1\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == Map)
    {
        printf("Invalid param 3\n");
        return STATUS_INVALID_PARAMETER;
    }

    // preinit return
    Map->adr   = NULL;
    Map->hFile = INVALID_HANDLE_VALUE;
    Map->hMap = NULL;
    Map->size = 0;

    // open file
    Map->hFile = CreateFileA(FileName,
                            AccessRights,
                            FILE_SHARE_READ,
                            NULL,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL);
    if (INVALID_HANDLE_VALUE == Map->hFile)
    {
        printf("CreateFileA failed: %d\n", GetLastError());
        status = STATUS_FILE_HANDLING_ERROR;
        return status;
    }

    // get the size
    GetFileSizeEx(Map->hFile, 
                 (PLARGE_INTEGER)&Map->size);
    
    // skip if size == 0
    if (0 == Map->size)
    {
        status = STATUS_FILE_SIZE_ERROR;
        goto Cleanup;
    }

    // skip if size > 2 GB
    if (Map->size > 0x80000000)
    {
        status = STATUS_FILE_SIZE_ERROR;
        goto Cleanup;
    }

    if (AccessRights & GENERIC_WRITE)
    {
        access = PAGE_READWRITE;
    }
    else
    {
        access = PAGE_READONLY;
    }

    // create the mapping
    Map->hMap = CreateFileMapping(Map->hFile,
                                  NULL,
                                  access,
                                  0,
                                  0,
                                  NULL);
    if (NULL == Map->hMap)
    {
        printf("CreateFileMapping failed: %d\n", GetLastError());
        status = STATUS_FILE_HANDLING_ERROR;
        goto Cleanup;
    }

    if (AccessRights & GENERIC_WRITE)
    {
        access = FILE_MAP_WRITE;
    }
    else
    {
        access = FILE_MAP_READ;
    }

    // view the mapping
    Map->adr = (BYTE*) MapViewOfFile(Map->hMap,
                                     access,
                                     0,
                                     0,
                                     0);
    if (NULL == Map->adr)
    {
        printf("MapViewOfFile failed: %d\n", GetLastError());
        status = STATUS_FILE_HANDLING_ERROR;
        goto Cleanup;
    }

Cleanup:
    if (!MAP_SUCCESS(status))
    {
        UnmapFile(Map);
    }
    return status;
}


void
UnmapFile(__inout PMAP Map)
{
    if (NULL == Map)
    {
        return;
    }

    if (NULL != Map->adr)
    {
        UnmapViewOfFile(Map->adr);
        Map->adr = NULL;
    }

    if (NULL != Map->hMap)
    {
        CloseHandle(Map->hMap);
        Map->hMap = NULL;
    }

    if (INVALID_HANDLE_VALUE != Map->hFile)
    {
        CloseHandle(Map->hFile);
        Map->hFile = INVALID_HANDLE_VALUE;
    }
}