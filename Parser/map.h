#ifndef _MAP_H_
#define _MAP_H_

#include <stdio.h>
#include <Windows.h>

#define MAP_SUCCESS(status) ((status) >= 0)

#define STATUS_SUCCESS              0
//#define STATUS_INVALID_PARAMETER   -1 // already defined in windows
#define STATUS_FILE_HANDLING_ERROR -2
#define STATUS_FILE_SIZE_ERROR     -3

typedef unsigned long long QWORD;

typedef struct _MAP
{
    BYTE* adr;
    HANDLE hMap;
    HANDLE hFile;
    QWORD size;
} MAP, *PMAP;

int MapFile(__in char * FileName,
		    __in DWORD AccessRights,
			__out PMAP Map);

void UnmapFile(__inout PMAP Map);

void ProcessPE(__in PMAP Map);

#endif //_MAP_H_