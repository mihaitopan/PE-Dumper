#include "map.h"

// converting the virtual address to file address
DWORD RVA2FA(__in DWORD rva,
			 __in int nrOfSections, 
			 __in IMAGE_SECTION_HEADER* ish[])
{
	DWORD fa;
	for (int j = 0; j < nrOfSections; j++)
	{
		if (rva >= ish[j]->VirtualAddress && 
			rva < ish[j]->VirtualAddress + ish[j]->Misc.VirtualSize)
		{
			fa = ish[j]->PointerToRawData + rva - ish[j]->VirtualAddress;
		}
	}
	return fa;
}

void ProcessPE(__in PMAP Map)
{
	// declarations
    IMAGE_DOS_HEADER* idh;
    IMAGE_NT_HEADERS* inth;
	IMAGE_SECTION_HEADER* ish[16] = { 0 }; 
	IMAGE_EXPORT_DIRECTORY* ied;
	IMAGE_IMPORT_DESCRIPTOR* iid;
	IMAGE_RESOURCE_DIRECTORY* ird;
	int i;
    
	// declarations
	i = 0;
	idh = NULL;
	inth = NULL;
	ied = NULL;
	iid = NULL;
	ird = NULL;

	// if mapping failed return
    if (NULL == Map)
    {
        return;
    }

	// writing everything in file
	FILE * fp;
	fopen_s(&fp, "PARSER VIEW CREATED HERE.txt", "w");
	fprintf(fp, "\nFILE SIZE: \n");
	fprintf(fp, "\t %.2lfKB \n", ((double)Map->size) / 1000);

	// validating PE
    if (Map->size < sizeof(IMAGE_DOS_HEADER))
    {
        printf("Map->size < sizeof(IMAGE_DOS_HEADER)\n");
        return;
    }

    idh = (IMAGE_DOS_HEADER*) Map->adr;

    if (IMAGE_DOS_SIGNATURE != idh->e_magic)
    {
        printf("Not MZ signature\n");
        return;
    }

    if (Map->size < (idh->e_lfanew + sizeof(IMAGE_NT_HEADERS)))
    {
        printf("Map->size < (idh->e_lfanew + sizeof(IMAGE_NT_HEADERS))\n");
        return;
    }
    
    inth = (IMAGE_NT_HEADERS*) (Map->adr + idh->e_lfanew);

    if (IMAGE_NT_SIGNATURE != inth->Signature)
    {
        printf("Not PE signature \n");
        return;
    }
	
	// size of image optional header is not always constant !!!
	if (Map->size < (idh->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + inth->FileHeader.SizeOfOptionalHeader + inth->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)))
	{
		printf("Map->size < (idh->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + inth->FileHeader.SizeOfOptionalHeader + inth->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER))\n");
		return;
	}

	for (i = 0; i < inth->FileHeader.NumberOfSections; i++) {
		ish[i] = (IMAGE_SECTION_HEADER*)(Map->adr + idh->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + inth->FileHeader.SizeOfOptionalHeader + i * sizeof(IMAGE_SECTION_HEADER));
		if (ish[i]->PointerToRawData % inth->OptionalHeader.FileAlignment != 0) {
			printf("ish[i]->PointerToRawData %% inth->OptionalHeader.FileAlignment != 0\n"); // Sections did not link correctly
			return;
		}
	}

	// IMAGE_FILE_HEADER
	fprintf(fp, "\nIMAGE_FILE_HEADER: \n");
	fprintf(fp, "\t Machine = 0x%08x \n", inth->FileHeader.Machine);
	fprintf(fp, "\t NumberOfSections = 0x%08x \n", inth->FileHeader.NumberOfSections);
	fprintf(fp, "\t SizeOfOptionalHeader = 0x%08x \n", inth->FileHeader.SizeOfOptionalHeader);
	/// fprintf(fp, "\t Characteristics = 0x%08x \n", inth->FileHeader.Characteristics);
	fprintf(fp, "\t Characteristics: \n");
	if ((inth->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0)
	{
		fprintf(fp, "\t\t- executable \n");
	}
	if ((inth->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) != 0)
	{
		fprintf(fp, "\t\t- 32bit \n");
	}
	else
	{
		fprintf(fp, "Not a 32bit executable!\n");
		printf("Not a 32bit executable!\n");
		return;
	}
	if ((inth->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0)
	{
		fprintf(fp, "\t\t- dll \n");
	}
	fprintf(fp, "\t\t-\n");
	
	// IMAGE_OPTIONAL_HEADER
	fprintf(fp, "\nIMAGE_OPTIONAL_HEADER: \n");
	fprintf(fp, "\t SizeOfCode = 0x%08x \n", inth->OptionalHeader.SizeOfCode);
	fprintf(fp, "\t AddressOfEntryPoint = 0x%08x \n", inth->OptionalHeader.AddressOfEntryPoint);
	fprintf(fp, "\t ImageBase = 0x%08x \n", inth->OptionalHeader.ImageBase);
	/// fprintf(fp, "\t SectionAlignment = 0x%08x \n", inth->OptionalHeader.SectionAlignment); // constant
	/// fprintf(fp, "\t FileAlignment = 0x%08x \n", inth->OptionalHeader.FileAlignment); // constant
	fprintf(fp, "\t SizeOfImage = 0x%08x \n", inth->OptionalHeader.SizeOfImage);
	fprintf(fp, "\t SizeOfHeaders = 0x%08x \n", inth->OptionalHeader.SizeOfHeaders);
	/// fprintf(fp, "\t DllCharacteristics = 0x%08x \n", inth->OptionalHeader.DllCharacteristics);
	/// fprintf(fp, "\t LoaderFlags = 0x%08x \n", inth->OptionalHeader.LoaderFlags);

	fprintf(fp, "\t DllCharacteristics: \n");
	if ((inth->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0)
	{
		fprintf(fp, "\t\t- dynamic base \n");
	}
	if ((inth->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0)
	{
		fprintf(fp, "\t\t- nx compat \n");
	}
	fprintf(fp, "\t\t-\n");

	// EXPORTS
	fprintf(fp, "\nIMAGE_DIRECTORY_ENTRY_EXPORT: \n");
	fprintf(fp, "\t VirtualAddress = 0x%08x \n", inth->OptionalHeader.DataDirectory[0].VirtualAddress);
	fprintf(fp, "\t Size = 0x%08x \n", inth->OptionalHeader.DataDirectory[0].Size);
	// IMAGE_EXPORT_DIRECTORY
	fprintf(fp, "\nIMAGE_EXPORT_DIRECTORY: \n");
	if (0 != inth->OptionalHeader.DataDirectory[0].VirtualAddress)
	{
		DWORD virtualAddress, faAddress;
		DWORD mappedOrdinal, unmappedOrdinal, mappedRvasName, mappedName, unmappedName, unmappedAddress, mappedAddress;
		
		virtualAddress = faAddress = 0;
		mappedOrdinal = unmappedOrdinal = mappedRvasName = mappedName = unmappedName = unmappedAddress = mappedAddress = 0;
		
		virtualAddress = inth->OptionalHeader.DataDirectory[0].VirtualAddress;
		faAddress = RVA2FA(virtualAddress, inth->FileHeader.NumberOfSections, ish);
		ied = (IMAGE_EXPORT_DIRECTORY*)(Map->adr + faAddress);

		/// fprintf(fp, "\t Characteristics = 0x%08x \n", ied->Characteristics);
		/// fprintf(fp, "\t Name = 0x%08x \n", ied->Name);
		/// fprintf(fp, "\t Base = 0x%08x \n", ied->Base);
		fprintf(fp, "\t NumberOfFunctions = 0x%08x \n", ied->NumberOfFunctions);
		fprintf(fp, "\t NumberOfNames = 0x%08x \n", ied->NumberOfNames);
		/// fprintf(fp, "\t AddressOfFunctions = 0x%08x \n", ied->AddressOfFunctions);
		/// fprintf(fp, "\t AddressOfNames = 0x%08x \n", ied->AddressOfNames);
		/// fprintf(fp, "\t AddressOfNameOrdinals = 0x%08x \n", ied->AddressOfNameOrdinals);

		fprintf(fp, "\t EXPORTS:\n");
		for (int i = 0; i < (int)ied->NumberOfNames; i++)
		{
			// ordinal
			mappedOrdinal = ied->AddressOfNameOrdinals;
			unmappedOrdinal = RVA2FA(mappedOrdinal, inth->FileHeader.NumberOfSections, ish) + i * sizeof(WORD);
			// name
			mappedRvasName = ied->AddressOfNames;
			mappedName = *( (DWORD*)(Map->adr + RVA2FA(mappedRvasName, inth->FileHeader.NumberOfSections, ish) + i * sizeof(DWORD)) );
			unmappedName = RVA2FA(mappedName, inth->FileHeader.NumberOfSections, ish);
			// address of function
			WORD ord = *(WORD*)(Map->adr + unmappedOrdinal); // correspondent ordinal for function
			unmappedAddress = ied->AddressOfFunctions;
			mappedAddress = RVA2FA(unmappedAddress, inth->FileHeader.NumberOfSections, ish) + ord * sizeof(DWORD);
			// forwarded
			DWORD mappedAddressValue = *(DWORD*)(Map->adr + mappedAddress);
			if (mappedAddressValue >= inth->OptionalHeader.DataDirectory[0].VirtualAddress && // exports are always in section 0
				mappedAddressValue < inth->OptionalHeader.DataDirectory[0].VirtualAddress + inth->OptionalHeader.DataDirectory[0].Size)
			{
				DWORD biMappedAddress = RVA2FA(mappedAddressValue, inth->FileHeader.NumberOfSections, ish);
				fprintf(fp, "\t\t %d - FORWARDED - %s - FORWARDED \n", *(WORD*)(Map->adr + unmappedOrdinal), Map->adr + biMappedAddress);
			}
			else
			{
				fprintf(fp, "\t\t %d - %s - 0x%08x \n", *(WORD*)(Map->adr + unmappedOrdinal), Map->adr + unmappedName, *(DWORD*)(Map->adr + mappedAddress));
			}

		}
	}
	else
	{
		fprintf(fp, "\t No exports \n");
	}

	// IMPORTS
	fprintf(fp, "\nIMAGE_DIRECTORY_ENTRY_IMPORT: \n");
	fprintf(fp, "\t VirtualAddress = 0x%08x \n", inth->OptionalHeader.DataDirectory[1].VirtualAddress);
	fprintf(fp, "\t Size = 0x%08x \n", inth->OptionalHeader.DataDirectory[1].Size);
	// IMAGE_IMPORT_DIRECTORY
	fprintf(fp, "\nIMAGE_IMPORT_DESCRIPTOR: \n");
	if (0 != inth->OptionalHeader.DataDirectory[1].VirtualAddress)
	{
		DWORD virtualAddress, faAddress, functionAddress;
		char *thunk, *hintName, *libraryName, *functionName;

		virtualAddress = faAddress = 0;

		virtualAddress = inth->OptionalHeader.DataDirectory[1].VirtualAddress;
		faAddress = RVA2FA(virtualAddress, inth->FileHeader.NumberOfSections, ish);
		iid = (IMAGE_IMPORT_DESCRIPTOR*) (Map->adr + faAddress);

		/// fprintf(fp, "\t Characteristics = 0x%08x \n", iid->Characteristics); // union: Characteristics, OriginalFirstThunk 2 names for same data
		fprintf(fp, "\t OriginalFirstThunk = 0x%08x \n", iid->OriginalFirstThunk);
		fprintf(fp, "\t FirstThunk = 0x%08x \n", iid->FirstThunk);
		/// fprintf(fp, "\t ForwarderChain = 0x%08x \n", iid->ForwarderChain);
		/// fprintf(fp, "\t Name = 0x%08x \n", iid->Name);

		fprintf(fp, "\t IMPORTS:\n");
		while (iid->Name != 0)
		{
			thunk = Map->adr + iid->FirstThunk;
			hintName = Map->adr;

			if (iid->OriginalFirstThunk != 0)
			{
				hintName += RVA2FA(iid->OriginalFirstThunk, inth->FileHeader.NumberOfSections, ish); // OriginalFirstThunk
			}
			else
			{
				hintName += RVA2FA(iid->FirstThunk, inth->FileHeader.NumberOfSections, ish); // FirstThunk
			}

			libraryName = Map->adr + RVA2FA(iid->Name, inth->FileHeader.NumberOfSections, ish);
			fprintf(fp, "\t\t %s - 0x%08x\n", libraryName, iid->FirstThunk);
			IMAGE_THUNK_DATA* itd = (IMAGE_THUNK_DATA*)hintName;
			while (itd->u1.AddressOfData != 0)
			{
				functionAddress = itd->u1.AddressOfData;
				if ((functionAddress & 0x80000000) == 0x80000000)
				{
					functionAddress &= 0x7FFFFFFF;
				}
				else
				{
					functionName = Map->adr + RVA2FA(functionAddress, inth->FileHeader.NumberOfSections, ish) + 2;
					fprintf(fp, "\t\t\t %s\n", functionName);
				}
				thunk += 4;
				hintName += 4;
				itd++;
			}
			iid++;
		}
	}
	else
	{
		fprintf(fp, "\t No imports \n");
	}
	
	// RESOURCES
	fprintf(fp, "\nIMAGE_DIRECTORY_ENTRY_RESOURCE: \n");
	fprintf(fp, "\t VirtualAddress = 0x%08x \n", inth->OptionalHeader.DataDirectory[2].VirtualAddress);
	fprintf(fp, "\t Size = 0x%08x \n", inth->OptionalHeader.DataDirectory[2].Size);
	// IMAGE_RESOURCE_DIRECTORY
	fprintf(fp, "\nIMAGE_RESOURCE_DIRECTORY: \n");
	if (0 != inth->OptionalHeader.DataDirectory[2].VirtualAddress)
	{
		ird = (IMAGE_RESOURCE_DIRECTORY*) (Map->adr + inth->OptionalHeader.DataDirectory[2].VirtualAddress);

		fprintf(fp, "\t Characteristics = 0x%08x \n", ird->Characteristics);
		fprintf(fp, "\t NumberOfNamedEntries = 0x%08x \n", ird->NumberOfNamedEntries);
		fprintf(fp, "\t NumberOfIdEntries = 0x%08x \n", ird->NumberOfIdEntries);
	}
	else
	{
		fprintf(fp, "\t No resources \n");
	}

	// IAT
	fprintf(fp, "\nIMAGE_DIRECTORY_ENTRY_IAT: \n");
	fprintf(fp, "\t VirtualAddress = 0x%08x \n", inth->OptionalHeader.DataDirectory[13].VirtualAddress);
	fprintf(fp, "\t Size = 0x%08x \n", inth->OptionalHeader.DataDirectory[13].Size);


	// SECTION HEADERS
	for (i = 0; i < inth->FileHeader.NumberOfSections; i++) {
		fprintf(fp, "\nIMAGE_SECTION_HEADER %s: \n", ish[i]->Name);
		/// fprintf(fp, "\t PhysicalAddress = 0x%08x \n", ish[i]->Misc.PhysicalAddress); // union: VirtualSize, PhysicalAddress 2 names for same data
		fprintf(fp, "\t VirtualSize = 0x%08x \n", ish[i]->Misc.VirtualSize);
		fprintf(fp, "\t VirtualAddress = 0x%08x \n", ish[i]->VirtualAddress);
		/// fprintf(fp, "\t SizeOfRawData = 0x%08x \n", ish[i]->SizeOfRawData);
		fprintf(fp, "\t PointerToRawData = 0x%08x \n", ish[i]->PointerToRawData);
		/// fprintf("\t Characteristics = 0x%08x \n", ish[i]->Characteristics);
		fprintf(fp, "\t Characteristics:\n");
		if ((ish[i]->Characteristics & IMAGE_SCN_CNT_CODE) != 0)
		{
			fprintf(fp, "\t\t- has executable code \n");
		}
		if ((ish[i]->Characteristics & IMAGE_SCN_MEM_NOT_PAGED) != 0)
		{
			fprintf(fp, "\t\t- cannot be paged \n");
		}
		if ((ish[i]->Characteristics & IMAGE_SCN_MEM_SHARED) != 0)
		{
			fprintf(fp, "\t\t- can be shared \n");
		}
		fprintf(fp, "\t\t-\n");
	}

	// file written, close it
	fclose(fp);

	printf("parsing succeded\n");
	printf("file written - open 'PARSER VIEW CREATED HERE.txt' for more details\n");
}