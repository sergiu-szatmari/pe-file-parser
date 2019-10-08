#include <Windows.h>
#include <winnt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void MyStrcpy(BYTE* bDestination, BYTE* bSource, DWORD dwSize)
{
	for (DWORD i = 0; i < dwSize; i++)
		bDestination[i] = bSource[i];
}

// Virtual Address to File Address Conversion
DWORD VAtoFA(DWORD dwAddress, PIMAGE_DOS_HEADER pImageDosHeader, PIMAGE_FILE_HEADER pImageFileHeader, BYTE* pbBuffer)
{
	WORD i = 0;
	PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)(pbBuffer + pImageDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	if (dwAddress == 0)
		return 0;

	for (i = 0; i < pImageFileHeader->NumberOfSections; i++)
	{
		if ((pImageSectionHeader->VirtualAddress <= dwAddress) && (dwAddress < (pImageSectionHeader->VirtualAddress + pImageSectionHeader->Misc.VirtualSize)))
			break;
		pImageSectionHeader++;
	}

	return (DWORD)(pbBuffer + pImageSectionHeader->PointerToRawData + (dwAddress - pImageSectionHeader->VirtualAddress));
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{ 
		printf(__TEXT("Unexpected error: invalid number of parameters (file path needed)\n")); 
		return -1; 
	}
	char* path = (char*)calloc(MAX_PATH, sizeof(char));
	
	for (int i = 1; i < argc; i++)
	{
		strcat(path, argv[i]);
		if (i != argc - 1)
			strcat(path, " ");
	}

	HANDLE hFile = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) 
	{ 
		if (GetLastError() == 2)
			printf("Error: File does not exist\n");
		else
			printf("Error opening the file (error code: %d)\n", GetLastError()); 
		return -1; 
	}

	HANDLE hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == NULL) { printf("Error creating the file mapping (error code: %d)\n", GetLastError()); return -1; }

	LPVOID pBuffer = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (pBuffer == NULL) { printf("Error mapping the file (error code: %d)\n", GetLastError()); return -1; }

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pImageFileHeader = &(pImageNtHeader->FileHeader);
	PIMAGE_OPTIONAL_HEADER pImageOptionalHeader = &(pImageNtHeader->OptionalHeader);
	
	printf("File Header:\n");
	printf("-Machine: %#x\n", pImageFileHeader->Machine);
	printf("-NumberOfSections: %#x\n", pImageFileHeader->NumberOfSections);
	printf("-Caracteristics: %#x\n", pImageFileHeader->Characteristics);

	printf("\nPress any key to continue to Optional Header...\n");
	_fgetchar();
	
	printf("Optional Header:\n");
	printf("-AdressOfEntryPoint: %#x\n", VAtoFA(pImageOptionalHeader->AddressOfEntryPoint, pDosHeader, pImageFileHeader, pBuffer));
	printf("-ImageBase: %#x\n", pImageOptionalHeader->ImageBase);
	printf("-SectionAlignment: %#x\n", pImageOptionalHeader->SectionAlignment);
	printf("-FileAlignment: %#x\n", pImageOptionalHeader->FileAlignment);
	printf("-Subsystem: %#x\n", pImageOptionalHeader->Subsystem);
	printf("-NumberOfRvaAndSizes: %#x\n", pImageOptionalHeader->NumberOfRvaAndSizes);

	printf("\nPress any key to continue to Section...\n");
	_fgetchar();

	printf("Sections:\n");
	PIMAGE_SECTION_HEADER CurrentSection = (PIMAGE_SECTION_HEADER)((char*)pImageOptionalHeader + pImageNtHeader->FileHeader.SizeOfOptionalHeader);
	for (BYTE j = 0; j < pImageFileHeader->NumberOfSections; j++, CurrentSection++)
	{
		BYTE i = 0;
		while (i < 8 && CurrentSection->Name[i] != '\0')
		{
			printf("%c", CurrentSection->Name[i]);
			i++;
		}
		printf(",%#x,%#x\n", VAtoFA(CurrentSection->VirtualAddress, pDosHeader, pImageFileHeader, pBuffer), CurrentSection->SizeOfRawData);
	}

	printf("\nPress any key to continue to Exports...\n");
	_fgetchar();

	printf("Exports:\n");
	if (IMAGE_DIRECTORY_ENTRY_EXPORT < pImageOptionalHeader->NumberOfRvaAndSizes &&
		pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0)
	{
		PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)VAtoFA(pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, pDosHeader, pImageFileHeader, pBuffer);

		if (pImageExportDirectory != NULL)
		{
			DWORD* pdwFunctionAddress = (DWORD*) VAtoFA(pImageExportDirectory->AddressOfFunctions, pDosHeader, pImageFileHeader, pBuffer);
			WORD* pwNameOrdinals = (WORD*) VAtoFA(pImageExportDirectory->AddressOfNameOrdinals, pDosHeader, pImageFileHeader, pBuffer);
			DWORD* pdwNames = (DWORD*) VAtoFA(pImageExportDirectory->AddressOfNames, pDosHeader, pImageFileHeader, pBuffer);

			for (DWORD i = 0; i < pImageExportDirectory->NumberOfNames; i++)
			{
				BYTE* bName = (BYTE*)VAtoFA(pdwNames[i], pDosHeader, pImageFileHeader, pBuffer);
				WORD wNameOrdinal = pwNameOrdinals[i];
				DWORD dwFileAddress = VAtoFA(pdwFunctionAddress[pwNameOrdinals[i]], pDosHeader, pImageFileHeader, pBuffer);

				printf("%s,%#x,%#x\n", bName, wNameOrdinal, dwFileAddress);
			}

			if (pImageExportDirectory->NumberOfNames < pImageExportDirectory->NumberOfFunctions)
			{
				for (DWORD i = 0; i < pImageExportDirectory->NumberOfNames; i++)
					if (pdwFunctionAddress[i] != 0)
					{
						DWORD j;
						for (j = 0; j < pImageExportDirectory->NumberOfNames; j++)
							if (pdwFunctionAddress[pwNameOrdinals[j]] == pdwFunctionAddress[i])
								break;
						if (j == pImageExportDirectory->NumberOfNames)
						{
							printf(",%#x,%#x\n", i + pImageExportDirectory->Base, VAtoFA(pdwFunctionAddress[pwNameOrdinals[i]], pDosHeader, pImageFileHeader, pBuffer));
						}
					}
			}
		}
	}

	printf("\nPress any key to continue to Imports...\n");
	_fgetchar();

	printf("Imports:\n");
	if (IMAGE_DIRECTORY_ENTRY_IMPORT < pImageOptionalHeader->NumberOfRvaAndSizes &&
		pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
	{
		PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)VAtoFA(pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pDosHeader, pImageFileHeader, pBuffer);

		if (pImageImportDescriptor != NULL)
		{
			while (pImageImportDescriptor->Name != 0)
			{
				BYTE* pbName = (BYTE*)VAtoFA(pImageImportDescriptor->Name, pDosHeader, pImageFileHeader, pBuffer);
				PIMAGE_THUNK_DATA pImageImportTable = (PIMAGE_THUNK_DATA)VAtoFA(pImageImportDescriptor->OriginalFirstThunk, pDosHeader, pImageFileHeader, pBuffer);

				while (pImageImportTable->u1.AddressOfData != 0)
				{
					if (IMAGE_SNAP_BY_ORDINAL(pImageImportTable->u1.Ordinal))
						printf("%s,%#x\n", pbName, IMAGE_ORDINAL(pImageImportTable->u1.Ordinal));
					else
					{
						PIMAGE_IMPORT_BY_NAME pImageImportedFunction = (PIMAGE_IMPORT_BY_NAME)VAtoFA(pImageImportTable->u1.AddressOfData, pDosHeader, pImageFileHeader, pBuffer);
						printf("%s,%s\n", pbName, pImageImportedFunction->Name);
					}
					pImageImportTable++;
				}
				pImageImportDescriptor++;
			}
		}
	}

	UnmapViewOfFile(pBuffer);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
	free(path);

	printf("\nPress any key to exit...\n");
	_fgetchar();

	return 0;
}

