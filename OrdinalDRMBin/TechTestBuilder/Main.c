/*
// @NUL0x4C | @mrd0x : MalDevAcademy
This program is used to generated DRM binaries that will only run on the machine that generated them. 
*/


#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#define REPORT_ERROR(szApiName, _GOTO)							\
	printf("[!] \"%ws\" Failed With Error: %d \n", szApiName, GetLastError());	\
	goto _GOTO;

//----------------------------------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------

DWORD RVA2Offset(IN DWORD dwRVA, IN PBYTE pBaseAddress) {

	PIMAGE_NT_HEADERS        pImgNtHdrs		= NULL;
	PIMAGE_SECTION_HEADER    pImgSectionHdr		= NULL;

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBaseAddress + ((PIMAGE_DOS_HEADER)pBaseAddress)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return 0x00;

	pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)&pImgNtHdrs->OptionalHeader + pImgNtHdrs->FileHeader.SizeOfOptionalHeader);

	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		if (dwRVA >= pImgSectionHdr[i].VirtualAddress && dwRVA < (pImgSectionHdr[i].VirtualAddress + pImgSectionHdr[i].Misc.VirtualSize))
			return (dwRVA - pImgSectionHdr[i].VirtualAddress) + pImgSectionHdr[i].PointerToRawData;
	}

	printf("\t[!] Cound'nt Convert The 0x%0.8X RVA to File Offset! \n", dwRVA);
	return 0x00;
}

//----------------------------------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------

BOOL ReadSelfFromDisk(IN LPWSTR szLocalImageName, OUT ULONG_PTR* pModule, OUT DWORD* pdwFileSize) {

	HANDLE		hFile				= INVALID_HANDLE_VALUE;
	PBYTE		pFileBuffer			= NULL;
	DWORD		dwFileSize			= 0x00,
			dwNumberOfBytesRead		= 0x00;

	if (!szLocalImageName || !pModule || !pdwFileSize)
		return FALSE;

	if ((hFile = CreateFileW(szLocalImageName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		REPORT_ERROR(TEXT("CreateFileW"), _FUNC_CLEANUP)
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		REPORT_ERROR(TEXT("GetFileSize"), _FUNC_CLEANUP)
	}

	if ((pFileBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize)) == NULL) {
		REPORT_ERROR(TEXT("HeapAlloc"), _FUNC_CLEANUP)
	}

	if (!ReadFile(hFile, pFileBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		REPORT_ERROR(TEXT("ReadFile"), _FUNC_CLEANUP)
	}

	*pModule = (ULONG_PTR)pFileBuffer;
	*pdwFileSize = dwFileSize;

_FUNC_CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (!*pModule && pFileBuffer)
		HeapFree(GetProcessHeap(), 0, pFileBuffer);
	return *pModule == NULL ? FALSE : TRUE;
}

//----------------------------------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------

BOOL WriteSelfToDisk(IN LPWSTR szLocalImageName, IN PVOID pImageBase, IN DWORD sImageSize) {

	HANDLE		hFile			= INVALID_HANDLE_VALUE;
	DWORD		dwNumberOfBytesWritten	= 0x00;

	if (!szLocalImageName || !pImageBase || !sImageSize)
		return FALSE;

	if ((hFile = CreateFileW(szLocalImageName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		REPORT_ERROR(TEXT("CreateFileW"), _FUNC_CLEANUP)
	}

	if (!WriteFile(hFile, pImageBase, sImageSize, &dwNumberOfBytesWritten, NULL) || sImageSize != dwNumberOfBytesWritten) {
		REPORT_ERROR(TEXT("WriteFile"), _FUNC_CLEANUP)
	}

_FUNC_CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return dwNumberOfBytesWritten == sImageSize ? TRUE : FALSE;
}


//----------------------------------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------

//\
#define PRINT_FUNC_DETAILS
//\
#define PRINT_DLL_DETAILS

BOOL InstallSelfDRMPatch(IN LPWSTR szInputImg, IN LPWSTR szOutputImg) {

	HMODULE				hLocalModule			= NULL;
	ULONG_PTR			uWritableImgBase		= NULL;
	SIZE_T				sLocalImgSize			= NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs			= NULL;
	PIMAGE_DATA_DIRECTORY		pEntryImportDataDir		= NULL;
	PIMAGE_IMPORT_DESCRIPTOR	pImgDescriptor			= NULL;

	hLocalModule = (HMODULE)((PLDR_DATA_TABLE_ENTRY)(((PPEB)__readgsqword(0x60))->Ldr->InMemoryOrderModuleList.Flink))->Reserved2[0];
	if (!hLocalModule || ((PIMAGE_DOS_HEADER)hLocalModule)->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	if (!ReadSelfFromDisk(szInputImg, &uWritableImgBase, &sLocalImgSize))
		return FALSE;

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uWritableImgBase + ((PIMAGE_DOS_HEADER)uWritableImgBase)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	pEntryImportDataDir = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	for (SIZE_T i = 0; i < pEntryImportDataDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {

		pImgDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(uWritableImgBase + RVA2Offset(pEntryImportDataDir->VirtualAddress, uWritableImgBase) + i);

		// If both thunks are NULL, we've reached the end of the import descriptors list
		if (pImgDescriptor->OriginalFirstThunk == NULL && pImgDescriptor->FirstThunk == NULL)
			break;

		LPSTR		cDllName			= (LPSTR)(uWritableImgBase + RVA2Offset(pImgDescriptor->Name, uWritableImgBase));
		ULONG_PTR	uOriginalFirstThunkRVA		= RVA2Offset(pImgDescriptor->OriginalFirstThunk, uWritableImgBase);
		ULONG_PTR	uFirstThunkRVA			= RVA2Offset(pImgDescriptor->FirstThunk, uWritableImgBase);
		SIZE_T		ImgThunkSize			= 0x00;
		HMODULE		hModule				= LoadLibraryA(cDllName);
		DWORD		dwPatchCount			= 0x00;


		if (!hModule) {
			printf("[!] Failed To Load %s \n", cDllName);
			continue;
		}

		while (TRUE) {

			PIMAGE_THUNK_DATA		pOriginalFirstThunk		= (PIMAGE_THUNK_DATA)(uWritableImgBase + uOriginalFirstThunkRVA + ImgThunkSize);
			PIMAGE_THUNK_DATA           	pFirstThunk			= (PIMAGE_THUNK_DATA)(uWritableImgBase + uFirstThunkRVA + ImgThunkSize);
			PIMAGE_IMPORT_BY_NAME		pImgImportByName		= NULL;
			WORD				wOrdinal			= 0x00;

			if (pOriginalFirstThunk->u1.Function == NULL && pFirstThunk->u1.Function == NULL)
				break;

			// Function imported by ordinal	:::
			if (IMAGE_SNAP_BY_ORDINAL32(pOriginalFirstThunk->u1.Ordinal) || IMAGE_SNAP_BY_ORDINAL64(pOriginalFirstThunk->u1.Ordinal)) {
				ImgThunkSize += sizeof(IMAGE_THUNK_DATA);
				continue;
			}

			// Function imported by name	:::
			PIMAGE_NT_HEADERS		pDllImgNtHdrs			= NULL;
			PIMAGE_EXPORT_DIRECTORY		pExportDirectory		= NULL;
			PDWORD				pdwFunctionNameArray		= NULL;
			PDWORD				pdwFunctionAddressArray		= NULL;
			PWORD				pwFunctionOrdinalArray		= NULL;

			pDllImgNtHdrs = (ULONG_PTR)hModule + ((PIMAGE_DOS_HEADER)(ULONG_PTR)hModule)->e_lfanew;
			if (pDllImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
				break;

			pExportDirectory		= (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)hModule + pDllImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			pImgImportByName		= (PIMAGE_IMPORT_BY_NAME)(uWritableImgBase + RVA2Offset(pOriginalFirstThunk->u1.AddressOfData, uWritableImgBase));
			pdwFunctionNameArray		= (PDWORD)((ULONG_PTR)hModule + pExportDirectory->AddressOfNames);
			pdwFunctionAddressArray		= (PDWORD)((ULONG_PTR)hModule + pExportDirectory->AddressOfFunctions);
			pwFunctionOrdinalArray		= (PWORD)((ULONG_PTR)hModule + pExportDirectory->AddressOfNameOrdinals);

			for (DWORD x = 0; x < pExportDirectory->NumberOfFunctions; x++) {
				if (strcmp((LPSTR)pImgImportByName->Name, (LPSTR)((ULONG_PTR)hModule + pdwFunctionNameArray[x])) == 0x00) {
					wOrdinal = pwFunctionOrdinalArray[x] + pExportDirectory->Base;
					break;
				}
			}

			// Replace the function with its ordinal
			pFirstThunk->u1.Ordinal			= (ULONGLONG)(wOrdinal | IMAGE_ORDINAL_FLAG32 | IMAGE_ORDINAL_FLAG64);
			pOriginalFirstThunk->u1.Ordinal		= pFirstThunk->u1.Ordinal;

#ifdef PRINT_FUNC_DETAILS
			printf("[>] Replaceed Function !%s.%s With Its Ordinal [%d]\n", cDllName, pImgImportByName->Name, wOrdinal);
#endif
			dwPatchCount++;

			wOrdinal = 0x00;
			ImgThunkSize += sizeof(IMAGE_THUNK_DATA);
		}
#ifdef PRINT_DLL_DETAILS
		printf("[>] From %s: Patched \"%d\" Functions Imported With Their Ordinals\n", cDllName, dwPatchCount);
#endif
	}

	return WriteSelfToDisk(szOutputImg, uWritableImgBase, sLocalImgSize);
}


//----------------------------------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------

#pragma warning(disable: 4996)  // using mbstowcs

BOOL ParseCommandLineArgs(IN INT Argc, IN LPSTR Argv[], OUT LPWSTR* pszInputFile, OUT LPWSTR* pszOutputFile) {

	for (int i = 1; i < Argc; i++) {

		if ((strcmp(Argv[i], "-i") == 0 || strcmp(Argv[i], "--input") == 0) && i + 1 < Argc) {
			size_t len = mbstowcs(NULL, Argv[++i], 0) + 1;
			*pszInputFile = (wchar_t*)malloc(len * sizeof(wchar_t));
			mbstowcs(*pszInputFile, Argv[i], len);
		}

		if ((strcmp(Argv[i], "-o") == 0 || strcmp(Argv[i], "--output") == 0) && i + 1 < Argc) {
			size_t len = mbstowcs(NULL, Argv[++i], 0) + 1;
			*pszOutputFile = (wchar_t*)malloc(len * sizeof(wchar_t));
			mbstowcs(*pszOutputFile, Argv[i], len);
		}
	}

	if (*pszInputFile == NULL || *pszOutputFile == NULL) {
		printf("[i] Usage: %s -i <input_file> -o <output_file>\n", Argv[0]);
		return FALSE;
	}

	return TRUE;
}

//----------------------------------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------


int main(int argc, char* argv[]) {

	printf("[*] Program To Demonstrate The Technique Of Patching Function Names With Ordinals \n");

	LPWSTR	szInputFile		= NULL,
		szOutputFile		= NULL;

	if (!ParseCommandLineArgs(argc, argv, &szInputFile, &szOutputFile))
		return -1;

	if (!InstallSelfDRMPatch(szInputFile, szOutputFile))
		return -1;
	else
		printf("[*] Wrote Protected Binary To %ws \n", szOutputFile);

	return 0;
}
