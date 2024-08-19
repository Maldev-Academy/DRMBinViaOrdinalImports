/*
// @NUL0x4C | @mrd0x : MalDevAcademy
This program applies a DRM protection technique to its own executable file by replacing the imported function names with their ordinals.
*/

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>


#define NEW_STREAM	L":%x%x\x00"
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

typedef struct _FILE_RENAME_INFO2 {
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS1)
	union {
		BOOLEAN ReplaceIfExists;
		DWORD Flags;
	} DUMMYUNIONNAME;
#else
	BOOLEAN ReplaceIfExists;
#endif
	HANDLE RootDirectory;
	DWORD FileNameLength;
	WCHAR FileName[MAX_PATH]; // Instead of "WCHAR FileName[0]" (See FILE_RENAME_INFO's original documentation)
} FILE_RENAME_INFO2, * PFILE_RENAME_INFO2;


BOOL DeleteSelfFromDisk(IN LPCWSTR szFileName) {

	BOOL				bResult			= FALSE;
	HANDLE                      	hFile			= INVALID_HANDLE_VALUE;
	FILE_DISPOSITION_INFO       	DisposalInfo		= { .DeleteFile = TRUE };
	FILE_RENAME_INFO2		RenameInfo		= { .FileNameLength = sizeof(NEW_STREAM), .ReplaceIfExists = FALSE, .RootDirectory = 0x00 };

	if (!szFileName)
		return FALSE;

	swprintf(RenameInfo.FileName, MAX_PATH, NEW_STREAM, rand(), rand() * rand());

	hFile = CreateFileW(szFileName, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		REPORT_ERROR(TEXT("CreateFileW [R]"), _FUNC_CLEANUP)
	}

	if (!SetFileInformationByHandle(hFile, FileRenameInfo, &RenameInfo, sizeof(RenameInfo))) {
		REPORT_ERROR(TEXT("SetFileInformationByHandle [R]"), _FUNC_CLEANUP)
	}

	CloseHandle(hFile);

	hFile = CreateFileW(szFileName, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		REPORT_ERROR(TEXT("CreateFileW [D]"), _FUNC_CLEANUP)
	}

	if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &DisposalInfo, sizeof(DisposalInfo))) {
		REPORT_ERROR(TEXT("SetFileInformationByHandle [D]"), _FUNC_CLEANUP)
	}

	bResult = TRUE;

_FUNC_CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return bResult;
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

BOOL IsPatched(IN HMODULE hLocalModule) {

	PIMAGE_IMPORT_DESCRIPTOR	pImgDescriptor			= NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs			= NULL;
	PIMAGE_DATA_DIRECTORY		pEntryImportDataDir		= NULL;

	pImgNtHdrs = (ULONG_PTR)hLocalModule + ((PIMAGE_DOS_HEADER)(ULONG_PTR)hLocalModule)->e_lfanew;
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	pEntryImportDataDir = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	for (SIZE_T i = 0; i < pEntryImportDataDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		pImgDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)hLocalModule + pEntryImportDataDir->VirtualAddress + i);
		if (pImgDescriptor->OriginalFirstThunk == NULL && pImgDescriptor->FirstThunk == NULL)
			break;

		LPSTR		cDllName			= (LPSTR)((ULONG_PTR)hLocalModule + pImgDescriptor->Name);
		ULONG_PTR	uOriginalFirstThunkRVA		= pImgDescriptor->OriginalFirstThunk;
		SIZE_T		ImgThunkSize			= 0x00;
		HMODULE		hModule				= GetModuleHandleA(cDllName); // cDllName already loaded

		if (!hModule)
			continue;

		while (TRUE) {

			PIMAGE_THUNK_DATA	pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)hLocalModule + uOriginalFirstThunkRVA + ImgThunkSize);

			if (pOriginalFirstThunk->u1.Function == NULL)
				break;

			if (IMAGE_SNAP_BY_ORDINAL32(pOriginalFirstThunk->u1.Ordinal) || IMAGE_SNAP_BY_ORDINAL64(pOriginalFirstThunk->u1.Ordinal)) {
				ImgThunkSize += sizeof(IMAGE_THUNK_DATA);
				continue;
			}

			// Imported by name, we need patching
			return FALSE;
		}
	}

	return TRUE;
}

//----------------------------------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------

//\
#define PRINT_FUNC_DETAILS
//\
#define PRINT_DLL_DETAILS

BOOL InstallSelfDRMPatch(OUT BOOL *pbAlrdyProtected) {

	HMODULE				hLocalModule			= NULL;
	LPWSTR				szLocalImg			= NULL;
	ULONG_PTR			uWritableImgBase		= NULL;
	SIZE_T				sLocalImgSize			= NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs			= NULL;
	PIMAGE_DATA_DIRECTORY		pEntryImportDataDir		= NULL;
	PIMAGE_IMPORT_DESCRIPTOR	pImgDescriptor			= NULL;

	hLocalModule = (HMODULE)((PLDR_DATA_TABLE_ENTRY)(((PPEB)__readgsqword(0x60))->Ldr->InMemoryOrderModuleList.Flink))->Reserved2[0];
	if (!hLocalModule || ((PIMAGE_DOS_HEADER)hLocalModule)->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	if ((*pbAlrdyProtected = IsPatched(hLocalModule))) {
		printf("[i] Local Program Is Already Protected !\n");
		return TRUE;
	}

	szLocalImg = (LPWSTR)(((PPEB)__readgsqword(0x60))->ProcessParameters->ImagePathName.Buffer);

	if (!ReadSelfFromDisk(szLocalImg, &uWritableImgBase, &sLocalImgSize))
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
		HMODULE		hModule				= GetModuleHandleA(cDllName); // cDllName already loaded
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
			PIMAGE_NT_HEADERS		pDllImgNtHdrs				= NULL;
			PIMAGE_EXPORT_DIRECTORY		pExportDirectory			= NULL;
			PDWORD				pdwFunctionNameArray			= NULL;
			PDWORD				pdwFunctionAddressArray			= NULL;
			PWORD				pwFunctionOrdinalArray			= NULL;

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

	if (DeleteSelfFromDisk(szLocalImg))
		return WriteSelfToDisk(szLocalImg, uWritableImgBase, sLocalImgSize);
	else
		return FALSE; }


//----------------------------------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------

int main(int argc, char* argv[]) {

	printf("[*] Program That Patches Its Own IAT And Creates A New Version Of Itself On Disk\n");
	
	BOOL bAlrdyProtected = FALSE;

	if (!InstallSelfDRMPatch(&bAlrdyProtected))
		return -1;
	else
		if(!bAlrdyProtected) printf("[*] Current Binary Is Now Protected \n");

	return 0;
}
