#include <stdio.h>
#include <Windows.h>

int wmain(int argc, wchar_t **argv)
{
	if (argc < 2) {
		wprintf(L"StripBind v1.1, coded by sst311212\n\n");
		wprintf(L"usage: %s <exe> [EntryPoint]\n", argv[0]);
		return -1;
	}

	WCHAR szOldFile[MAX_PATH];
	swprintf_s(szOldFile, L"%s.Bak", argv[1]);
	MoveFile(argv[1], szOldFile);

	FILE *pExe, *pNew;
	_wfopen_s(&pExe, szOldFile, L"rb");
	
	IMAGE_DOS_HEADER hDos;
	fread(&hDos, 1, sizeof(hDos), pExe);
	fseek(pExe, hDos.e_lfanew, SEEK_SET);

	IMAGE_NT_HEADERS hNt;
	fread(&hNt, 1, sizeof(hNt), pExe);

	int SecSize = hNt.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	auto SecHdr = new byte [SecSize];
	fread(SecHdr, 1, SecSize, pExe);
	auto pSec = (PIMAGE_SECTION_HEADER)SecHdr;
	for (int i = 0; i < hNt.FileHeader.NumberOfSections; i++, pSec++)
	{
		if (!memcmp(pSec->Name, ".bind", 6))
		{
			DWORD signature;
			fseek(pExe, hNt.OptionalHeader.AddressOfEntryPoint - pSec->VirtualAddress + pSec->PointerToRawData, SEEK_SET);
			fread(&signature, 1, sizeof(DWORD), pExe);
			if (signature == 0xE8)
			{
				fseek(pExe, ftell(pExe) - 0xD4, SEEK_SET);
				auto buffer = new unsigned int [52];
				fread(buffer, 1, 52 * 4, pExe);
				for (int j = 0; j < 52; j++)
					buffer[j] ^= buffer[j + 1];
				hNt.OptionalHeader.AddressOfEntryPoint = buffer[6];
			}
			hNt.FileHeader.NumberOfSections -= 1;
			if (argc == 3)
				swscanf_s(argv[2], L"%x", &hNt.OptionalHeader.AddressOfEntryPoint);
			hNt.OptionalHeader.SizeOfImage = pSec->VirtualAddress;
			memset(pSec, 0, sizeof(IMAGE_SECTION_HEADER));
			pSec -= 1;
			_wfopen_s(&pNew, argv[1], L"wb");
			fwrite(&hDos, 1, sizeof(hDos), pNew);
			fseek(pNew, hDos.e_lfanew, SEEK_SET);
			fwrite(&hNt, 1, sizeof(hNt), pNew);
			fwrite(SecHdr, 1, SecSize, pNew);
			fseek(pExe, hNt.OptionalHeader.SizeOfHeaders, SEEK_SET);
			fseek(pNew, hNt.OptionalHeader.SizeOfHeaders, SEEK_SET);
			auto buffer = new byte [hNt.OptionalHeader.FileAlignment];
			DWORD dwPebSize = pSec->PointerToRawData + pSec->SizeOfRawData - hNt.OptionalHeader.SizeOfHeaders;
			for (unsigned int j = 0; j < dwPebSize; j += hNt.OptionalHeader.FileAlignment) {
				fread(buffer, 1, hNt.OptionalHeader.FileAlignment, pExe);
				fwrite(buffer, 1, hNt.OptionalHeader.FileAlignment, pNew);
			}
			fclose(pNew);
		}
	}
	fclose(pExe);
	return 0;
}

