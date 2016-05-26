#include <stdio.h>
#include <Windows.h>

int wmain(int argc, wchar_t **argv)
{
	if (argc < 2) {
		wprintf(L"StripBind v1.0, coded by sst311212\n\n");
		wprintf(L"usage: %s <exe> [EntryPoint]\n", argv[0]);
		return -1;
	}

	FILE *pExe, *pNew;
	_wfopen_s(&pExe, argv[1], L"rb");

	IMAGE_DOS_HEADER hDos;
	fread(&hDos, 1, sizeof(hDos), pExe);
	fseek(pExe, hDos.e_lfanew, SEEK_SET);

	IMAGE_NT_HEADERS hNt;
	fread(&hNt, 1, sizeof(hNt), pExe);

	int dwSections = hNt.OptionalHeader.SizeOfHeaders - ftell(pExe);
	auto szSections = new byte [dwSections];
	fread(szSections, 1, dwSections, pExe);

	auto pSec = (PIMAGE_SECTION_HEADER)szSections;
	for (int i = 0; i < hNt.FileHeader.NumberOfSections; i++) {
		if (!memcmp(pSec->Name, ".bind", 6)) {
			hNt.FileHeader.NumberOfSections--;
			hNt.OptionalHeader.SizeOfImage = pSec->VirtualAddress;
			if (argc == 3)
				swscanf_s(argv[2], L"%x", &hNt.OptionalHeader.AddressOfEntryPoint);
			int dwRawAddr = pSec->PointerToRawData;
			memset(pSec, 0, sizeof(*pSec));
			_wfopen_s(&pNew, L"Stripped.tmp", L"wb");
			fwrite(&hDos, 1, sizeof(hDos), pNew);
			fseek(pNew, hDos.e_lfanew, SEEK_SET);
			fwrite(&hNt, 1, sizeof(hNt), pNew);
			fwrite(szSections, 1, dwSections, pNew);
			auto buffer = new byte [hNt.OptionalHeader.FileAlignment];
			for (unsigned int j = 0; j < dwRawAddr - hNt.OptionalHeader.SizeOfHeaders; j += hNt.OptionalHeader.FileAlignment) {
				fread(buffer, 1, hNt.OptionalHeader.FileAlignment, pExe);
				fwrite(buffer, 1, hNt.OptionalHeader.FileAlignment, pNew);
			}
			fclose(pNew);
			fclose(pExe);
		}
		pSec++;
	}
	WCHAR szwOld[MAX_PATH];
	swprintf_s(szwOld, L"%s.Bak", argv[1]);
	MoveFile(argv[1], szwOld);
	MoveFile(L"Stripped.tmp", argv[1]);
	return 0;
}

