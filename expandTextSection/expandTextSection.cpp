#include <string>
#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <regex>
#include <sstream>
#include <windows.h>
#include <stdio.h>
#include <algorithm>
#include <Zydis/Zydis.h>
#include<ImageHlp.h>
#include "CmdlineParser.hpp"

#pragma comment(lib,"ImageHlp.lib")

using namespace std;

int FileSize;

typedef struct {
	char* dismStr;
	DWORD runtime_address;
	DWORD runtime_address_foa;
	DWORD dispOffset;
	DWORD immOffset;
}DismInfo, * PDismInfo;

map<DWORD, DismInfo> dismMap;
BYTE* dismArray;

struct CallbackInfo {
	PBYTE imageBase;
	DWORD codeFoa;
	DWORD length;
	DWORD runtime_address;
	bool is64bit;
	int level;
};
CallbackInfo cbInfo;

map<DWORD, bool> addrRVAMap;

DWORD rvaToFOA(LPVOID buf, int rva)
{
	PIMAGE_DOS_HEADER  pDH = (PIMAGE_DOS_HEADER)buf;
	IMAGE_SECTION_HEADER* sectionHeader;

	if (*(PWORD)((size_t)pDH + pDH->e_lfanew + 0x18) == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		PIMAGE_NT_HEADERS32  pNtH32 = PIMAGE_NT_HEADERS32((size_t)pDH + pDH->e_lfanew);

		sectionHeader = IMAGE_FIRST_SECTION(pNtH32);
	}
	else {
		PIMAGE_NT_HEADERS64 pNtH64 = PIMAGE_NT_HEADERS64((size_t)pDH + pDH->e_lfanew);

		sectionHeader = IMAGE_FIRST_SECTION(pNtH64);
	}

	while (sectionHeader->VirtualAddress != 0)
	{
		if (rva >= sectionHeader->VirtualAddress && rva < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
			return rva - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;
		}

		sectionHeader++;
	}

	return 0;
}

DWORD foaToRVA(LPVOID lpBuffer, DWORD FOA) {
	PIMAGE_DOS_HEADER pDH = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_FILE_HEADER pFile;
	PIMAGE_SECTION_HEADER pFirstSection;

	if (*(PWORD)((size_t)pDH + pDH->e_lfanew + 0x18) == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		PIMAGE_NT_HEADERS32  pNtH32 = PIMAGE_NT_HEADERS32((size_t)pDH + pDH->e_lfanew);
		PIMAGE_OPTIONAL_HEADER32 pOH32 = &pNtH32->OptionalHeader;
		pFile = (PIMAGE_FILE_HEADER)((size_t)pNtH32 + 4);
		pFirstSection = PIMAGE_SECTION_HEADER((size_t)pOH32 + pFile->SizeOfOptionalHeader);

		if (FOA < pOH32->SizeOfHeaders || pOH32->FileAlignment == pOH32->SectionAlignment) {
			return FOA;
		}
	}
	else {
		PIMAGE_NT_HEADERS64 pNtH64 = PIMAGE_NT_HEADERS64((size_t)pDH + pDH->e_lfanew);
		PIMAGE_OPTIONAL_HEADER64 pOH64 = &pNtH64->OptionalHeader;
		pFile = (PIMAGE_FILE_HEADER)((size_t)pNtH64 + 4);
		pFirstSection = PIMAGE_SECTION_HEADER((size_t)pOH64 + pFile->SizeOfOptionalHeader);

		if (FOA < pOH64->SizeOfHeaders || pOH64->FileAlignment == pOH64->SectionAlignment) {
			return FOA;
		}
	}

	PIMAGE_SECTION_HEADER pSectionHeader = pFirstSection;

	for (int i = 0; pFile->NumberOfSections; i++) {
		if (FOA >= pSectionHeader->PointerToRawData &&
			FOA < pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData) {
			/*获取FOA和节区文件地址的偏移*/
			DWORD relSectionFileAdd = FOA - pSectionHeader->PointerToRawData;
			/*偏移加节区的VA得到RVA*/
			return relSectionFileAdd + pSectionHeader->VirtualAddress;
		}
		/*指向下一个节表*/
		pSectionHeader = (PIMAGE_SECTION_HEADER)((size_t)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);
	}

	return 0;
}

void traverseResourceDirectory(PIMAGE_RESOURCE_DIRECTORY pBaseResourceDir, PIMAGE_RESOURCE_DIRECTORY pResourceDir, SIZE_T baseAddress, DWORD expandVirtualSize) {
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir + 1);

	DWORD dwTypeCount = pResourceDir->NumberOfIdEntries + pResourceDir->NumberOfNamedEntries;
	for (DWORD i = 0; i < dwTypeCount; i++)
	{
		if (pResourceEntry[i].DataIsDirectory == 1) {
			PIMAGE_RESOURCE_DIRECTORY pRes = (PIMAGE_RESOURCE_DIRECTORY)((size_t)pBaseResourceDir + pResourceEntry[i].OffsetToDirectory);
			traverseResourceDirectory(pBaseResourceDir, pRes, baseAddress, expandVirtualSize);
		}
		else {
			PIMAGE_RESOURCE_DATA_ENTRY pResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((size_t)pBaseResourceDir + pResourceEntry[i].OffsetToData);
			if (0x23a90 == pResDataEntry->OffsetToData)
				int xx = 1;
			addrRVAMap[pResDataEntry->OffsetToData] = true;
			pResDataEntry->OffsetToData += expandVirtualSize;
		}
	}
}

BYTE* readSectionData(BYTE* buffer, PDWORD rdataLength, char* secName) {
	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Invalid DOS header.\n");
		return 0;
	}

	PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(buffer) + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("Invalid NT header.\n");
		return 0;
	}

	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
		if (strcmp(secName, (char*)sectionHeader[i].Name) == 0) {
			*rdataLength = sectionHeader[i].SizeOfRawData;
			return reinterpret_cast<BYTE*>(buffer) + sectionHeader[i].PointerToRawData;
		}
	}

	return 0;
}

void dismCode(PBYTE imageBase, DWORD codeFoa, DWORD length, DWORD runtime_address, bool is64bit, int level)
{
	if (level == 0)
		memset(&cbInfo, 0, sizeof(cbInfo));

	if (dismMap.find(runtime_address) != dismMap.end()) {
		return;
	}

	ZydisDecoder decoder;
	if (is64bit)
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	else
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
	ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);

	ZyanUSize offset = 0;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	uint8_t* code = imageBase + codeFoa;

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code + offset, length - offset, &instruction, operands)))
	{
		char buffer[256];
		ZydisFormatterFormatInstruction(&formatter, &instruction, operands, instruction.operand_count_visible, &buffer[0], sizeof(buffer), runtime_address, ZYAN_NULL);

		if (strcmp(buffer, "int3") == 0) {
			for (int i = offset, j = 0; code[i] == 0xCC; i++, j++)
			{
				*(PBYTE)((PBYTE)dismArray + runtime_address + j) = 1;
			}
			break;
		}
		
		int strLength = strlen(buffer) + 1;
		DismInfo info;
		memset(&info, 0, sizeof(info));

		info.dismStr = new char[strLength];
		memcpy(info.dismStr, buffer, strLength);
		info.runtime_address = runtime_address;
		info.runtime_address_foa = rvaToFOA(imageBase, runtime_address);
		info.dispOffset = instruction.raw.disp.offset;
		info.immOffset = instruction.raw.imm->offset;

		if (info.runtime_address_foa > 0) {
			dismMap[runtime_address] = info;
			memset(dismArray + runtime_address, 1, instruction.length);
		}
		else
			break;

		if ((strstr(buffer, "call") != 0 || buffer[0] == 'j')) {
			char* token = strtok(buffer, " ");
			token = strtok(NULL, " ");

			if (token != 0) {
				char* endPtr;
				DWORD number = strtoul(token, &endPtr, 16);
				if (*endPtr == '\0') {
					if (level < 200)
						dismCode(imageBase, rvaToFOA(imageBase, number), length, number, is64bit, ++level);
					else {
						cbInfo.imageBase = imageBase;
						cbInfo.codeFoa = rvaToFOA(imageBase, number);
						cbInfo.length = length;
						cbInfo.runtime_address = number;
						cbInfo.is64bit = is64bit;
						cbInfo.level = 0;
						return;
					}
				}
			}
		}

		offset += instruction.length;
		runtime_address += instruction.length;
	}

	if (level == 0 && cbInfo.codeFoa > 0)
		dismCode(cbInfo.imageBase, cbInfo.codeFoa, cbInfo.length, cbInfo.runtime_address, cbInfo.is64bit, cbInfo.level);
}

string dwordToUpperCaseString(DWORD value) {
	stringstream ss;
	ss << uppercase << hex << value;
	return ss.str();
}

void repairReloc(BYTE* buffer, PIMAGE_BASE_RELOCATION pRelocBlock, long long beginVirtualAddr, long long endVirtualAddr, DWORD expandSize, long long imageBase, bool is64bit)
{
	while (pRelocBlock->VirtualAddress != 0 && pRelocBlock->SizeOfBlock != 0) {
		WORD* pRelocEntry = reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(pRelocBlock) + sizeof(IMAGE_BASE_RELOCATION));

		DWORD numRelocs = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		for (DWORD i = 0; i < numRelocs; i++) {
			if (pRelocEntry[i] != 0) {
				WORD relocType = (pRelocEntry[i] & 0xF000) >> 12;
				WORD relocOffset = pRelocEntry[i] & 0x0FFF;

				size_t relocAddr = (size_t)buffer + rvaToFOA(buffer, pRelocBlock->VirtualAddress + relocOffset);
				if (is64bit) {
					if (*(long long*)relocAddr >= endVirtualAddr + imageBase) {
						addrRVAMap[relocAddr] = true;
						*(long long*)relocAddr += expandSize;
					}
					else
						addrRVAMap[relocAddr] = true; //重定位表中的数据后续不需要再处理了
				}
				else {
					if (*(DWORD*)relocAddr >= endVirtualAddr + imageBase) {
						addrRVAMap[relocAddr] = true;
						*(DWORD*)relocAddr += expandSize;
					}
					else
						addrRVAMap[relocAddr] = true;
				}
			}
		}

		if (pRelocBlock->VirtualAddress >= endVirtualAddr)
			pRelocBlock->VirtualAddress += expandSize;

		pRelocBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>((reinterpret_cast<BYTE*>(pRelocBlock)) + pRelocBlock->SizeOfBlock);
	}
}

void removeSign(BYTE* buffer)
{
	PIMAGE_DOS_HEADER pDH = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_FILE_HEADER pFH;
	PIMAGE_SECTION_HEADER pSection;
	PIMAGE_DATA_DIRECTORY directory;

	if (*(PWORD)((size_t)pDH + pDH->e_lfanew + 0x18) == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		PIMAGE_NT_HEADERS32  pNtH32 = PIMAGE_NT_HEADERS32((size_t)pDH + pDH->e_lfanew);
		PIMAGE_OPTIONAL_HEADER32 pOH32 = &pNtH32->OptionalHeader;

		pFH = &pNtH32->FileHeader;
		pSection = (PIMAGE_SECTION_HEADER)((BYTE*)pOH32 + pFH->SizeOfOptionalHeader);
		directory = &(pOH32->DataDirectory[4]);
	}
	else {
		PIMAGE_NT_HEADERS64 pNtH64 = PIMAGE_NT_HEADERS64((size_t)pDH + pDH->e_lfanew);
		PIMAGE_OPTIONAL_HEADER64 pOH64 = &pNtH64->OptionalHeader;

		pFH = &pNtH64->FileHeader;
		pSection = (PIMAGE_SECTION_HEADER)((BYTE*)pOH64 + pFH->SizeOfOptionalHeader);
		directory = &(pOH64->DataDirectory[4]);
	}

	DWORD dwSectionNum = pFH->NumberOfSections;
	pSection = pSection + dwSectionNum - 1;

	FileSize = pSection->SizeOfRawData + pSection->PointerToRawData;

	directory->Size = 0;
	directory->VirtualAddress = 0;
}

char* addSign(char* buffer, string signPath)
{
	ifstream inFile(signPath, std::ios::binary);
	if (!inFile) {
		cout << "signPath open fail" << endl;
		return NULL;
	}

	inFile.seekg(0, std::ios::end);
	std::streamsize signFileSize = inFile.tellg();
	inFile.seekg(0, std::ios::beg);

	char* signBuffer = new char[signFileSize];

	if (!inFile.read(signBuffer, signFileSize)) {
		cout << "signPath read fail" << endl;
		delete[] signBuffer;
		return NULL;
	}

	PIMAGE_DOS_HEADER pDH = (PIMAGE_DOS_HEADER)signBuffer;
	PIMAGE_FILE_HEADER pFH;
	PIMAGE_SECTION_HEADER pSection;

	if (*(PWORD)((size_t)pDH + pDH->e_lfanew + 0x18) == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		PIMAGE_NT_HEADERS32  pNtH32 = PIMAGE_NT_HEADERS32((size_t)pDH + pDH->e_lfanew);
		PIMAGE_OPTIONAL_HEADER32 pOH32 = &pNtH32->OptionalHeader;

		pFH = &pNtH32->FileHeader;
		pSection = (PIMAGE_SECTION_HEADER)((BYTE*)pOH32 + pFH->SizeOfOptionalHeader);
	}
	else {
		PIMAGE_NT_HEADERS64 pNtH64 = PIMAGE_NT_HEADERS64((size_t)pDH + pDH->e_lfanew);
		PIMAGE_OPTIONAL_HEADER64 pOH64 = &pNtH64->OptionalHeader;

		pFH = &pNtH64->FileHeader;
		pSection = (PIMAGE_SECTION_HEADER)((BYTE*)pOH64 + pFH->SizeOfOptionalHeader);
	}

	DWORD dwSectionNum = pFH->NumberOfSections;
	pSection = pSection + dwSectionNum - 1;

	DWORD length = signFileSize - (pSection->SizeOfRawData + pSection->PointerToRawData);

	DWORD tempFileSize = FileSize + length;
	char* newBuffer = new char[tempFileSize];
	memset(newBuffer, 0, tempFileSize);
	memcpy(newBuffer, buffer, FileSize);
	delete[] buffer;
	buffer = newBuffer;

	memcpy(buffer + FileSize, signBuffer + pSection->SizeOfRawData + pSection->PointerToRawData, length);

	pDH = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_DATA_DIRECTORY directory;
	PDWORD checkSumValue;

	if (*(PWORD)((size_t)pDH + pDH->e_lfanew + 0x18) == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		PIMAGE_NT_HEADERS32  pNtH32 = PIMAGE_NT_HEADERS32((size_t)pDH + pDH->e_lfanew);
		PIMAGE_OPTIONAL_HEADER32 pOH32 = &pNtH32->OptionalHeader;

		pFH = &pNtH32->FileHeader;
		pSection = (PIMAGE_SECTION_HEADER)((BYTE*)pOH32 + pFH->SizeOfOptionalHeader);
		directory = &(pOH32->DataDirectory[4]);
		checkSumValue = &(pOH32->CheckSum);
	}
	else {
		PIMAGE_NT_HEADERS64 pNtH64 = PIMAGE_NT_HEADERS64((size_t)pDH + pDH->e_lfanew);
		PIMAGE_OPTIONAL_HEADER64 pOH64 = &pNtH64->OptionalHeader;

		pFH = &pNtH64->FileHeader;
		pSection = (PIMAGE_SECTION_HEADER)((BYTE*)pOH64 + pFH->SizeOfOptionalHeader);
		directory = &(pOH64->DataDirectory[4]);
		checkSumValue = &(pOH64->CheckSum);
	}

	dwSectionNum = pFH->NumberOfSections;
	pSection = pSection + dwSectionNum - 1;

	directory->Size = length;
	directory->VirtualAddress = pSection->SizeOfRawData + pSection->PointerToRawData;

	FileSize += length;

	DWORD HeaderSum, CheckSum;
	CheckSumMappedFile(buffer, FileSize, &HeaderSum, &CheckSum);

	*checkSumValue = CheckSum;

	return buffer;
}

bool expandSection(char** buffer, DWORD expandSize) {
	PIMAGE_DOS_HEADER  pDH = (PIMAGE_DOS_HEADER)*buffer;
	IMAGE_FILE_HEADER fh;
	_IMAGE_SECTION_HEADER* sectionHeader;
	DWORD sectionAlignment;
	DWORD oep;
	PDWORD sizeOfImage;
	PDWORD sizeOfCode;
	PDWORD baseOfData;
	IMAGE_DATA_DIRECTORY* dataDirectory;
	DWORD THUNK_DATA_SIZE;
	bool is64bit = false;
	ULONGLONG imageBase;

	if (*(PWORD)((size_t)pDH + pDH->e_lfanew + 0x18) == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		PIMAGE_NT_HEADERS32  pNtH32 = PIMAGE_NT_HEADERS32((size_t)pDH + pDH->e_lfanew);
		PIMAGE_OPTIONAL_HEADER32 pOH32 = &pNtH32->OptionalHeader;
		fh = pNtH32->FileHeader;
		sectionAlignment = pOH32->SectionAlignment;
		sizeOfImage = &(pOH32->SizeOfImage);
		sizeOfCode = &(pOH32->SizeOfCode);
		baseOfData = &(pOH32->BaseOfData);
		sectionHeader = (_IMAGE_SECTION_HEADER*)((UINT)pNtH32 + sizeof(_IMAGE_NT_HEADERS));
		dataDirectory = pOH32->DataDirectory;
		THUNK_DATA_SIZE = 4;
		imageBase = pOH32->ImageBase;
		pOH32->CheckSum = 0;
		oep = pOH32->AddressOfEntryPoint;
	}
	else {
		PIMAGE_NT_HEADERS64 pNtH64 = PIMAGE_NT_HEADERS64((size_t)pDH + pDH->e_lfanew);
		PIMAGE_OPTIONAL_HEADER64 pOH64 = &pNtH64->OptionalHeader;
		fh = pNtH64->FileHeader;
		sectionAlignment = pOH64->SectionAlignment;
		sizeOfImage = &(pOH64->SizeOfImage);
		sizeOfCode = &(pOH64->SizeOfCode);
		baseOfData = 0;
		sectionHeader = (_IMAGE_SECTION_HEADER*)((UINT)pNtH64 + sizeof(_IMAGE_NT_HEADERS64));
		dataDirectory = pOH64->DataDirectory;
		THUNK_DATA_SIZE = 8;
		is64bit = true;
		imageBase = pOH64->ImageBase;
		pOH64->CheckSum = 0;
		oep = pOH64->AddressOfEntryPoint;
	}

	if (dataDirectory[5].VirtualAddress == 0) {
		printf("expand exe is not have reloc table\n");
		return false;
	}

	removeSign((PBYTE)pDH);

	expandSize = ceil((expandSize * 1.0) / sectionAlignment) * sectionAlignment;

	_IMAGE_SECTION_HEADER** sectionArr = (_IMAGE_SECTION_HEADER**)malloc(sizeof(_IMAGE_SECTION_HEADER*) * fh.NumberOfSections);

	int cnt = 0;
	_IMAGE_SECTION_HEADER* textSection = NULL;
	while (cnt < fh.NumberOfSections) {
		_IMAGE_SECTION_HEADER* section;
		section = (_IMAGE_SECTION_HEADER*)((UINT)sectionHeader + sizeof(_IMAGE_SECTION_HEADER) * cnt);

		sectionArr[cnt++] = section;

		if (strcmp((const char*)(section->Name), ".text") == 0) {
			textSection = section;
			break;
		}
	}

	//获得text节的实际大小
	DWORD VirtualSize = textSection->Misc.VirtualSize;
	//获得text节的文件对齐后的大小
	DWORD SizeOfRawData = textSection->SizeOfRawData;

	//算出text节内存对齐后的大小
	UINT SizeInMemory = (UINT)ceil((double)max(VirtualSize, SizeOfRawData) / double(sectionAlignment)) * sectionAlignment;

	UINT offset = SizeInMemory - textSection->SizeOfRawData;

	//根据节在文件中的偏移 + 文件对齐后的大小 得到节的末尾
	UINT end = textSection->PointerToRawData + textSection->SizeOfRawData;

	DWORD textVirtualEndAddr = ((_IMAGE_SECTION_HEADER*)((UINT)sectionHeader + sizeof(_IMAGE_SECTION_HEADER) * cnt))->VirtualAddress;

	//修复资源表
	if (dataDirectory[2].VirtualAddress > 0) {
		PIMAGE_RESOURCE_DIRECTORY pBaseResourceDir = (PIMAGE_RESOURCE_DIRECTORY)(rvaToFOA(pDH, dataDirectory[2].VirtualAddress) + (size_t)pDH);
		traverseResourceDirectory(pBaseResourceDir, pBaseResourceDir, (SIZE_T)pDH, expandSize);
	}

	PIMAGE_BASE_RELOCATION pRelocBlock = (PIMAGE_BASE_RELOCATION)(rvaToFOA(pDH, dataDirectory[5].VirtualAddress) + (size_t)pDH);
	repairReloc((PBYTE)pDH, pRelocBlock, textSection->VirtualAddress, textVirtualEndAddr, expandSize, imageBase, is64bit);

	if (is64bit) {
		DWORD textLength;
		BYTE* textData = readSectionData((PBYTE)pDH, &textLength, (char*)".text");
		DWORD vaule;
		DWORD textVirtualAddress = textSection->VirtualAddress;
		DWORD textAddress = textSection->PointerToRawData;

		dismArray = (PBYTE)malloc(textLength + textVirtualAddress);
		memset(dismArray, 0, textLength + textVirtualAddress);

		DWORD oep_foa = rvaToFOA(pDH, oep);
		dismCode((PBYTE)pDH, oep_foa, textLength, oep, is64bit, 0);

		for (DWORD i = 0; i < textLength; i++) {
			if (dismArray[textVirtualAddress + i] != 1) {
				dismCode((PBYTE)pDH, textAddress + i, textLength, textVirtualAddress + i, is64bit, 0);
			}
		}
		free(dismArray);

		regex pattern("(?:ds|ss):\\[.*?(0x[0-9A-Fa-f]+)\\]");
		regex pattern1(",.*?(0x[0-9A-Fa-f]+)");
		smatch matches;

		DWORD fixOffset;
		for (const auto& pair : dismMap) {
			DismInfo dismInfo = pair.second;

			if (strstr(dismInfo.dismStr, "ds:") != 0 || strstr(dismInfo.dismStr, "ss:") != 0) {
				string input(dismInfo.dismStr);
				if (regex_search(input, matches, pattern) || regex_search(input, matches, pattern1)) {
					if (matches.size() > 1) {
						string addressStr = matches[1];
						ULONGLONG address = stoull(addressStr, nullptr, 16);

						if (address >= textVirtualEndAddr && address < *sizeOfImage) {
							fixOffset = dismInfo.dispOffset;
							if (!regex_search(input, matches, pattern))
								fixOffset = dismInfo.immOffset;

							DWORD fixAddr = (DWORD)pDH + dismInfo.runtime_address_foa + fixOffset;
							*(DWORD*)fixAddr += expandSize;
						}
					}
				}
			}
			delete[] dismInfo.dismStr;
		}
		dismMap.clear();

		DWORD improtStrMin = 0xFFFFFFFF, improtStrMax = 0;
		PIMAGE_IMPORT_DESCRIPTOR ImportTable = PIMAGE_IMPORT_DESCRIPTOR(rvaToFOA(pDH, dataDirectory[1].VirtualAddress) + (size_t)pDH);
		while (ImportTable->Name)
		{
			PIMAGE_THUNK_DATA pThunk = PIMAGE_THUNK_DATA(rvaToFOA(pDH, ImportTable->OriginalFirstThunk) + (size_t)pDH);

			while (pThunk->u1.AddressOfData)
			{
				//简单处理32，64下导入函数为序号问题
				if (pThunk->u1.Ordinal > 0xFFFF) {

					PIMAGE_IMPORT_BY_NAME pByName = (PIMAGE_IMPORT_BY_NAME)((size_t)pDH + rvaToFOA(pDH, pThunk->u1.AddressOfData));

					improtStrMax = max(improtStrMax, (DWORD)pThunk->u1.AddressOfData + 2 + strlen((const char*)pByName->Name));

					improtStrMin = min(improtStrMin, pThunk->u1.AddressOfData);
				}

				pThunk = PIMAGE_THUNK_DATA((PBYTE)pThunk + THUNK_DATA_SIZE);
			}

			char* dllName = (char*)((size_t)pDH + rvaToFOA(pDH, ImportTable->Name));
			improtStrMax = max(improtStrMax, (DWORD)ImportTable->Name + strlen(dllName));
			improtStrMin = min(improtStrMin, ImportTable->Name);

			ImportTable++;
		}

		textData = readSectionData((PBYTE)pDH, &textLength, (char*)".idata");
		if (textData) {
			for (DWORD i = 0; i < textLength; i += 4) {
				DWORD addr = DWORD(textData + i);
				DWORD addrRVA = foaToRVA(pDH, addr - size_t(pDH));
				if (*(PDWORD)(addr) >= textVirtualEndAddr && *(PDWORD)(addr) < *sizeOfImage && (addrRVA < improtStrMin || addrRVA > improtStrMax)) {
					if (addrRVAMap.find((DWORD)textData + i) == addrRVAMap.end())
						*(PDWORD)(textData + i) += expandSize;
				}
			}
		}

		textData = readSectionData((PBYTE)pDH, &textLength, (char*)".rdata");
		if (textData) {
			for (DWORD i = 0; i < textLength; i += 4) {
				DWORD addr = DWORD(textData + i);
				DWORD addrRVA = foaToRVA(pDH, addr - size_t(pDH));
				
				if (*(PDWORD)(addr) >= textVirtualEndAddr && *(PDWORD)(addr) < *sizeOfImage && (addrRVA < improtStrMin || addrRVA > improtStrMax)) {
					if (addrRVAMap.find((DWORD)textData + i) == addrRVAMap.end()) {
						*(PDWORD)(textData + i) += expandSize;
					}
				}
			}
		}

		textData = readSectionData((PBYTE)pDH, &textLength, (char*)".pdata");
		if (textData) {
			for (DWORD i = 0; i < textLength; i += 4) {
				DWORD addr = DWORD(textData + i);
				DWORD addrRVA = foaToRVA(pDH, addr - size_t(pDH));
				if (*(PDWORD)(addr) >= textVirtualEndAddr && *(PDWORD)(addr) < *sizeOfImage && (addrRVA < improtStrMin || addrRVA > improtStrMax)) {
					if (addrRVAMap.find((DWORD)textData + i) == addrRVAMap.end())
						*(PDWORD)(textData + i) += expandSize;
				}
			}
		}
	}
	else {
		PIMAGE_IMPORT_DESCRIPTOR ImportTable = PIMAGE_IMPORT_DESCRIPTOR(rvaToFOA(pDH, dataDirectory[1].VirtualAddress) + (size_t)pDH);
		while (ImportTable->Name)
		{
			PIMAGE_THUNK_DATA INT = PIMAGE_THUNK_DATA(rvaToFOA(pDH, ImportTable->OriginalFirstThunk) + (size_t)pDH);
			PIMAGE_THUNK_DATA IAT = PIMAGE_THUNK_DATA(rvaToFOA(pDH, ImportTable->FirstThunk) + (size_t)pDH);

			char* pName = (char*)(rvaToFOA(pDH, ImportTable->Name) + (size_t)pDH);

			while (INT->u1.AddressOfData)
			{
				if (!(INT->u1.Ordinal & 0x80000000) && INT->u1.AddressOfData >= textVirtualEndAddr)//判断是不是按照序号导入
					INT->u1.AddressOfData += expandSize;
				INT = PIMAGE_THUNK_DATA((PBYTE)INT + THUNK_DATA_SIZE);
			}

			while (IAT->u1.AddressOfData)
			{
				if (!(IAT->u1.AddressOfData & 0x80000000) && IAT->u1.AddressOfData >= textVirtualEndAddr)
					IAT->u1.AddressOfData += expandSize;
				IAT = PIMAGE_THUNK_DATA((PBYTE)IAT + THUNK_DATA_SIZE);
			}

			if (ImportTable->Name >= textVirtualEndAddr) {
				ImportTable->Characteristics += expandSize;
				ImportTable->Name += expandSize;
				ImportTable->FirstThunk += expandSize;
			}

			ImportTable++;
		}

		if (dataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress > 0) {
			//修复延迟导入表
			PIMAGE_DELAYLOAD_DESCRIPTOR pDelayImportDescriptor = (PIMAGE_DELAYLOAD_DESCRIPTOR)((size_t)pDH + rvaToFOA(pDH, dataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress));

			while (pDelayImportDescriptor->DllNameRVA != 0) {
				// 解析延迟加载描述符中的导入名称表地址和导入地址表地址
				DWORD importNameTableRVA = pDelayImportDescriptor->ImportNameTableRVA;
				DWORD importAddressTableRVA = pDelayImportDescriptor->ImportAddressTableRVA;

				pDelayImportDescriptor->DllNameRVA += expandSize;
				pDelayImportDescriptor->ModuleHandleRVA += expandSize;
				pDelayImportDescriptor->ImportNameTableRVA += expandSize;
				pDelayImportDescriptor->ImportAddressTableRVA += expandSize;
				pDelayImportDescriptor->BoundImportAddressTableRVA += expandSize;

				DWORD* pImportNameTable = (PDWORD)((size_t)pDH + rvaToFOA(pDH, importNameTableRVA));

				// 遍历导入函数表，直到遇到终止标志
				while (*pImportNameTable != 0) {
					*pImportNameTable += expandSize;

					++pImportNameTable;
				}

				++pDelayImportDescriptor;
			}
		}
	}

	//修正节表成员
	textSection->Misc.VirtualSize = SizeInMemory + expandSize;
	textSection->SizeOfRawData = SizeInMemory + expandSize;

	//修正SizeOfImage
	*sizeOfImage = *sizeOfImage + expandSize;

	*sizeOfCode = *sizeOfCode + expandSize + offset;

	if (baseOfData != 0)
		*baseOfData = *baseOfData + expandSize;


	while (cnt < fh.NumberOfSections) {
		_IMAGE_SECTION_HEADER* section;
		section = (_IMAGE_SECTION_HEADER*)((UINT)sectionHeader + sizeof(_IMAGE_SECTION_HEADER) * cnt);

		section->PointerToRawData += (offset + expandSize);
		section->VirtualAddress += expandSize;

		cnt++;
	}

	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		if (dataDirectory[i].VirtualAddress >= textVirtualEndAddr)
			dataDirectory[i].VirtualAddress += expandSize;
	}

	char* newBuffer = new char[FileSize + expandSize + offset];

	memcpy(newBuffer, *buffer, end);
	memset((PBYTE)newBuffer + end, 0, expandSize + offset);
	memcpy(newBuffer + end + expandSize + offset, (PBYTE)(*buffer) + end, FileSize - end);

	FileSize += (expandSize + offset);

	delete[] * buffer;
	*buffer = newBuffer;

	return true;
}

bool saveFile(string filePath, char* buffer)
{
	ofstream outFile;
	outFile.open(filePath, ios::binary | ios::trunc);
	if (!outFile.is_open()) {
		printf("Failed to open file for writing.\n");
		return false;
	}
	outFile.write(buffer, FileSize);
	outFile.close();

	return true;
}

int readFileContext(string path, char** contexts)
{
	ifstream inFile(path, ios::binary);
	if (!inFile) {
		printf("%s open fail\n", path.c_str());
		return -1;
	}

	inFile.seekg(0, ios::end);
	streamsize payloadFileSize = inFile.tellg();
	inFile.seekg(0, ios::beg);

	*contexts = new char[payloadFileSize];

	if (!inFile.read(*contexts, payloadFileSize)) {
		printf("%s payloadBuffer read fail\n", path.c_str());
		delete[] contexts;
		return -1;
	}

	return payloadFileSize;
}

int main(int argc, char* argv[]) {
	char input[0x255] = { 0 };
	char output[0x255] = { 0 };
	DWORD expandSize = 0;

	get_opt(argc, argv, OPT_TYPE_STRING, output, "o", "output", NULL);
	get_opt(argc, argv, OPT_TYPE_STRING, input, "i", "input", NULL);
	get_opt(argc, argv, OPT_TYPE_HEX, &expandSize, "a", "add", NULL);

	if (input[0] == NULL || expandSize == 0) {
		printf("params check fail!\nFor example: expandTextSection -i or --input D:\\test.exe [-o D:\\test_tmp.exe] -a 0x1000\n");
		return 0;
	}

	char* pyloadbuffer;
	FileSize = readFileContext(input, &pyloadbuffer);
	if (FileSize == -1)
		return 0;

	if (!expandSection(&pyloadbuffer, expandSize))
		return 0;

	pyloadbuffer = addSign(pyloadbuffer, input);

	if (output[0] == NULL) {
		string inputPath(input);
		string outFilePath = inputPath + "_tmp";

		int index = inputPath.rfind(".");
		if (index != string::npos && index != 0)
			outFilePath = inputPath.substr(0, index) + "_tmp" + inputPath.substr(index);

		strcpy(output, outFilePath.c_str());
	}

	if (saveFile(output, pyloadbuffer))
		printf("expand succ! save path as %s\n", output);

	return 0;
}