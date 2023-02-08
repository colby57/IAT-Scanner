#include "IATScan.hpp"

void Engine::OutputCorruptedFunctions()
{
    if ( m_cCorruptedFunctions.empty() ) 
    {
        printf( "[~] No corrupted functions found!\n" );
        return;
    }

    for ( const auto& Iterator : m_cCorruptedFunctions )
        printf( "[!] Module: %s\tFunction: %s\tAddress: 0x%p\n", Iterator.m_cModuleName.c_str(), Iterator.m_cFunctionName.c_str(), Iterator.m_pAddress );
}

void Engine::AddFunction( const S_CorruptedFunction& cCorruptedFunctions )
{
    m_cCorruptedFunctions.push_back( cCorruptedFunctions );
}

bool Engine::IATScan()
{
	LPVOID lpBaseAddress = (LPVOID) GetModuleHandle( NULL );

	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	IMAGE_OPTIONAL_HEADER pOptionalHeader;
	IMAGE_DATA_DIRECTORY pImportDirectory;
	DWORD dwStartRVA;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;

	pDosHeader = (PIMAGE_DOS_HEADER) lpBaseAddress;

	if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
		return false;

	pNtHeader = (PIMAGE_NT_HEADERS) ( (DWORD_PTR) lpBaseAddress + pDosHeader->e_lfanew );

	if ( pNtHeader->Signature != IMAGE_NT_SIGNATURE )
		return false;

	pOptionalHeader = pNtHeader->OptionalHeader;

	pImportDirectory = pOptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	dwStartRVA = pImportDirectory.VirtualAddress;

	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) ( (DWORD_PTR) lpBaseAddress + dwStartRVA );

	if ( pImportDescriptor == NULL )
		return false;

	DWORD dwIndex = -1;

	while ( pImportDescriptor[ ++dwIndex ].Characteristics != 0 )
	{
		PIMAGE_THUNK_DATA pOriginalFirstThunk;
		PIMAGE_THUNK_DATA pFirstThunk;

		char* pDllName = (char*) ( (DWORD_PTR) lpBaseAddress + pImportDescriptor[ dwIndex ].Name );

		HMODULE hModule = GetModuleHandleA( pDllName );

		pOriginalFirstThunk = (PIMAGE_THUNK_DATA) ( (DWORD_PTR) lpBaseAddress + pImportDescriptor[ dwIndex ].OriginalFirstThunk );
		pFirstThunk = (PIMAGE_THUNK_DATA) ( (DWORD_PTR) lpBaseAddress + pImportDescriptor[ dwIndex ].FirstThunk );

		if ( pOriginalFirstThunk == nullptr || pFirstThunk == nullptr )
			return false;

		while ( pOriginalFirstThunk->u1.AddressOfData )
		{
			if ( !( pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG ) )
			{
				PIMAGE_IMPORT_BY_NAME pImageImport = (PIMAGE_IMPORT_BY_NAME) ( (LPBYTE) lpBaseAddress + pOriginalFirstThunk->u1.AddressOfData );

				auto pFn = GetProcAddress( hModule, (LPCSTR) pImageImport->Name );

				if ( ( *(BYTE*) pFn == bInt3Breakpoint || *(BYTE*) pFn == bJumpOpcode ) 
					 || ( *(WORD*) pFn == wUd2Breakpoint || *(WORD*) pFn == wInt3Breakpoint ) )
				{
					Engine::AddFunction( S_CorruptedFunction( std::string( pDllName ), std::string( pImageImport->Name ), (std::uintptr_t) pFn ) );
				}
			}

			pFirstThunk++;
			pOriginalFirstThunk++;
		}
	}

	return true;
}