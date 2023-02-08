#include "IATScan.hpp"

int main()
{
	printf( "t.me/colby5engineering\n\n" );

	if ( Engine::IATScan() == true )
		Engine::OutputCorruptedFunctions();
	else
		printf( "[-] Failed to scan iat :(\n" );

	std::cin.get();
	return 0;
}