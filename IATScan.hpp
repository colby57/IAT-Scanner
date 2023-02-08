#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <iostream>

namespace Engine 
{
	struct S_CorruptedFunction
	{
		std::string m_cModuleName;
		std::string m_cFunctionName;
		std::uintptr_t m_pAddress;

		S_CorruptedFunction( std::string cModule, std::string cFunc, std::uintptr_t pAddress ): m_cModuleName( std::move( cModule ) ), m_cFunctionName( std::move( cFunc ) ), m_pAddress( std::move( pAddress ) )
		{
		}
	};

	inline BYTE bInt3Breakpoint = 0xCC;
	inline BYTE bJumpOpcode = 0xE9;

	inline WORD wUd2Breakpoint = 0x0B0F;
	inline WORD wInt3Breakpoint = 0x03CD;

	inline std::vector<S_CorruptedFunction> m_cCorruptedFunctions {};

	void OutputCorruptedFunctions();
	void AddFunction( const S_CorruptedFunction& cCorruptedFunctions );
	bool IATScan();
}