/*

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// Includes
#include "DllMain.h"
#include "Detours.h"

// Define globals
HMODULE		g_hThisModule = nullptr;
DWORD		g_dwCodeStartAddr = 0;
char		g_arrLoginPattern[ ] = { 0x0F, 0xB6, 0x02, 0x85, 0xC0 };
void*		g_pAddrLogin = nullptr;
char*		g_pAddrIsLoggedIn = nullptr;
bool		g_bFrozen = false;

// Make sure we are on the cool side of school.
#define GIANT_SCROTUM

// ----------------------------------------------------------------------------
// Searches the specified pattern in the given address space. "?" is wildcard.
// ----------------------------------------------------------------------------
void* FindPattern( const char* signature, const char* mask, void* start, unsigned int occurence, unsigned long length )
{
	// Check parameters to prevent Null-Pointer crashes.
	if (signature == nullptr || mask == nullptr || start == nullptr )
		return nullptr;

	for ( int i = 0; i < length; i++ )
	{
		// We have to access the string length twice.
		const unsigned int maskLen = strlen( mask );
		
		// This tells, if we exited the loop due to a break.
		bool didBreak = false;

		for ( int j = 0; j < maskLen; j++ )
		{
			// Ignore wildcards
			if ( mask[ j ] == '?' )
				continue;

			// Check if we match with the signature.
			if ( reinterpret_cast< char* >( start )[ i + j ] != signature[ j ] )
			{
				didBreak = true;
				break;
			}
		}

		// This means, we did not break a single time -> Pattern found.
		if ( !didBreak )
		{
			unsigned long result = reinterpret_cast< unsigned long >( start ) + i;
			if ( --occurence > 0 )
			{
				result = reinterpret_cast< unsigned long >( FindPattern( signature, mask, reinterpret_cast< void* >( result + 1 ), occurence, length ) );
			}

			return reinterpret_cast< void* >( result );
		}
	}

	return nullptr;
}


// ----------------------------------------------------------------------------
// 
// ----------------------------------------------------------------------------
int ( __stdcall * orig_connect )( SOCKET s, const sockaddr* name, int namelen );
int __stdcall my_connect( SOCKET s, const sockaddr* name, int namelen )
{
	sockaddr_in* my_name = reinterpret_cast< sockaddr_in* >( const_cast< sockaddr* >( name ) );

	// Detour every connection to localhost.
	if ( my_name->sin_addr.S_un.S_addr == inet_addr( "82.165.134.202" ) ) // 82.165.134.202 // die vom mBotCrack.exe (Frankreich) 
	{
		my_name->sin_addr.S_un.S_addr = inet_addr( "5.34.183.175" );
	}

	return orig_connect( s, reinterpret_cast< const sockaddr* >( my_name ), namelen );
}


void Thread_FreezeLogin( )
{
	// I cut the VirtualProtect stuff here, dude. It's really not necessary
	//	as the IsLoggedIn Boolean is a simple var and no part of the code section
	//	or any other thing we might not have access to.
	while ( true )
	{
		*g_pAddrIsLoggedIn = 1;
	}
}


void ( __cdecl * orig_Login )( );
void __declspec( naked ) __cdecl my_Login( )
{
	__asm
	{
		cmp		[ g_bFrozen ], 1;
		je		[ lbl_frozen ];
		mov		[ g_pAddrIsLoggedIn ], edx;
		mov		[ g_bFrozen ], 1;
		
		push	0;
		push	0;
		push	0;
		push	[ Thread_FreezeLogin ];
		push	0;
		push	0;
		call	CreateThread;


	lbl_frozen:
		movzx	eax, byte ptr ds:[ edx ];
		test	eax, eax;
	}
}


void Thread_CheckThemidaFinished( )
{
	DWORD oldProtect;
	VirtualProtect( reinterpret_cast< void* >( g_dwCodeStartAddr ), 1, PAGE_EXECUTE_READWRITE, &oldProtect );

	while ( *reinterpret_cast< char* >( g_dwCodeStartAddr ) != 0x55 )
	{
		Sleep( 10 );
	}

	g_pAddrLogin = FindPattern( g_arrLoginPattern, "xxxxx", reinterpret_cast< void* >( g_dwCodeStartAddr ), 5, 0x1E2000 );

	orig_connect = ( int ( __stdcall * )( SOCKET, const sockaddr*, int ) )DetourCreate( GetProcAddress( GetModuleHandle( "ws2_32.dll" ), "connect" ), my_connect, 5 );
	orig_Login = ( void ( __cdecl * )( ) )DetourCreate( g_pAddrLogin, my_Login, 5 );
}

// ----------------------------------------------------------------------------
// This is a thread's EP and will be called when the DLL is loaded.
// ----------------------------------------------------------------------------
void OnInject( )
{
	g_dwCodeStartAddr = 0x00401000;

	CreateThread( NULL, 0, reinterpret_cast< LPTHREAD_START_ROUTINE >( Thread_CheckThemidaFinished ), NULL, 0, NULL );
}

// ----------------------------------------------------------------------------
// This will be called when the DLL is unloaded. In example the game is closed.
// ----------------------------------------------------------------------------
void OnEject( )
{

}

// ----------------------------------------------------------------------------
// This is the DLLs main entry point. It will call OnInject and OnEject.
// ----------------------------------------------------------------------------
BOOL WINAPI DllMain( HMODULE hDll, DWORD dwReason, LPVOID lpReserved ) //das hier wird ausgeführt sobald die dll injected wurde
{
	DisableThreadLibraryCalls( hDll );

	switch ( dwReason )
	{
		case DLL_PROCESS_ATTACH:
		{
			g_hThisModule = hDll;

			CreateThread( NULL, 0, reinterpret_cast< LPTHREAD_START_ROUTINE >( OnInject ), NULL, 0, NULL );

			break;
		}
		case DLL_PROCESS_DETACH:
		{
			//OnEject( );

			break;
		}
	}

	return TRUE;
}