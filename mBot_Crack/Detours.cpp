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

#include "Detours.h"


// ----------------------------------------------------------------------------
// See Header-File for information.
// ----------------------------------------------------------------------------
void * DetourCreate( void * lpOldFunc, void * lpNewFunc, int nSize )
{
	// First, check the params.
	if( nSize < 5 || !POINTERVALID( lpOldFunc ) || !POINTERVALID( lpNewFunc ) )
		return NULL;

	// This is the codecave, which contains the saved opcodes and the jumpingback.
	BYTE * lpOpcodes = new BYTE[ nSize + 5 ];

	// The patch, which contains a jump to lpNewFunc and maybe some NOPs.
	BYTE * lpPatch = new BYTE[ nSize ];

	// Calculate the distance of both functions, because the JMP-Command needs it.
	DWORD dwFuncDist = ( DWORD )lpNewFunc - ( DWORD )lpOldFunc - 5;

	// Calculate the distance between the Codecave and the To-Hook-Function.
	DWORD dwOpDist = ( DWORD )lpOldFunc - ( DWORD )lpOpcodes - 5;

	// Used by VirtualProtect.
	DWORD dwBack = 0;

	// Give access to write the patch.
	VirtualProtect( lpOldFunc, 5, PAGE_READWRITE, &dwBack );

	// Save the opcodes.
	memcpy( lpOpcodes, lpOldFunc, nSize );

	// Write JMP-Command for the jumpingback.
	lpOpcodes[ nSize ] = 0xE9;

	// Write the needed parameter ( distance ) for the jumpingback.
	memcpy( &lpOpcodes[ nSize + 1 ], &dwOpDist, 4 );

	 // Write the JMP-Command for calling the new function in the patch.
	lpPatch[ 0 ] = 0xE9;

	// Write address of the new function in the patch.
	memcpy( &lpPatch[ 1 ], &dwFuncDist, 4 );

	// Fill the remaining Opcodes with NOPs.
	for( int i = 5; i < nSize; i++ )
		lpPatch[ i ] = 0x90;

	// Write the patch!
	memcpy( lpOldFunc, lpPatch, nSize );

	// Restore old protection.
	VirtualProtect( lpOldFunc, 5, dwBack, &dwBack );

	// Free non-needed space.
	delete[ ] lpPatch;

	// Return the CodeCave
	return lpOpcodes;
}

// ----------------------------------------------------------------------------
// See Header-File for information.
// ----------------------------------------------------------------------------
void DetourRemove( BYTE * lpDetour, int nSize )
{
	// First, check the params.
	if( nSize < 5 || !POINTERVALID( lpDetour ) )
		return;

	// The opcodes we have saved before.
	BYTE * lpOpcodes = new BYTE[ nSize ];

	//  Distance between the hooked function and the codecave.
	DWORD dwOldFuncDist = 0;

	// Address of the old function.
	DWORD dwOldFunc = 5;

	// Used by VirtualProtect.
	DWORD dwBack = 0;

	// Give access to write the patch.
	VirtualProtect( lpDetour, 5 + nSize, PAGE_READWRITE, &dwBack );

	// Get the saved opcodes.
	memcpy( lpOpcodes, &lpDetour[ 0 ], nSize );

	// Get distance to calculate old function's address.
	memcpy( &dwOldFuncDist, &lpDetour[ nSize + 1 ], 4 );

	// Restore old protection.
	VirtualProtect( lpDetour, 5 + nSize, dwBack, &dwBack );

	// Add address from where the distance will be calculated.
	dwOldFunc += ( DWORD )lpDetour;

	// Add distance.
	dwOldFunc += dwOldFuncDist;

	// Give access to write the opcodes back.
	VirtualProtect( ( void * )dwOldFunc, nSize, PAGE_READWRITE, &dwBack );

	// Write the opcodes back.
	memcpy( ( void * )dwOldFunc, lpOpcodes, nSize );

	// Restore old protection.
	VirtualProtect( ( void * )dwOldFunc, nSize, dwBack, &dwBack );

	// The codecave is not needed anymore.
	delete[ ] lpDetour;

	// Free non-needed space.
	delete[ ] lpOpcodes;
}

// ----------------------------------------------------------------------------
// See Header-File for information.
// ----------------------------------------------------------------------------
void PatchBytes( void * lpAddress, BYTE * lpBytes, int nLen )
{
	// First, check the params.
	if( !POINTERVALID( lpAddress ) || !POINTERVALID( lpBytes ) || nLen < 0 )
		return;

	// Needed by VirtualProtect.
	DWORD dwBack = 0;

	// Grant access to write the patch.
	VirtualProtect( lpAddress, nLen, PAGE_READWRITE, &dwBack );

	// Apply the Patch!
	memcpy( lpAddress, lpBytes, nLen );

	// Restore old protection.
	VirtualProtect( lpAddress, nLen, dwBack, &dwBack );
}

// ================================================================================

// See Header-File for information.
void PatchBytes( void * lpAddress, const char * szBytes, int nLen )
{
	// First, check the params.
	if( !POINTERVALID( lpAddress ) || !POINTERVALID( szBytes ) || nLen < 0 )
		return;

	// Needed by VirtualProtect.
	DWORD dwBack = 0;
	VirtualProtect( lpAddress, nLen, PAGE_READWRITE, &dwBack );

	// Write Byte-After-Byte.
	for( int i = 0; i < nLen; i++ )
		*( BYTE * )( ( DWORD )lpAddress + i ) = szBytes[ i ];

	// Restore old protection.
	VirtualProtect( lpAddress, nLen, dwBack, &dwBack );
}

/* END OF FILE */

