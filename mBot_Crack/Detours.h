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

#pragma once

#include <windows.h>
#include <stdio.h>
#include <vector>

#define POINTERVALID( ptr )	( ptr > NULL && ptr < ( void * )0xFFFFFFFF )


// Description.........: Hooks a function to get an own one called.
// Param. lpOldFunc....: Address of the function you want to hook.
// Param. lpNewFunc....: Address of the function you want to be called instead
// Param. nSize........: Size of the patch. Normally it's 5 ( Address ( 4Bytes ) + 0xE9 ).
// Return Value........: Address of the original function.
void * DetourCreate( void * lpOldFunc, void * lpNewFunc, int nSize );

// Description.......: Removes a prior created hook.
// Param. lpDetour...: The result of DetourCreate.
// Param. nSize......: Must be the same value, you specified in DetourCreate.
void DetourRemove( BYTE * lpDetour, int nSize );

// Description...........: Copies lpBytes to lpAddress.
// Param. lpAddress......: Destination Address.
// Param. lpBytes........: Bytes to copy.
// Param. nLen...........: Byte array's length.
void PatchBytes( void * lpAddress, BYTE * lpBytes, int nLen );

// Description...........: Copies lpBytes to lpAddress.
// Param. lpAddress......: Destination Address.
// Param. szBytes........: Bytes to copy.
// Param. nLen...........: Byte array's length.
void PatchBytes( void * lpAddress, const char * szBytes, int nLen );


/* END OF FILE */