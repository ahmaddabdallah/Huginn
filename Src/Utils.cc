#include <windows.h>

#include "Native.h"
#include "Instance.h"
#include "Prototypes.h"
#include "Macros.h"

D_SEC(D)
DWORD	StrLenA(
	_In_	LPSTR	Str
)
{
	DWORD cx = 0;
	while(*Str++)
		cx++;

	return cx;
}

D_SEC(D)
VOID	_memset(
	_In_	PVOID	pAddress,
	_In_	BYTE	Value,
	_In_	SIZE_T	Size
)
{
	PBYTE pDst = reinterpret_cast<PBYTE>(pAddress);
	for (SIZE_T i = 0; i < Size; i++)
		pDst[i] = Value;
}

D_SEC(D)
VOID	_memcpy(
	_In_	PVOID	pDstBuffer,
	_In_	PVOID	pSrcBuffer,
	_In_	SIZE_T	sBufferSize
)
{
	PBYTE pDst = reinterpret_cast<PBYTE>(pDstBuffer);
	PBYTE pSrc = reinterpret_cast<PBYTE>(pSrcBuffer);
	for (SIZE_T i = 0; i < sBufferSize; i++)
		pDst[i] = pSrc[i];
}

D_SEC(D)
bool	_strcmp(
	_In_	LPSTR	lpStrA,
	_In_	LPSTR	lpStrB
)
{
	while (*lpStrA && *lpStrB)
	{
		if (*lpStrA != *lpStrB)
			return false;
		lpStrA++;
		lpStrB++;
	}
	return *lpStrA == *lpStrB;
}

D_SEC(D)
bool _memcmp(
	_In_	PVOID	lpBufferA,
	_In_	PVOID	lpBufferB,
	_In_	DWORD	dwCheckSize
)
{
	PBYTE pA = reinterpret_cast<PBYTE>(lpBufferA);
	PBYTE pB = reinterpret_cast<PBYTE>(lpBufferB);
	for (DWORD i = 0; i < dwCheckSize; i++)
	{
		if (pA[i] != pB[i])
			return false;
	}
	return true;
}

D_SEC(D)
LPSTR	_strtok_s(
	_Inout_opt_	LPSTR	lpStr,
	_In_		LPSTR	lpDelimiters,
	_Inout_		LPSTR*	lpContext
)
{
	LPSTR pCurrent = lpStr ? lpStr : *lpContext;
	if (!pCurrent)
		return NULL;

	while (*pCurrent)
	{
		bool bIsDelim = FALSE;
		LPSTR pDelim = lpDelimiters;
		while (*pDelim)
		{
			if (*pCurrent == *pDelim)
			{
				bIsDelim = TRUE;
				break;
			}
			pDelim++;
		}
		if (!bIsDelim)
			break;
		pCurrent++;
	}

	if (!*pCurrent)
	{
		*lpContext = NULL;
		return NULL;
	}

	LPSTR pTokenStart = pCurrent;
	while (*pCurrent)
	{
		LPSTR pDelim = lpDelimiters;
		while (*pDelim)
		{
			if (*pCurrent == *pDelim)
			{
				*pCurrent = '\0';
				*lpContext = pCurrent + 1;
				return pTokenStart;
			}
			pDelim++;
		}
		pCurrent++;
	}

	*lpContext = NULL;
	return pTokenStart;
}
