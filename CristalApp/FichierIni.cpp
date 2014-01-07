//
//////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "network.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
//#define _WIN_INI
#define SIZE_CODE_UNICODE		2


DWORD dwGetPrivateProfileString(LPCTSTR lpszSection, LPCTSTR lpszEntry, LPCTSTR lpszDefault,LPTSTR lpszReturnedString,int iSizeMax,LPCTSTR lpszFileIni)
{
#ifdef _WIN_INI
	return GetPrivateProfileString( lpszSection, lpszEntry, lpszDefault,lpszReturnedString,iSizeMax,lpszFileIni);
#endif

	HANDLE hf;
	BOOL bReturn = FALSE;
	TCHAR *lpbuf = NULL;
	long filelen = 0;
	DWORD nReadSize;
	TCHAR szRub[MAX_PATH];
	TCHAR *pStart;
	TCHAR *pEnd;

	int ntry = 0;
	//lstrcpy(lpszReturnedString,lpszDefault);
	StringCchCopy(lpszReturnedString, MAX_PATH, lpszDefault);
	do
	{
		ntry ++;

		hf = CreateFile(lpszFileIni, GENERIC_READ,
			FILE_SHARE_READ|FILE_SHARE_WRITE,
			NULL, 
			OPEN_EXISTING, 
			FILE_ATTRIBUTE_NORMAL, 
			NULL);

		if (hf == INVALID_HANDLE_VALUE)  
		{
			filelen = GetLastError();
			if (filelen == ERROR_ACCESS_DENIED)
			{
				Sleep(50);
			}
			else break;
		}
	}
	while ((hf == INVALID_HANDLE_VALUE) && (ntry < 100));

	if (hf != INVALID_HANDLE_VALUE)
	{
		filelen = (long)GetFileSize(hf, NULL);
		if (filelen > 0) 
		{
			if (filelen >= SIZE_CODE_UNICODE) 
			{
				SetFilePointer(hf, SIZE_CODE_UNICODE, 0, FILE_BEGIN);
				filelen -= SIZE_CODE_UNICODE;
			}
			lpbuf = new TCHAR[filelen/sizeof(TCHAR) + 2];
			if (lpbuf) 
			{
				if (ReadFile(hf, lpbuf, filelen, &nReadSize, NULL)) 
				{
					lpbuf[nReadSize/sizeof(TCHAR)] = 0;
					// debut de RUB
					_stprintf(szRub,_T("[%s]"),lpszSection);
					if (pStart = _tcsstr(lpbuf,szRub))
					{
						// recherche fin rub
						pStart++;
						pEnd = _tcsstr(pStart,_T("[")); // peut être null
						// recherche clef
						_stprintf(szRub,_T("%s="),lpszEntry);
						pStart = _tcsstr(pStart,szRub);
						bReturn = (pStart != NULL);
						if (bReturn)
						{
							pStart += lstrlen(szRub);
							if (pEnd != NULL) bReturn = (pStart < pEnd);
							if (bReturn)
							{
								pEnd = _tcsstr(pStart,_T("\r"));
								if (pEnd == NULL)
								{
									pEnd = _tcsstr(pStart,_T("\n"));
								}
							}
							if (pEnd == NULL) pEnd = lpbuf + nReadSize/2;
							filelen = (int)(pEnd - pStart);
							if ((filelen > 0) && (filelen < iSizeMax))
							{
								*pEnd = 0;
								StringCchCopy(lpszReturnedString, MAX_PATH, pStart);
								//lstrcpy(lpszReturnedString,pStart);
							}
						}

					}
				}
				delete [] lpbuf;
			}
		}
	}
	CloseHandle(hf);

	hf = INVALID_HANDLE_VALUE;

	return (lstrlen(lpszReturnedString));
}



BOOL bWritePrivateProfileString( LPCTSTR lpszSection, LPCTSTR lpszEntry,LPTSTR lpszString,LPCTSTR lpszFileIni)
{
	HANDLE hf;
	TCHAR *lpbuf = NULL;
	DWORD filelen = 0;
	DWORD nReadSize = 0;
	BOOL bReturn = FALSE; 
	int ntry = 0;
	TCHAR szRub[2*MAX_PATH];
	TCHAR *pStart;
	TCHAR *pStart2;
	TCHAR *pEnd;
	int iSize;

#ifdef _WIN_INI
	return WritePrivateProfileString(lpszSection,lpszEntry,lpszString,lpszFileIni);
#endif

	do
	{
		ntry ++;
		hf = CreateFile(lpszFileIni, 
			GENERIC_READ|GENERIC_WRITE,
			0,//FILE_SHARE_READ|FILE_SHARE_WRITE,
			NULL, 
			OPEN_ALWAYS, 
			FILE_ATTRIBUTE_NORMAL, 
			NULL);

		if (hf == INVALID_HANDLE_VALUE)  
		{
			filelen = GetLastError();
			if (filelen == ERROR_ACCESS_DENIED)
			{
				Sleep(50);
			}
			else break;
		}
	}
	while ((hf == INVALID_HANDLE_VALUE) && (ntry < 100));

	if (hf != INVALID_HANDLE_VALUE)
	{
		filelen = GetFileSize(hf, NULL);

		if (filelen >= SIZE_CODE_UNICODE) 
		{
			SetFilePointer(hf, SIZE_CODE_UNICODE, 0, FILE_BEGIN);
			filelen -= SIZE_CODE_UNICODE;
		}
		iSize = filelen/sizeof(TCHAR) + lstrlen(lpszString) + lstrlen(lpszSection)  + lstrlen(lpszEntry) + 32; // 32 ==> extra caracteres ([, ],  =, cr/lf ;
		if (lpbuf = new TCHAR[iSize])
		{
			memset(lpbuf,0,iSize * sizeof(TCHAR));
			if (ReadFile(hf, lpbuf, filelen, &nReadSize, NULL))
			{
			}
			lpbuf[nReadSize/sizeof(TCHAR)] = 0;
			// debut de RUB
			_stprintf(szRub,_T("[%s]"),lpszSection);
			if (pStart = _tcsstr(lpbuf,szRub))
			{
				// recherche fin rub
				pStart++;
				pEnd = _tcsstr(pStart,_T("[")); 
				if (pEnd == NULL) 
				{
					// recherche clef
					_stprintf(szRub,_T("%s="),lpszEntry);
					pStart2 = _tcsstr(pStart,szRub);
					if (pStart2 == NULL)// c'est la dernière rubrique du fichier ==> ajout à la fin du fichier
					{
						pStart2 = _tcsstr(pStart,_T("\n"));
						if (pStart2 == NULL)
						{
							lstrcat(lpbuf,_T("\r\n"));
						}
						_stprintf(szRub,_T("%s=%s\r\n"),lpszEntry,lpszString);
						lstrcat(lpbuf,szRub);
					}
					else pEnd = (TCHAR*)(lpbuf + nReadSize);
				}
				if (pEnd != NULL)
				{
					// recherche clef
					_stprintf(szRub,_T("%s="),lpszEntry);
					if ((pStart2 = _tcsstr(pStart,szRub)) && (pStart2 < pEnd))
					{
						pEnd = _tcsstr(pStart2,_T("\r\n"));
						pStart2 += lstrlen(szRub);
						_stprintf(szRub,_T("%s"),lpszString);
						if (pEnd)
						{
							memmove(pStart2 + lstrlen(szRub),pEnd,(((BYTE*)lpbuf) + nReadSize - ((BYTE*)pEnd)));
							memcpy(pStart2,szRub,lstrlen(szRub)*sizeof(TCHAR));
						}
					}
					else // insertion d'une clef
					{
						_stprintf(szRub,_T("%s=%s\r\n"),lpszEntry,lpszString);
						memmove(pEnd + lstrlen(szRub),pEnd,((BYTE*)lpbuf) + nReadSize - ((BYTE*)pEnd));
						memcpy(pEnd,szRub,lstrlen(szRub)*sizeof(TCHAR));
					}
				}
			}
			else
			{
				//ajouter à la fin
				_stprintf(szRub,_T("[%s]\r\n"),lpszSection);
				lstrcat(lpbuf,szRub);
				_stprintf(szRub,_T("%s=%s\r\n"),lpszEntry,lpszString);
				lstrcat(lpbuf,szRub);
			}

			if (filelen >= SIZE_CODE_UNICODE) 
			{
				SetFilePointer(hf, SIZE_CODE_UNICODE, 0, FILE_BEGIN);
				filelen -= SIZE_CODE_UNICODE;
			}
			else if (filelen == 0) 
			{
//				DWORD	dwCodageUnicode = 0xFFFE;		//UNICODE LITTLEENDIAN
				WORD	dwCodageUnicode = 0xFEFF;		//UNICODE BIGENDIAN
				// encodage unicode 
				bReturn= WriteFile(hf, &dwCodageUnicode, sizeof(dwCodageUnicode), &nReadSize, NULL);
				
			}
			bReturn= WriteFile(hf, lpbuf, lstrlen(lpbuf)*sizeof(TCHAR), &nReadSize, NULL);
			if (bReturn) 
			{
				bReturn = SetEndOfFile(hf);
			} 
			CloseHandle(hf);
			delete [] lpbuf;
		}
	}
	return bReturn;
}




/*(@!*****************************************************************
* Nom                          : bWritePrivateProfileInt
* Role                         : ecriture d'un entier dans le fichier INI
*
*****************************************************************@!)*/
BOOL bWritePrivateProfileInt( LPCTSTR lpszSection, LPCTSTR lpszEntry, int nValue ,LPCTSTR lpszFileIni)
{
	TCHAR szText[CONV_BUFFER_SIZE];

	_stprintf(szText,_T("%d"),nValue);
	return bWritePrivateProfileString(lpszSection, lpszEntry, szText,lpszFileIni);
}

/*(@!*****************************************************************
* Nom                          : iGetPrivateProfileInt
* Role                         : ecriture d'un entier dans le fichier INI
*
*****************************************************************@!)*/
int iGetPrivateProfileInt( LPCTSTR lpszSection, LPCTSTR lpszEntry, int nDefaultValue ,LPCTSTR lpszFileIni)
{
	TCHAR szText[CONV_BUFFER_SIZE];

	dwGetPrivateProfileString(lpszSection,lpszEntry,_T(""),szText,sizeof(szText) / sizeof(TCHAR),lpszFileIni);
	if (lstrlen(szText) > 0) nDefaultValue = _ttoi(szText);
	return nDefaultValue;
}

/*(@!*****************************************************************
* Nom                          : WritePrivateProfileFloat
* Role                         : ecriture d'un entier dans le fichier INI
*
*****************************************************************@!)*/
BOOL bWritePrivateProfileFloat( LPCTSTR lpszSection, LPCTSTR lpszEntry, float fValue ,LPCTSTR lpszFileIni)
{
	TCHAR szText[CONV_BUFFER_SIZE];

	_stprintf(szText,_T("%.3f"),fValue);
	return bWritePrivateProfileString(lpszSection, lpszEntry, szText,lpszFileIni);
}


/*(@!*****************************************************************
* Nom                          : fGetPrivateProfileFloat
* Role                         : lecture d'un flottant dans le fichier INI
*
*****************************************************************@!)*/
float fGetPrivateProfileFloat( LPCTSTR lpszSection, LPCTSTR lpszEntry, float fDefaultValue ,LPCTSTR lpszFileIni) 
{
	TCHAR szText[CONV_BUFFER_SIZE];
	
	dwGetPrivateProfileString(lpszSection, lpszEntry,_T(""),szText,sizeof(szText)/sizeof(TCHAR),lpszFileIni );
	if (lstrlen(szText) > 0) _stscanf( szText, _T("%f"), &fDefaultValue );
	return fDefaultValue;
}

long lConvString2Long(LPTSTR szVal)
{
	long lID = 0;
	if ((_tcsstr(szVal,_T("0x")) != NULL) || (_tcsstr(szVal,_T("0X")) != NULL))// c'est une adresse
	{
		_stscanf(szVal,_T("%x"),&lID);
	}
	else lID = _ttoi(szVal);
	return lID;
}

LPTSTR szGetFullPathName(LPTSTR szFileName,LPTSTR szFullPathName)
{
	int iSize;

	iSize = GetModuleFileName(NULL,szFullPathName,MAX_PATH);

	while ((iSize>0) && (szFullPathName[iSize-1] != _T('\\'))) {iSize--; szFullPathName[iSize] = 0 ; }
	lstrcat(szFullPathName,szFileName);

	return szFullPathName;
}

BOOL bCopyFile( LPCTSTR szSrc, LPCTSTR szDst,BOOL bFailIfExist)
{
	BOOL bReturn;

	DeleteFile(szDst);
	bReturn = CopyFile(szSrc,szDst,FALSE);
	if (!bReturn) TRACE_DEBUG(eError,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: fichier %s introuvable"),szSrc);
	
	return bReturn;
}

//Lit jusqu'à la fin d'une ligne à partir d'une position dans le fichier
DWORD bReadLineFromPos(LPCTSTR pszFileName, LPTSTR lpszReturnedString, long& argnPosition)
{
	HANDLE hf;
	BOOL bReturn = FALSE;
	TCHAR *lpbuf = NULL;
	long filelen = 0;
	int iSizeMax = MAX_PATH;
	DWORD nReadSize;
	TCHAR *pStart;
	TCHAR *pEnd;
	
	//Lecture du fichier
	int ntry = 0;
	memset(lpszReturnedString, NULL, iSizeMax);
	do
	{
		ntry ++;

		hf = CreateFile(pszFileName, GENERIC_READ,
			FILE_SHARE_READ|FILE_SHARE_WRITE,
			NULL, 
			OPEN_EXISTING, 
			FILE_ATTRIBUTE_NORMAL, 
			NULL);

		if (hf == INVALID_HANDLE_VALUE)  
		{
			//TRACE_LOG_MSG(_T("INVALID_HANDLE_VALUE  \n"));

			filelen = GetLastError();
			if (filelen == ERROR_ACCESS_DENIED)
			{
				//TRACE_LOG_MSG(_T("ERROR_ACCESS_DENIED  \n"));
				Sleep(50);
			}
			else break;
		}
	}
	while ((hf == INVALID_HANDLE_VALUE) && (ntry < 100));

	
	if (hf != INVALID_HANDLE_VALUE)
	{
		filelen = (long)GetFileSize(hf, NULL);
		if (filelen > 0) 
		{
			if (filelen >= SIZE_CODE_UNICODE) 
			{
				SetFilePointer(hf, SIZE_CODE_UNICODE, 0, FILE_BEGIN);
				filelen -= SIZE_CODE_UNICODE;
			}
			lpbuf = new TCHAR[filelen/sizeof(TCHAR) + 2];
			if (lpbuf) 
			{
				
				if (ReadFile(hf, lpbuf, filelen, &nReadSize, NULL)) 
				{
					lpbuf[nReadSize/sizeof(TCHAR)] = 0;
					// debut de la lecture à partir de lpbuf+argnPosition
					if (pStart = (lpbuf+argnPosition))
					{
						
						
						pEnd = _tcsstr(pStart,_T("\r"));
						if (pEnd == NULL)
						{
							
							pEnd = _tcsstr(pStart,_T("\n"));
						}
						
						if (pEnd == NULL) pEnd = lpbuf + nReadSize/2;
						//Taille de la ligne
						filelen = (int)(pEnd - pStart);
						if ((filelen > 0) && (filelen < iSizeMax))
						{
							
							*pEnd = 0;
							lstrcpy(lpszReturnedString,pStart);
						}
						//Positionnement sur la prochaine ligne
						argnPosition += filelen+1;

					}
				}
				delete [] lpbuf;
			}
		}
	}
	CloseHandle(hf);
	hf = INVALID_HANDLE_VALUE;

	return (lstrlen(lpszReturnedString));
}
