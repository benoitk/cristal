///////////////////////////////////////////////////////////////////
#pragma once

#define CONV_BUFFER_SIZE					64


NETWORK_API DWORD dwGetPrivateProfileString( LPCTSTR lpszSection, LPCTSTR lpszEntry, LPCTSTR lpszDefault,LPTSTR lpszReturnedString,int iSizeMax,LPCTSTR lpszFileIni);
NETWORK_API BOOL bWritePrivateProfileString( LPCTSTR lpszSection, LPCTSTR lpszEntry,LPTSTR lpszString,LPCTSTR lpszFileIni);

NETWORK_API int iGetPrivateProfileInt( LPCTSTR lpszSection, LPCTSTR lpszEntry, int nDefaultValue ,LPCTSTR lpszFileIni);
NETWORK_API BOOL bWritePrivateProfileInt( LPCTSTR lpszSection, LPCTSTR lpszEntry, int nDefaultValue ,LPCTSTR lpszFileIni);
// lecture d'un float dans le fichier INI
NETWORK_API float fGetPrivateProfileFloat(LPCTSTR lpszSection, LPCTSTR lpszEntry,float fDefaultValue,LPCTSTR lpszFileIni );
// stockage d'un flottant dans le fichier INI
NETWORK_API BOOL bWritePrivateProfileFloat( LPCTSTR lpszSection, LPCTSTR lpszEntry,float fDefaultValue,LPCTSTR lpszFileIni );
NETWORK_API long lConvString2Long(LPTSTR szVal);
NETWORK_API LPTSTR szGetFullPathName(LPTSTR szFileName,LPTSTR szFullPathName);
NETWORK_API BOOL bCopyFile( LPCTSTR szSrc, LPCTSTR szDst,BOOL bFailIfExist);
NETWORK_API DWORD bReadLineFromPos(LPCTSTR pszFileName, LPTSTR lpszReturnedString, long& argnPosition);



