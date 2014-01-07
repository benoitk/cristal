///////////////////////////////////////////////////////////////////
#pragma once

#define CONV_BUFFER_SIZE					64


 DWORD dwGetPrivateProfileString( LPCTSTR lpszSection, LPCTSTR lpszEntry, LPCTSTR lpszDefault,LPTSTR lpszReturnedString,int iSizeMax,LPCTSTR lpszFileIni);
 BOOL bWritePrivateProfileString( LPCTSTR lpszSection, LPCTSTR lpszEntry,LPTSTR lpszString,LPCTSTR lpszFileIni);

 int iGetPrivateProfileInt( LPCTSTR lpszSection, LPCTSTR lpszEntry, int nDefaultValue ,LPCTSTR lpszFileIni);
 BOOL bWritePrivateProfileInt( LPCTSTR lpszSection, LPCTSTR lpszEntry, int nDefaultValue ,LPCTSTR lpszFileIni);
// lecture d'un float dans le fichier INI
 float fGetPrivateProfileFloat(LPCTSTR lpszSection, LPCTSTR lpszEntry,float fDefaultValue,LPCTSTR lpszFileIni );
// stockage d'un flottant dans le fichier INI
 BOOL bWritePrivateProfileFloat( LPCTSTR lpszSection, LPCTSTR lpszEntry,float fDefaultValue,LPCTSTR lpszFileIni );
 long lConvString2Long(LPTSTR szVal);
 LPTSTR szGetFullPathName(LPTSTR szFileName,LPTSTR szFullPathName);
 BOOL bCopyFile( LPCTSTR szSrc, LPCTSTR szDst,BOOL bFailIfExist);
 DWORD bReadLineFromPos(LPCTSTR pszFileName, LPTSTR lpszReturnedString, long& argnPosition);



