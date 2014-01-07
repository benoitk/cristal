//

#include "stdafx.h"
#include "network.h"

/*(@!*****************************************************************
* Nom                          : ThreadEntryPoint 
* Role                         : point d'entree de la tache
* --------------------------------------------------------------------
* Contraintes                  : Sans objet
* Donnees en entree            : LPVOID lpParam
* Donnees en sortie            : Sans objet
* Donnees globales modifiees   : Sans objet
* --------------------------------------------------------------------
*
* Pseudo code                  : lancement du thread
*
*****************************************************************@!)*/
//DWORD __stdcall CThread::ThreadEntryPoint(LPVOID lpParam)
//{
//	DWORD dwResult = -1;
//	
//	CThread* pThread = (CThread*)lpParam;
//	if (pThread != NULL)
//	{
//		dwResult = pThread->RunThread();  // run it
//		CloseHandle(pThread->m_hThread);
//		pThread->m_hThread = NULL;
//		pThread->m_dwThreadID = 0;
//
//	}
//	return 0;
//}

/*(@!*****************************************************************
* Nom                          : hCreateThread 
* Role                         : creer la tache
* --------------------------------------------------------------------
* Contraintes                  : Sans objet
* Donnees en entree            : DWORD* pdwThreadID, DWORD cbStack, DWORD fdwCreate
* Donnees en sortie            : Sans objet
* Donnees globales modifiees   : Sans objet
* --------------------------------------------------------------------
*
* Pseudo code                  : creation du thread
*
*****************************************************************@!)*/
//HANDLE CThread::hCreateThread(DWORD cbStack, DWORD fdwCreate)
//{
///*	m_hThread = ::CreateThread(NULL, cbStack,ThreadEntryPoint, (LPVOID)this, fdwCreate, &m_dwThreadID);
//	_tprintf(_T("* m_hThread: %s %d*\n"),m_hThread!=NULL ? _T("OK") : _T("KO"), GetLastError());
//   */ 
//	return m_hThread;
//}


/*(@!*****************************************************************
* Nom                          : ~CThread
* Role                         : destructeur
* --------------------------------------------------------------------
* Contraintes                  : Sans objet
* Donnees en entree            : Sans objet
* Donnees en sortie            : Sans objet
* Donnees globales modifiees   : Sans objet
* --------------------------------------------------------------------
*
* Pseudo code                  : destruction de CThread
*
*****************************************************************@!)*/
CThread::~CThread()
{
	DeleteCriticalSection(&m_hCriticalSection);
}

/*(@!*****************************************************************
* Nom                          : CThread
* Role                         : constructeur
* --------------------------------------------------------------------
* Contraintes                  : Sans objet
* Donnees en entree            : Sans objet
* Donnees en sortie            : Sans objet
* Donnees globales modifiees   : Sans objet
* --------------------------------------------------------------------
*
* Pseudo code                  : construction de CThread
*
*****************************************************************@!)*/
CThread::CThread()
{
	m_bRun = FALSE;
	m_bPause = FALSE;
	m_hThread = NULL;
	m_dwThreadID = 0;
	m_sTypeMsgHwnd = TYPE_MSG_AUCUN;
	m_hWnd = NULL;
	m_bInRunThread = FALSE;
	InitializeCriticalSection(&m_hCriticalSection);
}

void CThread::SetPause(BOOL bPause)
{
	m_bPause = bPause;
}


void CThread::ShowError(LPCTSTR szLabel,DWORD dwError)
{
	TCHAR szText[1024];
	LPVOID lpMsgBuf;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |FORMAT_MESSAGE_FROM_SYSTEM |FORMAT_MESSAGE_IGNORE_INSERTS,
				  NULL,dwError,MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),(LPTSTR) &lpMsgBuf,0,NULL);
	_stprintf(szText,_T("%s %s\n"),szLabel, (LPCTSTR)lpMsgBuf);
	OutputDebugString(szText);
	LocalFree(lpMsgBuf);
}



/*(@!*****************************************************************
* Nom                          :  
* Role                         :  
* --------------------------------------------------------------------
* Contraintes                  : Sans objet
* Donnees en entree            : 
* Donnees en sortie            : 
* Donnees globales modifiees   : Sans objet
* --------------------------------------------------------------------
*
* Pseudo code                  : Sans objet
*****************************************************************@!)*/
BOOL CThread::bSendMessageToHwnd(HWND hWnd,BYTE *lpBlock,long lSize , DWORD dwMsgCode)
{
	COPYDATASTRUCT CopyDataStruct;

	if (m_hWnd && (m_sTypeMsgHwnd != TYPE_MSG_AUCUN))
	{
		CopyDataStruct.dwData = dwMsgCode;
		CopyDataStruct.cbData = lSize;
		CopyDataStruct.lpData = (PVOID)lpBlock;

		::SendMessage(hWnd,WM_COPYDATA,(WPARAM)this,(LPARAM)&CopyDataStruct);
	}
	return ( hWnd != NULL );
} 



/*(@!*****************************************************************
* Nom                          :  
* Role                         :  
* --------------------------------------------------------------------
* Contraintes                  : Sans objet
* Donnees en entree            : 
* Donnees en sortie            : 
* Donnees globales modifiees   : Sans objet
* --------------------------------------------------------------------
*
* Pseudo code                  : Sans objet
*****************************************************************@!)*/
BOOL CThread::bIsRunning()
{
	BOOL bReturn;
	DWORD dwExitCode;

	bReturn = FALSE;

	if (m_hThread != NULL)
	{
		if (GetExitCodeThread(m_hThread, &dwExitCode))
		{
			bReturn = (dwExitCode == STILL_ACTIVE);
		}
	}

	return bReturn;
} 

void CThread::Stop()
{
	MSG msg;

	m_bRun = FALSE;
	while (bIsRunning())
	{
		while (::PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))     
		{
			TranslateMessage(&msg);         
			DispatchMessage(&msg);      
		}
		Sleep(1000);
	}
	m_bInRunThread = FALSE;
}