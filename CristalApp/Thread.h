#pragma once

#include <QThread>
#define WM_EXCEPTION			0
#define WM_TRACE				1
#define WM_TCP_CNX				2
#define WM_TCP					3
#define WM_DATA_R				4
#define WM_DATA_W				5


#define SZ_TYPE_TCP				_T("TCP       :")
#define SZ_TYPE_EXCEPTION		_T("EXCEPTION :")
#define SZ_TYPE_TRACE			_T("TRACE     :")
#define SZ_TYPE_DATA			_T("DATA      :")



#define TYPE_MSG_AUCUN			0
#define TYPE_MSG_DONNEES		1
#define TYPE_MSG_ERREUR			2
#define TYPE_MSG_TOUS			3


class  CThread : public QThread
{
// Operations
public:                 

    CThread(); 
    //HANDLE hCreateThread(DWORD cbStack = 0, DWORD fdwCreate = 0);
	void SetTypeMsgHwnd(short sTypeMsgHwnd){m_sTypeMsgHwnd = sTypeMsgHwnd;};
	short sGetTypeMsgHwnd(){return m_sTypeMsgHwnd;};
	//void SetHwnd(HWND hWnd){ m_hWnd = hWnd;};
	//HWND hGetHwnd(){ return m_hWnd;};	
	BOOL bIsRunning();
	void ShowError(LPCTSTR szLabel,DWORD dwError);
	BOOL bGetInRunThread(){return m_bInRunThread;};
	void SetPause(BOOL bPause);
	BOOL bGetPause(){return m_bPause;};

// Overrideables
public:
    //virtual DWORD RunThread() = 0;
    virtual void run() =0;
    virtual ~CThread(); 
	virtual void Stop();
protected:
    //static DWORD __stdcall ThreadEntryPoint(LPVOID lpParam);
	virtual BOOL bOnConnect(LPCTSTR szIni = NULL){return TRUE;};
	virtual BOOL bOnDeconnect(){return TRUE;};
	virtual BOOL bSendMessageToHwnd(HWND hWnd ,BYTE *lpBlock,long lSize , DWORD dwMsgCode);

protected:
	short m_sTypeMsgHwnd;
	HWND m_hWnd;
	BOOL m_bRun;
	BOOL m_bPause;
	BOOL m_bInRunThread;

public:
	CRITICAL_SECTION  m_hCriticalSection;
	HANDLE m_hThread;
	DWORD m_dwThreadID;
};


