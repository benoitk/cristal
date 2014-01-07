#include "stdafx.h"
#include "network.h"
#include "header_qt.h"

#define MASK	(EV_BREAK | EV_CTS | EV_DSR | EV_ERR | EV_RING | EV_RLSD | EV_RXCHAR | EV_RXFLAG | EV_TXEMPTY)
/////////////////////////////////////////////////////////////////////////////
// CSerialPort
////////////////////////////////////////////////////////////////
/*@!************************************************************************
* NOM:                      CSerialPort:CSerialPort
* ROLE:                     Constructeur de la classe CSerialPort
* ALGORITHME:
*    Point d'entree
*    Initialisation des membres de la classe
*    Point de sortie
***********************************************************************@!)*/

CSerialPort::CSerialPort():CThreadInterface()
{
	m_bModeInteger = TRUE;
	// Initialisation des membres de la classe
	m_hTTY = 0;
	m_pRxBuffer = NULL;
	m_bRun = false;
	m_lSizeDataMax = 128;
	m_nNumPort = 0;
	memset(&m_DCB,0,sizeof(m_DCB));
	m_lOffsetBuffer = 0;
	m_pListExchange = new CElemList(NBR_EXCHANGE_JBUS_MAX);
}


/*@!************************************************************************
* NOM:                      CSerialPort::~CSerialPort
* ROLE:                     Destructeur de la classe client
* ALGORITHME:
*    Point d'entree
*    L'appli s'en va, pas la peine d'attendre le message de connexion
*    Point de sortie
***********************************************************************@!)*/
CSerialPort::~CSerialPort()
{
	if (m_pRxBuffer) free(m_pRxBuffer);
}


/******************************************************************************
 * @func :	ReadConfig
 * 
 * Rôle  :	Initialisation de donnees membres
 * @parm :	LPCSTR | szIni | fichier de configuration
 *****************************************************************************/
BOOL CSerialPort::bReadConfig(LPCTSTR pszFileName)
{
	TCHAR szPort[ 64 ];
	long lSizeDataMax;
	BOOL bReturn;

	bReturn = CThreadInterface::bReadConfig(pszFileName);
	// taille du buffer
	lSizeDataMax = iGetPrivateProfileInt(_T("Config"),_T("m_lSizeDataMax"),1024,pszFileName);

	if (lSizeDataMax > 0)
	{
		if (m_pRxBuffer == NULL) 
		{
			m_pRxBuffer = (BYTE*)malloc(lSizeDataMax + 16);
		}
		else if (m_lSizeDataMax != lSizeDataMax)
		{
			m_pRxBuffer = (BYTE*)realloc(m_pRxBuffer,lSizeDataMax + 16);
		}
		m_lSizeDataMax = lSizeDataMax;
	}

	// port com
	m_nNumPort = iGetPrivateProfileInt(_T("Config"),_T("m_nNumPort"),m_nNumPort,pszFileName);
	m_DCB.DCBlength = sizeof(DCB);
	memset(&m_DCB,0,sizeof(m_DCB));
#ifdef _WIN32_WCE
	_stprintf( szPort, _T("COM%d:"), m_nNumPort );
#else
	_stprintf( szPort, _T("\\\\.\\COM%d"), m_nNumPort );
#endif
	m_hTTY = CreateFile( szPort, GENERIC_READ | GENERIC_WRITE,0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM/*FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED*/, NULL );
	if (m_hTTY != INVALID_HANDLE_VALUE)
	{
		GetCommState( m_hTTY, &m_DCB );
		CloseHandle(m_hTTY);
		m_hTTY = INVALID_HANDLE_VALUE;
	}
	else
	{
		TRACE_DEBUG_LAST_ERROR(eDebug,eConfig,GetLastError());
	}
	m_DCB.BaudRate = iGetPrivateProfileInt(_T("Com"), _T("BaudRate"),m_DCB.BaudRate, pszFileName);
	m_DCB.ByteSize = iGetPrivateProfileInt(_T("Com"), _T("ByteSize"), m_DCB.ByteSize, pszFileName);
	m_DCB.Parity = iGetPrivateProfileInt(_T("Com"), _T("Parity"), m_DCB.Parity, pszFileName);
	m_DCB.fParity = iGetPrivateProfileInt(_T("Com"), _T("fParity"), m_DCB.fParity, pszFileName);
	m_DCB.StopBits = iGetPrivateProfileInt(_T("Com"), _T("StopBits"),m_DCB.StopBits, pszFileName); 
	m_DCB.fBinary = iGetPrivateProfileInt(_T("Com"), _T("fBinary"), m_DCB.fBinary, pszFileName);
	m_DCB.fOutxCtsFlow = iGetPrivateProfileInt(_T("Com"), _T("fOutxCtsFlow"),m_DCB.fOutxCtsFlow, pszFileName);
	m_DCB.fOutxDsrFlow = iGetPrivateProfileInt(_T("Com"), _T("fOutxDsrFlow"),m_DCB.fOutxDsrFlow, pszFileName);
	m_DCB.fDtrControl = iGetPrivateProfileInt(_T("Com"), _T("fDtrControl"), m_DCB.fDtrControl, pszFileName);
	m_DCB.fDsrSensitivity = iGetPrivateProfileInt(_T("Com"), _T("fDsrSensitivity"), m_DCB.fDsrSensitivity, pszFileName);
	m_DCB.fTXContinueOnXoff = iGetPrivateProfileInt(_T("Com"), _T("fTXContinueOnXoff"),m_DCB.fTXContinueOnXoff, pszFileName);
	m_DCB.fOutX = iGetPrivateProfileInt(_T("Com"), _T("fOutX"), m_DCB.fOutX, pszFileName);
	m_DCB.fInX = iGetPrivateProfileInt(_T("Com"), _T("fInX"),m_DCB.fInX, pszFileName);
	m_DCB.fErrorChar = iGetPrivateProfileInt(_T("Com"), _T("fErrorChar"),m_DCB.fErrorChar, pszFileName);
	m_DCB.fNull = iGetPrivateProfileInt(_T("Com"), _T("fNull"),m_DCB.fNull, pszFileName);
	m_DCB.fRtsControl = iGetPrivateProfileInt(_T("Com"), _T("fRtsControl"), m_DCB.fRtsControl, pszFileName);
	m_DCB.fAbortOnError = iGetPrivateProfileInt(_T("Com"), _T("fAbortOnError"), m_DCB.fAbortOnError, pszFileName);
	m_DCB.XonLim = iGetPrivateProfileInt(_T("Com"), _T("XonLim"),m_DCB.XonLim, pszFileName);
	m_DCB.XoffLim = iGetPrivateProfileInt(_T("Com"), _T("XoffLim"),m_DCB.XoffLim, pszFileName);
	m_DCB.ErrorChar = iGetPrivateProfileInt(_T("Com"), _T("ErrorChar"),m_DCB.ErrorChar, pszFileName);
	m_DCB.XonChar = iGetPrivateProfileInt(_T("Com"), _T("XonChar"), m_DCB.XonChar, pszFileName);
	m_DCB.XoffChar = iGetPrivateProfileInt(_T("Com"), _T("XoffChar"), m_DCB.XoffChar, pszFileName);
	m_DCB.fDummy2 = 17;
	m_DCB.wReserved = 0;
	m_DCB.EofChar = iGetPrivateProfileInt(_T("Com"), _T("EofChar"), m_DCB.EofChar, pszFileName);//'\n';
	m_DCB.EvtChar = iGetPrivateProfileInt(_T("Com"), _T("EvtChar"), m_DCB.EvtChar, pszFileName);//'\r'; 
	
	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error"));

	return bReturn;
}


/******************************************************************************
 * @func :	bWriteConfig
 * 
 * Rôle  :	enregistre la configuration dans un fichier
 * @parm :	LPCSTR | szIni | fichier de configuration
 *****************************************************************************/
BOOL CSerialPort::bWriteConfig(LPCTSTR pszFileName)
{
	BOOL bReturn;

	bReturn = CThreadInterface::bWriteConfig(pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Config"),_T("m_lSizeDataMax"),m_lSizeDataMax,pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Config"),_T("m_nNumPort"),m_nNumPort,pszFileName);

	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("BaudRate"),m_DCB.BaudRate, pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("ByteSize"),m_DCB.ByteSize , pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("Parity"),m_DCB.Parity , pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("fParity"),m_DCB.fParity , pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("StopBits"),m_DCB.StopBits, pszFileName); 
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("fBinary"),m_DCB.fBinary, pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("fOutxCtsFlow"),m_DCB.fOutxCtsFlow, pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("fOutxDsrFlow"),m_DCB.fOutxDsrFlow, pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("fDtrControl"),m_DCB.fDtrControl , pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("fDsrSensitivity"),m_DCB.fDsrSensitivity , pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("fTXContinueOnXoff"),m_DCB.fTXContinueOnXoff, pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("fOutX"),m_DCB.fOutX , pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("fInX"),m_DCB.fInX, pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("fErrorChar"),m_DCB.fErrorChar, pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("fNull"),m_DCB.fNull, pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("fRtsControl"),m_DCB.fRtsControl , pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("fAbortOnError"),m_DCB.fAbortOnError , pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("fDummy2"),m_DCB.fDummy2, pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("wReserved"),m_DCB.wReserved, pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("XonLim"),m_DCB.XonLim, pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("XoffLim"),m_DCB.XoffLim, pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("ErrorChar"),m_DCB.ErrorChar, pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("EofChar"),m_DCB.EofChar , pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("EvtChar"),m_DCB.EvtChar , pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("XonChar"),m_DCB.XonChar , pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Com"), _T("XoffChar"), m_DCB.XoffChar, pszFileName);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error"));
	return bReturn;
}

BOOL CSerialPort::bOpen()
{
	BOOL bReturn = FALSE;
	TCHAR szPort[ 30 ];
	COMMTIMEOUTS  CommTimeOuts;

#ifdef _WIN32_WCE
	_stprintf( szPort, _T("COM%d:"), m_nNumPort );
#else
	_stprintf( szPort, _T("\\\\.\\COM%d"), m_nNumPort );
#endif
	m_hTTY = CreateFile( szPort, GENERIC_READ | GENERIC_WRITE,0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM/*FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED*/, NULL );
	if (m_hTTY != INVALID_HANDLE_VALUE)
	{
		// config du port par default
		// get any early notifications
		SetCommMask( m_hTTY, MASK);
		// purge any information in the buffer
		PurgeComm( m_hTTY, PURGE_TXABORT | PURGE_RXABORT | PURGE_TXCLEAR | PURGE_RXCLEAR );
		// set up for overlapped non-blocking I/O
		CommTimeOuts.ReadIntervalTimeout = 0xFFFFFFFF;
		CommTimeOuts.ReadTotalTimeoutMultiplier = 0;
		CommTimeOuts.ReadTotalTimeoutConstant = 1000;
		CommTimeOuts.WriteTotalTimeoutMultiplier = 0;
		CommTimeOuts.WriteTotalTimeoutConstant = 10000;
		SetCommTimeouts( m_hTTY, &CommTimeOuts );
		SetCommState( m_hTTY, &m_DCB );
		SetupComm( m_hTTY, 4096, 4096 );
		SetThreadPriority( m_hThread,THREAD_PRIORITY_HIGHEST  );	
		EscapeCommFunction( m_hTTY, SETDTR);   //		SETRTS
		bReturn = (SetCommMask( m_hTTY, MASK));
	}
	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error"));
	return bReturn;
}

void CSerialPort::Close()
{
	if (m_hTTY != INVALID_HANDLE_VALUE)
	{
		// disable event notification and wait for thread to halt
		SetCommMask( m_hTTY, 0 );
		// drop DTR
		EscapeCommFunction( m_hTTY, CLRDTR);	//	 	SETRTS	 
		// purge  reads/writes 
		PurgeComm( m_hTTY, PURGE_TXABORT | PURGE_RXABORT);
		CloseHandle( m_hTTY );
		m_hTTY = INVALID_HANDLE_VALUE;
	}
}

//DWORD CSerialPort::RunThread()
void CSerialPort::run()
{
	long lLength;

	m_bRun = bOpen();
	m_bInRunThread = TRUE;
    
    qDebug() << "Interface : " << this->m_bNumInterface << " Thread : " << QThread::currentThreadId  ();
            
	while ( m_bRun )
	{
        
		if ((m_lSizeDataMax > 0) && (m_pRxBuffer != NULL))
		{
			if (bRead(m_pRxBuffer + m_lOffsetBuffer,m_lSizeDataMax - m_lOffsetBuffer,&lLength,FALSE))
			{
				m_lOffsetBuffer += lLength;
			}
			if (lDispatchTrame(m_pRxBuffer ,m_lOffsetBuffer) != 0)
			{
			}
			m_lOffsetBuffer = 0;	
		}
		else Sleep(1000);
	}
   
	Close();

//	return 0;
}



void CSerialPort::Stop()
{
	CThread::Stop();
}

BOOL CSerialPort::bWrite (BYTE* lpData,long lSizeTotal)
{
	DWORD dwNbBytesWritten = 0;

	if (m_hTTY != INVALID_HANDLE_VALUE)
	{
		if (!WriteFile(m_hTTY, lpData, lSizeTotal, &dwNbBytesWritten, NULL))
		{
			TRACE_DEBUG_LAST_ERROR(eError,eComSerial,GetLastError());
			m_lNbrErrCom++;
		}
	}

	return (dwNbBytesWritten == (DWORD)lSizeTotal);
}

BOOL CSerialPort::bRead(BYTE* lpData,long lSizeDataMax,long *plNbrLu,BOOL bByPass)
{
	DWORD dwLengthRead;
	DWORD dwTick = GetTickCount();
	//int randInt(rand()); 
	*plNbrLu = 0;
	//TRACE_DEBUG_MSG_TIME(_T("ping"), randInt);
	while ((m_hTTY > 0) && m_bRun && (lSizeDataMax > 0 ) && ((DWORD)(GetTickCount() - dwTick) < TIME_OUT_READ_RS232)) 
	{
		//TRACE_DEBUG_MSG_TIME(_T("pong"), randInt);
		if (ReadFile( m_hTTY, lpData,lSizeDataMax, &dwLengthRead, NULL ))
		{
			lSizeDataMax -= dwLengthRead;
			lpData += dwLengthRead;
			(*plNbrLu) += dwLengthRead;
		}
		else if (!bByPass)
		{
			TRACE_DEBUG_LAST_ERROR(eError,eComSerial,GetLastError());
			m_lNbrErrCom++;
		}
		//TRACE_DEBUG_MSG_TIME(_T("paf"), randInt);
	}
	return (*plNbrLu); 
}

BOOL CSerialPort::bWriteAndRead(long lExtraHeader,BYTE* pBufferWrite,long iSizeToWrite,BYTE* pBufferRead, long iSizeToRead,long iSizeToReadMax, long *piSizeRead,BOOL bByPass)
{
	BOOL bReturn = FALSE;

	EnterCriticalSection(&m_hCriticalSection);
	
	PurgeComm( m_hTTY, PURGE_TXABORT | PURGE_RXABORT | PURGE_TXCLEAR | PURGE_RXCLEAR );
	
	if (bWrite(pBufferWrite,iSizeToWrite))
	{
		m_iNbrErrWrite = 0;
		if (bRead(pBufferRead,iSizeToRead,piSizeRead,bByPass))
		{
			bReturn = bByPass ? TRUE : (iSizeToRead == *piSizeRead);
			m_iNbrErrRead = 0;
		}
		else if(m_iNbrErrRead < 3) //Afficher une erreur que si on a dépassé les 3 essais
		{
			m_iNbrErrRead++;
		}
		//Pas de réponse
		else if(m_iNbrErrRead > 2)
		{
			TRACE_DEBUG(eWarning,eCycle,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Reponse non recu sur port COM %u"), m_nNumPort);
		}	
	}
	else if(m_iNbrErrWrite < 3 )//Afficher une erreur qu'au bou de 3 essais
	{
		m_iNbrErrWrite++;
	} else if(m_iNbrErrWrite > 2)
	{
		TRACE_DEBUG(eWarning,eCycle,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Impossible d'ecrire sur le port COM %u"), m_nNumPort);
	}
	if (!bReturn) 
	{
		m_lNbrErrCom++;
	}

	LeaveCriticalSection(&m_hCriticalSection);
	
	if (!bReturn && ( m_iNbrErrRead>3 || m_iNbrErrRead>3 ))
	{
		TRACE_DEBUG(eDebug,eCycle,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error CSerialPort::bWriteAndRead"));
		m_iNbrErrRead  = 0;
		m_iNbrErrWrite = 0;
	}

	return bReturn;
}

long CSerialPort::lDispatchTrame(BYTE* lpData,long lSizeTotal)
{
	return (0); // 0 pour continuer sinon retour au rcev
}


/*Ajoute une requete pour carte Mesure et IO pour utiliser en dehors des cycles
		pszRQ et pszRP servent uniquement de prototype
		
		les valeur peuvent être modifier grace à la liste m_ListParams 
		membre de m_pTrameJbusRQ ou m_pTrameJbusRP eux même membre de m_pListExchange(membre de CSerialPort)
		
		pszRQ requete sous la forme : 10|05|0x1202|0|0
									addr carte|nul fct|addr data|data en fct du num de fct
		pszRP reponse sous la même forme que la requete

*/
BOOL CSerialPort::bAddExchangeJbus(LPTSTR pszRQ,LPTSTR pszRP,CListStream *pListStream)
{
	//CElemList *m_pListExchange membre
	BOOL bReturn = FALSE;
	TCHAR szText[MAX_PATH*2];
	CElemExchangeJbus *pExchangeJbus = NULL;
	int iCurrentPos;

	if (pExchangeJbus = new CElemExchangeJbus())
	{
		_stprintf(szText,_T("Requete perif : %d"), m_pListExchange->iGetCount()+1);
		pExchangeJbus->SetLabel(szText);
		pExchangeJbus->SetAutoDelete(TRUE);

	
		// requete
		iCurrentPos = 0;
		if (bReturn = pExchangeJbus->bSetConfig(TRUE,pszRQ,iCurrentPos,pListStream))
		{
			iCurrentPos = 0;
			// reponse
			if (bReturn = pExchangeJbus->bSetConfig(FALSE,pszRP,iCurrentPos,pListStream))
			{
				bReturn = (m_pListExchange->pAdd(pExchangeJbus) != NULL);
				pExchangeJbus = NULL;
			}
		
		}
		
	}
	if (pExchangeJbus) delete pExchangeJbus;
	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: ExchangeJbusSerial"));
	}
	return bReturn;
}

