// ..\socket\ethwnd.cpp : implementation file
//

#include "stdafx.h"
#include "network.h"


#define MSG_SOCKET_READY		_T("socket ready, waiting for connection...")
#define MSG_SOCKET_EXIT			_T("socket exit")
#define TCP_CONNECTED			_T("Serveur connected")
#define TCP_DISCONNECTED		_T("Serveur disconnected")


/////////////////////////////////////////////////////////////////////////////
// CSocketBase
BOOL  CSocketBase::m_bStatusInit=bInitGenerale();

/*@!************************************************************************
* NOM:                      CSocketBase:CSocketBase
* ALGORITHME:
*    Point d'entree
*    Initilalisation des membres de la classe
*    Si la DLL socket n'est pas initialisée
*      Le faire
*    FINSI
*    Point de sortie
***********************************************************************@!)*/
CSocketBase::CSocketBase() : CThreadInterface()
{
	m_bModeInteger = FALSE;
	m_nSocket = INVALID_SOCKET ;
	m_nNumPort=-1;
	m_bConnected = FALSE;

	m_pRxBuffer = NULL;
	m_bRun = FALSE;
	m_lSizeDataMax = 2048;
	m_szNomMachineDst[0] = 0;
}

BOOL CSocketBase::bOnConnect(LPCTSTR szIni)
{
	bSendMessageToHwnd(m_hWnd,(BYTE*)TCP_CONNECTED,(lstrlen(TCP_CONNECTED)+1)*sizeof(TCHAR), WM_TCP_CNX);
	
	return (m_bConnected);
}

BOOL CSocketBase::bOnDeconnect()
{
	bSendMessageToHwnd(m_hWnd,(BYTE*)TCP_DISCONNECTED,(lstrlen(TCP_DISCONNECTED)+1)*sizeof(TCHAR), WM_TCP_CNX);
	
	return (!m_bConnected);
}


void  CSocketBase::ConfigSocket(unsigned short nNumPort,long lSizeDataMax,LPTSTR szHostName)
{
	lstrcpy(m_szNomMachineDst,szHostName);
	m_nNumPort=nNumPort;
	m_lSizeDataMax = lSizeDataMax;
	if (m_pRxBuffer == NULL) 
	{
		m_pRxBuffer = (BYTE*)malloc(lSizeDataMax + 16);
	}
	else
	{
		m_pRxBuffer = (BYTE*)realloc(m_pRxBuffer,lSizeDataMax + 16);
	}

}

/*@!************************************************************************
* NOM:                      CSocketBase:~CSocketBase
* ROLE:                     Destructeur de la classe CSocketBase
* ALGORITHME:
*    Point d'entree
*    SI la connexion est encore ouverte ALORS
*      La fermer
*    FINSI
*    SI c'est le dernier objet de l'application   
*      ALORS Fermer la DLL socket
*    FINSI
*    Point de sortie
***********************************************************************@!)*/
CSocketBase::~CSocketBase()
{
  // SI la connexion est encore ouverte ALORS  La fermer
  CloseSocket();
  if (m_pRxBuffer) free(m_pRxBuffer);
}

long CSocketBase::lSetOption()
{
	BOOL bKeppAlive = TRUE;
	int iBufferSize = 8*1024;
	BOOL bKeppAlive2 = TRUE;
	int iBufferSize2 = 8*1024;
	//LINGER linger;
	//LINGER linger2;
	int iSize;
	long err;

	err = setsockopt(m_nSocket , SOL_SOCKET,SO_KEEPALIVE , (char*)&bKeppAlive, sizeof(bKeppAlive) );
	err &= setsockopt(m_nSocket , SOL_SOCKET,SO_RCVBUF , (char*)&iBufferSize, sizeof(iBufferSize) );
	err &= setsockopt(m_nSocket , SOL_SOCKET,SO_SNDBUF , (char*)&iBufferSize, sizeof(iBufferSize) );
	/*linger.l_onoff = 1;
	linger.l_linger = 1;
	err &= setsockopt(m_nSocket , SOL_SOCKET,SO_LINGER , (BYTE*)&linger, sizeof(linger) );
*/
	err &= setsockopt(m_nSocket , IPPROTO_TCP,SO_KEEPALIVE , (char*)&bKeppAlive, sizeof(bKeppAlive) );
	err &= setsockopt(m_nSocket , IPPROTO_TCP,SO_RCVBUF , (char*)&iBufferSize, sizeof(iBufferSize) );
	err &= setsockopt(m_nSocket , IPPROTO_TCP,SO_SNDBUF , (char*)&iBufferSize, sizeof(iBufferSize) );

	iSize = sizeof(BOOL);
	err = getsockopt(m_nSocket , SOL_SOCKET,SO_KEEPALIVE , (char*)&bKeppAlive2, &iSize);
	err &= (bKeppAlive2 != bKeppAlive);
	iSize = sizeof(int);
	err &= getsockopt(m_nSocket , SOL_SOCKET,SO_RCVBUF , (char*)&iBufferSize2, &iSize);
	err &= (iBufferSize2 != iBufferSize);
	iSize = sizeof(int);
	err &= getsockopt(m_nSocket , SOL_SOCKET,SO_SNDBUF , (char*)&iBufferSize2,&iSize );
	err &= (iBufferSize2 != iBufferSize);
	/*linger2.l_onoff = 1;
	linger2.l_linger = 10;
	iSize = sizeof(linger2);
	err &= getsockopt(m_nSocket , SOL_SOCKET,SO_LINGER , (char*)&linger2, &iSize );
	err &= (memcmp(&linger,&linger2,sizeof(linger2)) != 0);*/
	iSize = sizeof(BOOL);
	err &= getsockopt(m_nSocket , IPPROTO_TCP,SO_KEEPALIVE , (char*)&bKeppAlive2, &iSize);
	err &= (bKeppAlive2 != bKeppAlive);
	iSize = sizeof(int);
	err &= getsockopt(m_nSocket , IPPROTO_TCP,SO_RCVBUF , (char*)&iBufferSize2, &iSize );
	err &= (iBufferSize2 != iBufferSize);
	iSize = sizeof(int);
	err &= getsockopt(m_nSocket , IPPROTO_TCP,SO_SNDBUF , (char*)&iBufferSize2, &iSize );
	err &= (iBufferSize2 != iBufferSize);
	return err;
}

/******************************************************************************
 * @func :	lProtectedRead
 * 
 * Rôle :	
 *
 * @parm :	BYTE* | pBuffer | buffer recevant les données
 * @parm :	long | lSize | nombre de données à lire avant de retourner
 *
 * @rdesc: valeur > 0 ou code d'erreur.
 *****************************************************************************/
long CSocketBase::lProtectedRead(BYTE* pBuffer,long lSize)
{
	long rr = 1;

	/* Tant que la longueur voulue n'est pas atteinte */
	while( (lSize > 0 ) && (rr > 0)) 
	{	/* Lire ce qu'il y a dans la socket */
		rr=recv(m_nSocket,(char*)pBuffer,lSize,0);  
		if (rr > 0)
		{
			lSize -= rr;
			pBuffer += rr;
		}
		else if (/*(rr == WSAEINPROGRESS) || */(rr == WSAEINTR)/* || (rr == WSAEWOULDBLOCK)*/)
		{
			rr = 1;
		}
	}
	return (rr);
}

long CSocketBase::lRead(long *plExtraHeader,BYTE* lpData,long lSizeMax,long *plNbrLu)
{
	long lRet=0;
	long lNbrToRead=0;
	
	*plNbrLu = 0;
	if (m_nSocket != INVALID_SOCKET) 
	{
		// Lire la longueur
		lRet=lProtectedRead(lpData,sizeof(lNbrToRead));
		if (lRet > 0) 
		{	
			lNbrToRead = *((long*)lpData);
			// lire lExtraHeader
			lRet=lProtectedRead((BYTE*)plExtraHeader,sizeof(*plExtraHeader));
			if (lRet > 0) 
			{	
				// Controle de la longueur
				if (lNbrToRead  <= m_lSizeDataMax) 
				{
					// Lire le reste de la trame
					if (lNbrToRead > 0) lRet=lProtectedRead((BYTE*)lpData,lNbrToRead);
					if (lRet > 0)
					{
						*plNbrLu = lNbrToRead;
					}
				}
				else
				{
					lRet = 0;
				}
			}
		}
	}
	return lRet; 
}

/*@!************************************************************************
* NOM:                      CSocketBase::lProtectedWrite
***********************************************************************@!)*/
long CSocketBase::lProtectedWrite (BYTE* lpData,long lSizeTotal)
{
	long erreur = 0;
	long rw=1;

	if ((m_nSocket != INVALID_SOCKET) && m_bConnected)
	{
		::EnterCriticalSection(&m_hCriticalSection);
		/* Tant que la longueur voulue n'est pas atteinte */
		while( (lSizeTotal > 0 ) && (rw>0) ) 
		{
			/* Ecrire ce qu'il reste dans la socket */
			rw=send(m_nSocket,(char*)lpData,lSizeTotal,0);   
			if (rw>0)
			{
				lSizeTotal -= rw;
				lpData += rw;
			}
			else
			{
				erreur = WSAGetLastError();
				if ((erreur == WSAEINTR) || (erreur == WSAEINPROGRESS))
				{	// continuer
					rw = 1;
					Sleep(0);
				}
				else // arreter
				{
					AfficheMessage(erreur); 
					CloseSocket();
					rw = 0;
				}
			}
		}
		::LeaveCriticalSection(&m_hCriticalSection);
	}

	return (rw); 
}

long CSocketBase::lWrite (long lExtraHeader,BYTE* lpData,long lSizeTotal)
{
	long erreur = 0;
	long rw=1;

	rw = lProtectedWrite((BYTE*)&lSizeTotal,sizeof(lSizeTotal));
	if (rw > 0)
	{
		rw = lProtectedWrite ((BYTE*)&lExtraHeader,sizeof(lExtraHeader));
		if (rw > 0)
		{
			rw = lProtectedWrite (lpData,lSizeTotal);
		}
	}

	return (rw); 
}




//DWORD CSocketBase::RunThread()
void CSocketBase::run()
{
	long lNbrLu=0;
	long lCode=0;
	long lUsed = 0;
	long lReste = 0;
	long lExtraHeader = -1;


	m_bInRunThread = TRUE;
    m_bRun = TRUE;
	bSendMessageToHwnd(m_hWnd,(BYTE*)MSG_SOCKET_READY,lstrlen(MSG_SOCKET_READY)*sizeof(TCHAR)+sizeof(TCHAR), WM_TCP);
	while (m_bRun)
	{
		if ((m_nSocket == INVALID_SOCKET) || !m_bConnected) 
		{
			m_bConnected = lConnect();
			if (m_bConnected) 
			{
				lSetOption();
				bOnConnect();
			}
			else Sleep(100);
			lReste = 0;
		}
		else 
		{
			lCode = lRead(&lExtraHeader, m_pRxBuffer,m_lSizeDataMax,&lNbrLu);
			if (lCode <= 0)
			{
				AfficheMessage(WSAGetLastError()); 
				if (m_bRun) CloseSocket();
			}
			if (lNbrLu >= 0)
			{
				lNbrLu += lReste;
				// suppression entete + longueur
				if (lDispatchTrame(lExtraHeader,m_pRxBuffer,lNbrLu,&lUsed) == 0)
				{
				}
				lReste = lNbrLu - lUsed;
				if ((lUsed > 0) && (lReste > 0))
				{
					memmove(m_pRxBuffer,m_pRxBuffer + lUsed, lReste);
				}
			}
		}
	}

    if ( m_nSocket != INVALID_SOCKET ) CloseSocket(); 

	bSendMessageToHwnd(m_hWnd,(BYTE*)MSG_SOCKET_EXIT,lstrlen(MSG_SOCKET_EXIT)*sizeof(TCHAR)+sizeof(TCHAR), WM_TCP);


//	return 0;
}

/*@!************************************************************************
* NOM:                      CSocketBase::bInitGenerale
* ROLE:                     Initialisation de la DLL socket
* CONTRAINTES:				Le premier objet vient d'etre créé
* ALGORITHME:
*    Point d'entree
*    SI DLL deja initialisee
*      Erreur grave !!!
*    SINON
*      Effacement du fichier de trace
*      Si la recherche de la DLL se passe mal
*        Erreur grave
*      SINON
*        SI la version de la DLL n'est pas correcte
*          Erreur grave
*        SINON
*          Rechercher notre nom machine une fois pour toute
*        FINSI
*      FINSI
*    FINSI
*    Point de sortie
***********************************************************************@!)*/
BOOL CSocketBase::bInitGenerale()
{
	WORD wVersionRequested=0x101;
	WSADATA wsaData;
	BOOL bInit;

	// Si la recherche de la DLL se passe mal
	if (bInit = ( WSAStartup( wVersionRequested, &wsaData ) == 0 )) 
	{
		// SI la version de la DLL n'est pas correcte
		bInit = ( LOBYTE( wsaData.wVersion ) == 1 && HIBYTE( wsaData.wVersion ) == 1 );
		if (!bInit) 
		{
			TRACE_DEBUG(eError,eComSocket,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),_T("PB init Socket"));
			// Erreur grave
			WSACleanup( );
		} 
	}
	return bInit;
}



long CSocketBase::lDispatchTrame(long lExtraHeader,BYTE* lpData,long lSizeTotal,long *plUsed)
{
	*plUsed = 0;
	return (0); // 0 pour continuer sinon retour au rcev
}


/*@!************************************************************************
* NOM:                      CSocketBase::CloseSocket
* ROLE:                     Fermer un connexion
* ALGORITHME:
*    Point d'entree
*    SI l'appli n'est pas au courrant de la perte de connexion
*      Autoenvoi du message de perte de connexion
*    FINSI
*    SI la socket existe
*      La fermer
*    FINSI
*    Point de sortie
***********************************************************************@!)*/
void CSocketBase::CloseSocket()
{
	// SI la socket existe
	if (m_nSocket != INVALID_SOCKET) 
	{
	//	WSACancelBlockingCall();
		shutdown(m_nSocket,2/*SD_BOTH*/);
		closesocket( m_nSocket );
	}

	m_nSocket = INVALID_SOCKET;
	m_bConnected = FALSE;
	bOnDeconnect();
}

void CSocketBase::Stop()
{
	m_bRun = FALSE;
	CloseSocket();
	CThread::Stop();
}

void CSocketBase::AfficheMessage(long lErr)
{
	TCHAR *szMsg = NULL;

	if (lErr == WSANOTINITIALISED) szMsg = TEXT("A successful WSAStartup must occur before using this function.");
	else if (lErr == WSAENETDOWN) szMsg = TEXT("The network subsystem has failed. ");
	else if (lErr == WSAEADDRINUSE) szMsg = TEXT("The socket's local address is already in use and the socket was not marked to allow address reuse with SO_REUSEADDR. This error usually occurs when executing bind, but could be delayed until this function if the bind was to a partially wild-card address (involving ADDR_ANY) and if a specific address needs to be committed at the time of this function.");
	else if (lErr == WSAEINTR) szMsg = TEXT("The (blocking) Windows Socket 1.1 call was canceled through WSACancelBlockingCall. ");
	else if (lErr == WSAEINPROGRESS) szMsg = TEXT("A blocking Windows Sockets 1.1 call is in progress, or the service provider is still processing a callback function. ");
	else if (lErr == WSAEALREADY) szMsg = TEXT("A nonblocking connect call is in progress on the specified socket.\nNote In order to preserve backward compatibility, this error is reported as WSAEINVAL to Windows Sockets 1.1 applications that link to either WINSOCK.DLL or WSOCK32.DLL.");
	else if (lErr == WSAEADDRNOTAVAIL) szMsg = TEXT("The remote address is not a valid address (such as ADDR_ANY). ");
	else if (lErr == WSAEAFNOSUPPORT) szMsg = TEXT("Addresses in the specified family cannot be used with this socket."); 
	else if (lErr == WSAECONNREFUSED) szMsg = TEXT("The attempt to connect was forcefully rejected. ");
	else if (lErr == WSAEFAULT) szMsg = TEXT("The name or the namelen parameter is not a valid part of the user address space, the namelen parameter is too small, or the name parameter contains incorrect address format for the associated address family. ");
	else if (lErr == WSAEINVAL) szMsg = TEXT("The parameter s is a listening socket, or the destination address specified is not consistent with that of the constrained group the socket belongs to. ");
	else if (lErr == WSAEISCONN) szMsg = TEXT("The socket is already connected (connection-oriented sockets only). ");
	else if (lErr == WSAENETUNREACH) szMsg = TEXT("The network cannot be reached from this host at this time. ");
	else if (lErr == WSAENOBUFS) szMsg = TEXT("No buffer space is available. The socket cannot be connected. ");
	else if (lErr == WSAENOTSOCK) szMsg = TEXT("The descriptor is not a socket. ");
	else if (lErr == WSAETIMEDOUT) szMsg = TEXT("Attempt to connect timed out without establishing a connection. ");
	else if (lErr == WSAEWOULDBLOCK)  szMsg = TEXT("The socket is marked as nonblocking and the connection cannot be completed immediately. ");
	else if (lErr == WSAEACCES) szMsg = TEXT("Attempt to connect datagram socket to broadcast address failed because setsockopt option SO_BROADCAST is not enabled. ");
	else if (lErr == WSAENOTCONN) szMsg = TEXT(" The socket is not connected. ");
	else if (lErr == WSAENETRESET) szMsg = TEXT(" The connection has been broken due to the keep-alive activity detecting a failure while the operation was in progress. ");
	else if (lErr == WSAEOPNOTSUPP) szMsg = TEXT(" MSG_OOB was specified, but the socket is not stream-style such as type SOCK_STREAM, out-of-band data is not supported in the communication domain associated with this socket, or the socket is unidirectional and supports only send operations. ");
	else if (lErr == WSAESHUTDOWN) szMsg = TEXT(" The socket has been shut down; it is not possible to recv on a socket after shutdown has been invoked with how set to SD_RECEIVE or SD_BOTH. ");
	else if (lErr == WSAEMSGSIZE) szMsg = TEXT(" The message was too large to fit into the specified buffer and was truncated. ");
	else if (lErr == WSAECONNABORTED) szMsg = TEXT(" The virtual circuit was terminated due to a time-out or other failure. \nThe application should close the socket as it is no longer usable. ");
	else if (lErr == WSAECONNRESET) szMsg = TEXT(" The virtual circuit was reset by the remote side executing a <hard> or <abortive> close. \nThe application should close the socket as it is no longer usable. On a UDP datagram socket this error would indicate that a previous send operation resulted in an ICMP <Port Unreachable> message. ");
	else if (lErr == WSAEHOSTUNREACH) szMsg = TEXT(" The remote host cannot be reached from this host at this time. ");
	else szMsg = NULL;

	m_lNbrErrCom++;
	TRACE_DEBUG_IHM(eError,eComSocket,eErrorSocketRunThread);

	if (szMsg) 
	{
		bSendMessageToHwnd(m_hWnd,(BYTE*)szMsg,lstrlen(szMsg)+1,WM_EXCEPTION);
		TRACE_DEBUG(eError,eComSocket,_T(__FILE__),_T(__FUNCTION__),__LINE__,(LPCTSTR)_T("ERROR Socket : %s"),szMsg);
	}
}




