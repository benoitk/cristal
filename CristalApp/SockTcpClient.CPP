// ..\socket\ethserve.cpp : implementation file
//

#include "stdafx.h"
#include "network.h"


/////////////////////////////////////////////////////////////////////////////
// CSocketTcpClient
////////////////////////////////////////////////////////////////
/*@!************************************************************************
* NOM:                      CSocketTcpClient:CSocketTcpClient
* ROLE:                     Constructeur de la classe CSocketTcpClient
* ALGORITHME:
*    Point d'entree
*    Initialisation des membres de la classe
*    Point de sortie
***********************************************************************@!)*/

CSocketTcpClient::CSocketTcpClient()
{
	memset(&m_sinClient,0,sizeof(m_sinClient));
}


/*@!************************************************************************
* NOM:                      CSocketTcpClient::~CSocketTcpClient
* ROLE:                     Destructeur de la classe client
* ALGORITHME:
*    Point d'entree
*    L'appli s'en va, pas la peine d'attendre le message de connexion
*    Point de sortie
***********************************************************************@!)*/
CSocketTcpClient::~CSocketTcpClient()
{
	// L'appli s'en va, pas la peine d'attendre le message de connexion
}


/*@!************************************************************************
* NOM:                      CSocketTcpClient::lConnect
* ALGORITHME:
***********************************************************************@!)*/
long CSocketTcpClient::lConnect()
{
	long erreur=1;
	PHOSTENT phe;
	long err;
	char szText[MAX_PATH];

#ifdef _UNICODE
	wcstombs(szText,m_szNomMachineDst,MAX_PATH);
#else
	strcpy(szText,m_szNomMachineDst);
#endif

	phe = gethostbyname(szText);
	if (phe != NULL) 
	{
		// Creer la socket 
		if (m_nSocket == INVALID_SOCKET) m_nSocket = socket( AF_INET, SOCK_STREAM, 0);
		if (m_nSocket != INVALID_SOCKET) 
		{
			m_sinClient.sin_family = AF_INET;
			memcpy((TCHAR *)&(m_sinClient.sin_addr), phe->h_addr,phe->h_length);
			m_sinClient.sin_port = htons(m_nNumPort+ETH_SHIFT_TYPE_APPLI_PORT); 
            err = ::connect( m_nSocket, (PSOCKADDR) &m_sinClient, sizeof( m_sinClient));
		}
	}

	if ((err != 0) && (err != SOCKET_ERROR) ) 
	{
		err = WSAGetLastError();
		AfficheMessage(err); 
	}

	return (err == 0);
}




