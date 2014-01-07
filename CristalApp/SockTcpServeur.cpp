// ..\socket\ethserve.cpp : implementation file
//

#include "stdafx.h"
#include "network.h"


#define ETH_NOMBRE_CONNEXION_MAXI    1

/////////////////////////////////////////////////////////////////////////////
// CSocketTcpServeur
////////////////////////////////////////////////////////////////
/*@!************************************************************************
* NOM:                      CSocketTcpServeur:CSocketTcpServeur
* ROLE:                     Constructeur de la classe CSocketTcpServeur
* ALGORITHME:
*    Point d'entree
*    Initialisation des membres de la classe
*    Point de sortie
***********************************************************************@!)*/

CSocketTcpServeur::CSocketTcpServeur():CSocketBase()
{
	// Initialisation des membres de la classe
	m_nSocketListen=INVALID_SOCKET;
	memset(&m_sinListen,0,sizeof(m_sinListen));
	memset(&m_sinServeur,0,sizeof(m_sinServeur));
}


/*@!************************************************************************
* NOM:                      CSocketTcpServeur::~CSocketTcpServeur
* ROLE:                     Destructeur de la classe client
* ALGORITHME:
*    Point d'entree
*    L'appli s'en va, pas la peine d'attendre le message de connexion
*    Point de sortie
***********************************************************************@!)*/
CSocketTcpServeur::~CSocketTcpServeur()
{
  if (m_nSocketListen > INVALID_SOCKET) closesocket( m_nSocketListen );
}


/*@!************************************************************************
* NOM:                      CSocketTcpServeur::lConnect
* ROLE:                     Attendre une connexion
* DONNEES INTERNES:			unsigned short int nTypeAppli       : 
* ALGORITHME:
*    Point de sortie
***********************************************************************@!)*/
long CSocketTcpServeur::lConnect()
{
	long erreur=1;
    FD_SET readfds; 

	if (m_nSocketListen == INVALID_SOCKET)
	{
		m_nSocketListen = socket( AF_INET, SOCK_STREAM, 0);
		if (m_nSocketListen != INVALID_SOCKET) 
		{
			m_sinListen.sin_family = AF_INET;
			m_sinListen.sin_addr.S_un.S_addr = INADDR_ANY; 
			m_sinListen.sin_port = htons(m_nNumPort+ETH_SHIFT_TYPE_APPLI_PORT); 

			// Faire le bind
			if ((erreur = bind( m_nSocketListen, (struct sockaddr FAR *) &m_sinListen, sizeof(m_sinListen))) == SOCKET_ERROR) 
			{
				closesocket( m_nSocketListen );
				m_nSocketListen=INVALID_SOCKET;
			}
		}
	}
	if (m_nSocketListen != INVALID_SOCKET)
	{
		// Se mettre en ecoute
		if ((erreur = listen( m_nSocketListen, ETH_NOMBRE_CONNEXION_MAXI )) == 0) 
		{
			// Faire le select
			FD_ZERO( &readfds ); 
			FD_SET(m_nSocketListen, &readfds ); 
			erreur = select( 1, &readfds, NULL, NULL, NULL);// bloquant
			
			if (erreur == 0) 
			{
				erreur = -1;//WSAGetLastError() ;
			}
			else if (erreur > 0 )
			{
				// Find the socket that received an incoming connection and accept the connection. 
				FD_ISSET(m_nSocketListen, &readfds );
				// Accept the connection from the client.  We ignore the client's  address here. 
				m_nSocket = accept(m_nSocketListen, NULL, NULL ); 
				if (m_nSocket != INVALID_SOCKET)
				{
					erreur = 0;
				}
			}
		}
	}
	
	return (erreur == 0);
}

void CSocketTcpServeur::CloseSocket()
{
	if (m_nSocketListen != INVALID_SOCKET)
	{
		shutdown(m_nSocketListen,2/*SD_BOTH*/);
		closesocket( m_nSocketListen );
		m_nSocketListen=INVALID_SOCKET;
	}
	CSocketBase::CloseSocket();
}


