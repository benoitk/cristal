#pragma once

class  CSocketTcpServeur : public CSocketBase
{
// Construction
public:
	CSocketTcpServeur();
	virtual ~CSocketTcpServeur();
/////////////////////////////////// FONCTIONS
protected:
	// Membres
	SOCKET      m_nSocketListen;  // Socket
	SOCKADDR_IN m_sinListen;
	SOCKADDR_IN m_sinServeur;

public:
	// Fonctions normales de connexion  / deconnexion
	virtual long lConnect();          
	virtual void CloseSocket();       // Fermeture de la connexion
};

/////////////////////////////////////////////////////////////////////////////
