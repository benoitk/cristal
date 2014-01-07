#pragma once


#define ETH_SHIFT_TYPE_APPLI_PORT              0/*8510*/


/* Longueur maximum admissible d'une ligne de texte */
#define ETH_MAX_LG_TEXTE           130
////////////////////////////////////////////////////////////////////////////
// CSocketBase window
class  CSocketBase : public CThreadInterface
{
protected:
	// Membres
	SOCKET m_nSocket;  // Socket
	short m_nNumPort;
	long m_lSizeDataMax;
	BYTE *m_pRxBuffer;
	BOOL m_bConnected;
	SOCKADDR_IN m_sin;
	TCHAR m_szNomMachineDst[ETH_MAX_LG_TEXTE];
	// Membres statiques
	static BOOL m_bStatusInit;

//////////////// FONCTIONS
public:
	CSocketBase();
	short sGetNumPort(){return m_nNumPort;};
	virtual ~CSocketBase();
    //virtual DWORD RunThread();
    virtual void run();
	virtual void ConfigSocket(unsigned short nNumPort, long lSizeDataMax,LPTSTR szHostName);
	virtual void AfficheMessage(long lErr);
	virtual BOOL bGetConnected(){return ((m_nSocket != INVALID_SOCKET) && m_bConnected);};   
	virtual void Stop();

	// Methode de transmission de donnees
	virtual long lWrite(long lExtraHeader,BYTE* lpData,long lSizeTotal);
	virtual long lRead(long *plExtraHeader,BYTE* lpData,long lSizeMax,long *plNbrLu);       // Message recu
	virtual long lConnect() = 0;          
	virtual long lDispatchTrame(long lExtraHeader,BYTE* lpData,long lSizeTotal,long *plUsed);

protected:
	// Utilitaires
	// Fonction globale a toutes les classes d'initialisation
	static BOOL bInitGenerale();
	long lProtectedRead(BYTE* pBuffer,long lSize);
	long lProtectedWrite(BYTE* pBuffer,long lSize);

	virtual BOOL bOnConnect(LPCTSTR szIni = NULL);
	virtual BOOL bOnDeconnect();
	virtual long lSetOption();
	virtual void CloseSocket();       // Fermeture de la connexion
};

/////////////////////////////////////////////////////////////////////////////
