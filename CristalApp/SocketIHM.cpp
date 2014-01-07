// ..\socket\ethserve.cpp : implementation file
//

#include "stdafx.h"
#include "header.h"


/////////////////////////////////////////////////////////////////////////////
// CSocketIHM
////////////////////////////////////////////////////////////////
/*@!************************************************************************
* NOM:                      CSocketIHM:CSocketIHM
* ROLE:                     Constructeur de la classe CSocketIHM
* ALGORITHME:
*    Point d'entree
*    Initialisation des membres de la classe
*    Point de sortie
***********************************************************************@!)*/

CSocketIHM::CSocketIHM():CSocketTcpServeur()
{
	m_bNumInterface = NUM_INTERFACE_SOCKET_IHM;
}
	

BOOL CSocketIHM::bReadConfig(LPCTSTR pszFileName,CListStream *pListStream)
{
	BOOL bReturn = TRUE;
	unsigned short nNumPort;
	long lSizeDataMax;


	bReturn = CThreadInterface::bReadConfig(pszFileName);
	// taille du buffer
	lSizeDataMax = iGetPrivateProfileInt(_T("Config"),_T("m_lSizeDataMax"),1024,pszFileName);
	// port TCP/IP
	nNumPort = iGetPrivateProfileInt(_T("Config"),_T("m_nNumPort"),8192,pszFileName);
	ConfigSocket(nNumPort,lSizeDataMax,_T("localhost"));
	
	if (bReturn) bReturn = m_ElemCycleStep.bReadConfig(_T("0"),pszFileName,pListStream);

	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("BOOL CSocketIHM::bReadConfig"));
		TRACE_DEBUG_IHM(eError,eConfig,eErrorSocketReadConfig);
	}

	return (bReturn);
}

BOOL CSocketIHM::bWriteConfig(LPCTSTR pszFileName)
{
	BOOL bReturn = TRUE;

	bReturn = CThreadInterface::bWriteConfig(pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Config"),_T("m_lSizeDataMax"),m_lSizeDataMax,pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Config"),_T("m_nNumPort"),m_nNumPort,pszFileName);

	bReturn = m_ElemCycleStep.bWriteConfig(_T("0"),pszFileName);

	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("BOOL CSocketIHM::bWriteConfig"));
		TRACE_DEBUG_IHM(eError,eConfig,eErrorSocketWriteConfig);
	}

	return (bReturn);
}

/*@!************************************************************************
* NOM:                      CSocketIHM::~CSocketIHM
* ROLE:                     Destructeur de la classe client
* ALGORITHME:
*    Point d'entree
*    L'appli s'en va, pas la peine d'attendre le message de connexion
*    Point de sortie
***********************************************************************@!)*/
CSocketIHM::~CSocketIHM()
{
}

long CSocketIHM::lDispatchTrame(long lExtraHeader,BYTE* lpData,long lSizeTotal,long *plUsed)
{
	// séparation du lExtraHeader
	if (m_ElemCycleStep.bFindRqAndExecuteFromIHM(lExtraHeader,TRUE,TRUE,lpData,lSizeTotal,lpData,plUsed,m_lSizeDataMax,m_ExternalInterface))
	{
		// lpData contient toujours le lExtraHeader,
		lWrite(lExtraHeader,lpData,*plUsed);
	}
	// il faut toujours repondre qqc
	else lWrite(lExtraHeader,lpData,0);
	*plUsed = lSizeTotal;
	return 0;
}



