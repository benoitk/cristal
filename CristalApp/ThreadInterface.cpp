#include "stdafx.h"
#include "network.h"



CEnumInterface::CEnumInterface()
{
	m_pSocketIHM = NULL;
	m_pCarteIO = NULL;
	m_pCarteMesure = NULL;
	m_pCarteJbusSlave = NULL;
}

CEnumInterface::~CEnumInterface()
{
}

void CEnumInterface::SetExternalInterface(CThreadInterface *pSocketIHM,CThreadInterface *pCarteIO,CThreadInterface *pCarteMesure,CThreadInterface *pCarteJbusSlave)
{
	m_pSocketIHM = pSocketIHM;
	m_pCarteIO = pCarteIO;
	m_pCarteMesure = pCarteMesure;
	m_pCarteJbusSlave = pCarteJbusSlave;
}

CThreadInterface *CEnumInterface::pGetSelectedInterface(int iNum)
{
	CThreadInterface *pInterface = NULL;

	if (m_pSocketIHM)
	{
		if (m_pSocketIHM->bGetNumInterface() == iNum) pInterface = m_pSocketIHM;
	}
	if (m_pCarteIO)
	{
		//if (m_pCarteIO->bGetNumInterface() == iNum) pInterface = m_pCarteIO;
		if ((iNum >= NUM_INTERFACE_CARTE_IO_MIN) && (iNum <= NUM_INTERFACE_CARTE_IO_MAX)) 
		{
			pInterface = m_pCarteIO;
		}
	}
	if (m_pCarteMesure)
	{
		if (m_pCarteMesure->bGetNumInterface() == iNum) pInterface = m_pCarteMesure;
	}

	if ((pInterface == NULL) && (m_pSocketIHM == m_pCarteIO) && (m_pSocketIHM == m_pCarteMesure))
	{
		pInterface = m_pSocketIHM;
	}

	if (m_pCarteJbusSlave)
	{
		if (m_pCarteJbusSlave->bGetNumInterface() == iNum) pInterface = m_pCarteJbusSlave;
	}

	return pInterface;
};

/////////////////////////////////////////////////////////////////////////////
// CThreadInterface
////////////////////////////////////////////////////////////////
/*@!************************************************************************
* NOM:                      CThreadInterface:CThreadInterface
* ROLE:                     Constructeur de la classe CThreadInterface
* ALGORITHME:
*    Point d'entree
*    Initialisation des membres de la classe
*    Point de sortie
***********************************************************************@!)*/

CThreadInterface::CThreadInterface():CThread()
{
	m_bModeInteger = FALSE;
	m_bNumInterface = -1;
	m_bCanRead = FALSE;
	m_bCanWrite = FALSE;
	m_bError= FALSE;
}


/*@!************************************************************************
* NOM:                      CThreadInterface::~CThreadInterface
* ROLE:                     Destructeur de la classe client
* ALGORITHME:
***********************************************************************@!)*/
CThreadInterface::~CThreadInterface()
{
}

void CThreadInterface::SetAccess(BOOL bCanRead,BOOL bCanWrite)
{
	m_bCanRead = bCanRead;
	m_bCanWrite = bCanWrite;
	m_lNbrErrCom = 0;
	m_iNbrErrRead = 0;
	m_iNbrErrWrite = 0;
}


BOOL CThreadInterface::bReadConfig(LPCTSTR pszFileName)
{
	m_bNumInterface = iGetPrivateProfileInt(_T("Config"), _T("m_bNumInterface"),m_bNumInterface, pszFileName); 
	m_bCanRead = iGetPrivateProfileInt(_T("Config"), _T("m_bCanRead"),m_bCanRead, pszFileName); 
	m_bCanWrite = iGetPrivateProfileInt(_T("Config"), _T("m_bCanWrite"),m_bCanWrite, pszFileName); 
	m_bModeInteger = iGetPrivateProfileInt(_T("Config"), _T("m_bModeInteger"),m_bModeInteger, pszFileName); 

	return TRUE;
}

BOOL CThreadInterface::bWriteConfig(LPCTSTR pszFileName)
{
	BOOL bReturn = TRUE;

	bReturn = bWritePrivateProfileInt(_T("Config"), _T("m_bNumInterface"),m_bNumInterface, pszFileName); 
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Config"), _T("m_bCanRead"),m_bCanRead, pszFileName); 
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Config"), _T("m_bCanWrite"),m_bCanWrite, pszFileName); 
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Config"), _T("m_bModeInteger"),m_bModeInteger, pszFileName); 

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error"));

	return (bReturn);
}


