#include "stdafx.h"
#include "header.h"
#include "header_qt.h"

/////////////////////////////////////////////////////////////////////////////
// CCarteMesure
////////////////////////////////////////////////////////////////
/*@!************************************************************************
* NOM:                      CCarteMesure:CCarteMesure
* ROLE:                     Constructeur de la classe CCarteMesure
* ALGORITHME:
*    Point d'entree
*    Initialisation des membres de la classe
*    Point de sortie
***********************************************************************@!)*/

CCarteMesure::CCarteMesure():CSerialPort()
{
	m_bNumInterface = NUM_INTERFACE_CARTE_MESURE;
	m_bCanRead = TRUE;
	m_bCanWrite = TRUE;
	m_nNumPort = 1;
	m_ExternalInterface.SetExternalInterface(NULL,NULL,this,NULL);
}


/*@!************************************************************************
* NOM:                      CCarteMesure::~CCarteMesure
* ROLE:                     Destructeur de la classe client
* ALGORITHME:
***********************************************************************@!)*/
CCarteMesure::~CCarteMesure()
{
}


/******************************************************************************
 * @func :	ReadConfig
 * 
 * Rôle  :	Initialisation de donnees membres
 * @parm :	LPCSTR | szIni | fichier de configuration
 *****************************************************************************/
BOOL CCarteMesure::bReadConfig(LPCTSTR pszFileName,CListStream *pListStream)
{
	BOOL bReturn;

	bReturn = CSerialPort::bReadConfig(pszFileName);
	
	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("BOOL CCarteMesure::bReadConfig"));
		TRACE_DEBUG_IHM(eError,eConfig,eErrorCarteMesureReadConfig);
	}

	return bReturn;
}


/******************************************************************************
 * @func :	bWriteConfig
 * 
 * Rôle  :	enregistre la configuration dans un fichier
 * @parm :	LPCSTR | szIni | fichier de configuration
 *****************************************************************************/
BOOL CCarteMesure::bWriteConfig(LPCTSTR pszFileName)
{
	BOOL bReturn;

	bReturn = CSerialPort::bWriteConfig(pszFileName);

	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("BOOL CCarteMesure::bWriteConfig"));
		TRACE_DEBUG_IHM(eError,eConfig,eErrorCarteMesureWriteConfig);
	}
	return TRUE;
}



//DWORD CCarteMesure::RunThread()
void CCarteMesure::run()
{
	m_bRun = bOpen();
    qDebug() << "Interface : " << this->m_bNumInterface << " Thread : " << QThread::currentThreadId  ();

	m_bInRunThread = TRUE;
	while (m_bRun)
	{
		Sleep(1000);
	}
	Close();

//	return 0;
}


