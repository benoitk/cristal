#include "stdafx.h"
#include "header.h"


/////////////////////////////////////////////////////////////////////////////
// CCarteJbusSlave
////////////////////////////////////////////////////////////////
/*@!************************************************************************
* NOM:                      CCarteJbusSlave:CCarteJbusSlave
* ROLE:                     Constructeur de la classe CCarteJbusSlave
* ALGORITHME:
*    Point d'entree
*    Initialisation des membres de la classe
*    Point de sortie
***********************************************************************@!)*/
CCarteJbusSlave::CCarteJbusSlave():CSerialPort(),m_ListDataCanRead(NBR_CMD_READ_JBUS_SLAVE_MAX),m_ListDataCanWrite(NBR_CMD_WRITE_JBUS_SLAVE_MAX)
{
	m_bNumInterface = NUM_INTERFACE_CARTE_JBUS_SLAVE;
	m_bCanRead = FALSE;
	m_bCanWrite = TRUE;
	m_nNumPort = 3;
	m_ExternalInterface.SetExternalInterface(NULL,NULL,NULL,this);
}


/*@!************************************************************************
* NOM:                      CCarteJbusSlave::~CCarteJbusSlave
* ROLE:                     Destructeur de la classe client
* ALGORITHME:
***********************************************************************@!)*/
CCarteJbusSlave::~CCarteJbusSlave()
{
}


/******************************************************************************
 * @func :	ReadConfig
 * 
 * Rôle  :	Initialisation de donnees membres
 * @parm :	LPCSTR | szIni | fichier de configuration
 *****************************************************************************/
BOOL CCarteJbusSlave::bReadConfig(LPCTSTR pszFileName,CListStream *pListStream)
{
	BOOL bReturn;
	CElemFieldBit8 *pElemFieldBit8 = NULL;
	CElemBase *pElem = NULL;
	CElemInt16 *pElemInt16 = NULL;
	TCHAR szText[2048];
	TCHAR szSeps[]   = _T("|");
	int iCurrentPos = 0;
	
	if (bReturn = CSerialPort::bReadConfig(pszFileName))
	{
		iCurrentPos = 0;
		// commande ECRITURE 
		// CMD MARCHE VOIE
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|%08x|%08x"),MAKE_ID(0,0xFF,eTYPE_INT8,eID_STREAM_ACTIVE),MAKE_ID(1,0xFF,eTYPE_INT8,eID_STREAM_ACTIVE),MAKE_ID(2,0xFF,eTYPE_INT8,eID_STREAM_ACTIVE),
					MAKE_ID(3,0xFF,eTYPE_INT8,eID_STREAM_ACTIVE),MAKE_ID(4,0xFF,eTYPE_INT8,eID_STREAM_ACTIVE),MAKE_ID(5,0xFF,eTYPE_INT8,eID_STREAM_ACTIVE),0,0);
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanWrite.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		// CMD RUN
		_stprintf(szText, _T("0x%08x"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_RUN));
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanWrite.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanWrite.pAdd(new CElemFieldBit8());


		iCurrentPos = 0;
		// commande LECTURE 
		// ETAT MARCHE VOIE : 0x8610
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|%08x|%08x"),MAKE_ID(0,0xFF,eTYPE_INT8,eID_STREAM_ACTIVE),MAKE_ID(1,0xFF,eTYPE_INT8,eID_STREAM_ACTIVE),MAKE_ID(2,0xFF,eTYPE_INT8,eID_STREAM_ACTIVE),
					MAKE_ID(3,0xFF,eTYPE_INT8,eID_STREAM_ACTIVE),MAKE_ID(4,0xFF,eTYPE_INT8,eID_STREAM_ACTIVE),MAKE_ID(5,0xFF,eTYPE_INT8,eID_STREAM_ACTIVE),0,0);
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		// analyse en cours de la VOIE : 0x8611
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|%08x|%08x"),MAKE_ID(0,0xFF,eTYPE_INT8,eID_STREAM_IS_RUNNING),MAKE_ID(1,0xFF,eTYPE_INT8,eID_STREAM_IS_RUNNING),MAKE_ID(2,0xFF,eTYPE_INT8,eID_STREAM_IS_RUNNING),
					MAKE_ID(3,0xFF,eTYPE_INT8,eID_STREAM_IS_RUNNING),MAKE_ID(4,0xFF,eTYPE_INT8,eID_STREAM_IS_RUNNING),MAKE_ID(5,0xFF,eTYPE_INT8,eID_STREAM_IS_RUNNING),0,0);
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		// analyse arrêt / attente / sav : 0x8612
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_RUN),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_PAUSE),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATE_MAINTENANCE));
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		// analyseur nettoyage zero calibrage : 0x8613
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATE_CLEANUP),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATE_ZERO),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATE_CALIB));
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		// ADU : 0x8614
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8615
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8616
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8617
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8618
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8619
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x861A
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x861B
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x861C
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x861D
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x861E
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x861F
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// Voie 1 Mesure x status Seuil 1 et 2 : 0x8620
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x"),
							MAKE_ID(0,0,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(0,0,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(0,1,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(0,1,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(0,2,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(0,2,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(0,3,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(0,3,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2));
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		// Voie 2 Mesure x status Seuil 1 et 2 : 0x8621
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x"),
							MAKE_ID(1,0,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(1,0,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(1,1,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(1,1,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(1,2,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(1,2,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(1,3,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(1,3,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2));
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		// Voie 3 Mesure x status Seuil 1 et 2 : 0x8622
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x"),
							MAKE_ID(2,0,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(2,0,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(2,1,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(2,1,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(2,2,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(2,2,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(2,3,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(2,3,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2));
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		// Voie 4 Mesure x status Seuil 1 et 2 : 0x8623
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x"),
							MAKE_ID(3,0,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(3,0,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(3,1,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(3,1,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(3,2,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(3,2,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(3,3,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(3,3,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2));
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		// Voie 5 Mesure x status Seuil 1 et 2 : 0x8624
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x"),
							MAKE_ID(4,0,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(4,0,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(4,1,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(4,1,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(4,2,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(4,2,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(4,3,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(4,3,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2));
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		// Voie 6 Mesure x status Seuil 1 et 2 : 0x8625
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x"),
							MAKE_ID(5,0,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(5,0,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(5,1,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(5,1,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(5,2,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(5,2,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),
							MAKE_ID(5,3,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),MAKE_ID(5,3,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2));
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		// ADU : 0x8626
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8627
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8628
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// default mesure 1 et 2 : 0x8629
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x"),
							MAKE_ID(0,0,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),MAKE_ID(0,1,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),
							MAKE_ID(0,2,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),MAKE_ID(0,3,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),
							MAKE_ID(1,0,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),MAKE_ID(1,1,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),
							MAKE_ID(1,2,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),MAKE_ID(1,3,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	));
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		// default mesure 3 et 4 : 0x862A
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x"),
							MAKE_ID(2,0,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),MAKE_ID(2,1,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),
							MAKE_ID(2,2,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),MAKE_ID(2,3,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),
							MAKE_ID(3,0,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),MAKE_ID(3,1,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),
							MAKE_ID(3,2,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),MAKE_ID(3,3,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	));
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		//default mesure 5 et 6  : 0x862B
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x"),
							MAKE_ID(4,0,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),MAKE_ID(4,1,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),
							MAKE_ID(4,2,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),MAKE_ID(4,3,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),
							MAKE_ID(5,0,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),MAKE_ID(5,1,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),
							MAKE_ID(5,2,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	),MAKE_ID(5,3,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	));
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}



		// default mesure 1 et 2 : 0x862C
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x"),
							MAKE_ID(0,0,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),MAKE_ID(0,1,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),
							MAKE_ID(0,2,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),MAKE_ID(0,3,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),
							MAKE_ID(1,0,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),MAKE_ID(1,1,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),
							MAKE_ID(1,2,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),MAKE_ID(1,3,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	));
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		// default mesure 3 et 4 : 0x862D
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x"),
							MAKE_ID(2,0,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),MAKE_ID(2,1,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),
							MAKE_ID(2,2,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),MAKE_ID(2,3,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),
							MAKE_ID(3,0,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),MAKE_ID(3,1,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),
							MAKE_ID(3,2,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),MAKE_ID(3,3,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	));
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		//default mesure 5 et 6  : 0x862E
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x"),
							MAKE_ID(4,0,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),MAKE_ID(4,1,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),
							MAKE_ID(4,2,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),MAKE_ID(4,3,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),
							MAKE_ID(5,0,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),MAKE_ID(5,1,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),
							MAKE_ID(5,2,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	),MAKE_ID(5,3,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF	));
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}

		// ADU : 0x862F
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// defaut d'analyseur : 0x8630
		_stprintf(szText, _T("0x%08x"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATUS_FAILURE));
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		// defaut de voie : 0x8631
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|%08x|%08x"),
							MAKE_ID(0,0xFF,eTYPE_INT8,eID_STREAM_STATUS_FAILURE),MAKE_ID(1,0xFF,eTYPE_INT8,eID_STREAM_STATUS_FAILURE),
							MAKE_ID(2,0xFF,eTYPE_INT8,eID_STREAM_STATUS_FAILURE),MAKE_ID(3,0xFF,eTYPE_INT8,eID_STREAM_STATUS_FAILURE),
							MAKE_ID(4,0xFF,eTYPE_INT8,eID_STREAM_STATUS_FAILURE),MAKE_ID(5,0xFF,eTYPE_INT8,eID_STREAM_STATUS_FAILURE),
							0,0);
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		// defaut d'eau de voie : 0x8632
		_stprintf(szText, _T("0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|0x%08x|%08x|%08x"),
							MAKE_ID(0,0xFF,eTYPE_INT8,eID_STREAM_STATUS_WATER_FAILURE),MAKE_ID(1,0xFF,eTYPE_INT8,eID_STREAM_STATUS_WATER_FAILURE),
							MAKE_ID(2,0xFF,eTYPE_INT8,eID_STREAM_STATUS_WATER_FAILURE),MAKE_ID(3,0xFF,eTYPE_INT8,eID_STREAM_STATUS_WATER_FAILURE),
							MAKE_ID(4,0xFF,eTYPE_INT8,eID_STREAM_STATUS_WATER_FAILURE),MAKE_ID(5,0xFF,eTYPE_INT8,eID_STREAM_STATUS_WATER_FAILURE),
							0,0);
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		if (bReturn = (pElemFieldBit8 != NULL))
		{
			iCurrentPos = 0;
			bReturn = pElemFieldBit8->bSetConfig(szText,iCurrentPos,pListStream);
		}
		// ADU : 0x8633
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8634
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8635
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8636
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8637
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// Défaut matériel 1 - 8 : 0x8638
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// Défaut matériel 9 - 16 : 0x8639
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// Défaut matériel 17 - 24 : 0x863A
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// maintenance : 0x863B
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x863C
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x863D
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x863E
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x863F
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// Valeur analogique 1 : 0x8640
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 2 : 0x8642
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 3 : 0x8644
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 4 : 0x8646
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 5 : 0x8648
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 6 : 0x864A
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 7 : 0x864C
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 8 : 0x864E
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 9 : 0x8650
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 10 : 0x8652
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 11 : 0x8654
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 12 : 0x8656
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 13 : 0x8658
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 14 : 0x865A
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 15 : 0x865C
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 16 : 0x865E
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 17 : 0x8660
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 18 : 0x8662
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 19 : 0x8664
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 20 : 0x8666
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 21 : 0x8668
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 22 : 0x866A
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 23 : 0x866C
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// Valeur analogique 24 : 0x866E
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// ADU : 0x8670
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8671
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8672
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8673
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8674
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8675
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8676
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8677
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8678
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8679
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x867A
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x867B
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x867C
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x867D
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x867E
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x867F
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// compteur cycle voie 1 : 0x8680
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(0,0xFF,eTYPE_INT16,eID_STREAM_COUNTER_CYCLE)));
		// compteur cycle voie 2 : 0x8682
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(1,0xFF,eTYPE_INT16,eID_STREAM_COUNTER_CYCLE)));
		// compteur cycle voie 3 : 0x8684
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(2,0xFF,eTYPE_INT16,eID_STREAM_COUNTER_CYCLE)));
		// compteur cycle voie 4 : 0x8686
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(3,0xFF,eTYPE_INT16,eID_STREAM_COUNTER_CYCLE)));
		// compteur cycle voie 5 : 0x8688
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(4,0xFF,eTYPE_INT16,eID_STREAM_COUNTER_CYCLE)));
		// compteur cycle voie 6 : 0x868A
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(5,0xFF,eTYPE_INT16,eID_STREAM_COUNTER_CYCLE)));
		// ADU : 0x868C
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x868D
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x868E
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x868F
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8690
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8691
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8692
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8693
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8694
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8695
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8696
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8697
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8698
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x8699
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x869A
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x869B
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x869C
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x869D
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x869E
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// ADU : 0x869F
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListDataCanRead.pAdd(new CElemFieldBit8());
		// voie 1 mesure 1 : 0x86A0
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(0, 0,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 1 mesure 2 : 0x86A2
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(0, 1,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 1 mesure 3 : 0x86A4
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(0, 2,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 1 mesure 4 : 0x86A6
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(0, 3,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 2 mesure 1 : 0x86A8
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(1, 0,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 2 mesure 2 : 0x86AC
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(1, 1,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 2 mesure 3 : 0x86AE
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(1, 2,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 2 mesure 4 : 0x86B0
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(1, 3,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 3 mesure 1 : 0x86B2
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(2, 0,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 3 mesure 2 : 0x86B4
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(2, 1,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 3 mesure 3 : 0x86B4
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(2, 2,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 3 mesure 4 : 0x86B6
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(2, 3,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 4 mesure 1 : 0x86B8
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(3, 0,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 4 mesure 2 : 0x86BA
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(3, 1,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 4 mesure 3 : 0x86BC
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(3, 2,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 4 mesure 4 : 0x86BE
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(3, 3,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 5 mesure 1 : 0x86C0
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(4, 0,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 5 mesure 2 : 0x86C2
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(4, 1,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 5 mesure 3 : 0x86C4
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(4, 2,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 5 mesure 4 : 0x86C6
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(4, 3,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 6 mesure 1 : 0x86C8
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(5, 0,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 6 mesure 2 : 0x86CA
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(5, 1,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 6 mesure 3 : 0x86CC
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(5, 2,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// voie 6 mesure 4 : 0x86CE
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(pListStream->pFindOrCreateElemFromID(MAKE_ID(5, 3,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE)));
		// ADU : 0x86D0
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// ADU : 0x86D2
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// ADU : 0x86D4
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// ADU : 0x86D6
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
		// ADU : 0x86D8
		pElemInt16 = (CElemInt16 *)m_ListDataCanRead.pAdd(new CElemInt16());
	}

	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("BOOL CCarteJBusSlave::bReadConfig"));
		TRACE_DEBUG_IHM(eError,eConfig,eErrorCarteJBusSlaveReadConfig);
	}

	return bReturn;
}


/******************************************************************************
 * @func :	bWriteConfig
 * 
 * Rôle  :	enregistre la configuration dans un fichier
 * @parm :	LPCSTR | szIni | fichier de configuration
 *****************************************************************************/
BOOL CCarteJbusSlave::bWriteConfig(LPCTSTR pszFileName)
{
	BOOL bReturn;

	if (bReturn = CSerialPort::bWriteConfig(pszFileName))
	{
	}

	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("BOOL CCarteJBusSlave::bWriteConfig"));
		TRACE_DEBUG_IHM(eError,eConfig,eErrorCarteJBusSlavebWriteConfig);
	}



	return bReturn;
}

BOOL CCarteJbusSlave::bRead(BYTE* lpData,long lSizeDataMax,long *plNbrLu,BOOL bByPass)
{
	BOOL bReturn;
	long lLengthRead;
	BYTE bNumEsclave=0;
	BYTE bNumFct=0;
	WORD wAddress=0;
	WORD wNbr=0;
	BYTE bNbrOctet=0;
	WORD wCRC=0;
	//TCHAR szTrace[MAX_PATH];

	*plNbrLu = 0;

	if (bReturn = CSerialPort::bRead(lpData,1,&lLengthRead,bByPass))
	{
		
		// num esclave
		bNumEsclave = *lpData;
		lpData += lLengthRead; 
		(*plNbrLu) += lLengthRead;
		/*_stprintf(szTrace,_T("#T1 CCarteJbusSlave::bRead : bNumEsclave: %d , bNumFct : %d, wAddress : %d , wNbr : %d, wCRC : %d \n")
								, bNumEsclave
								, bNumFct
								, wAddress
								, wNbr
								, wCRC);
		TRACE_DEBUG(eError,eComJBusSlave,_T(__FILE__),_T(__FUNCTION__),__LINE__,szTrace);*/
		if (bNumEsclave == m_bNumInterface && (bReturn = CSerialPort::bRead(lpData,1,&lLengthRead,bByPass)))
		{
			
			bNumFct = *lpData;
			lpData += lLengthRead; 
			(*plNbrLu) += lLengthRead;
			/*_stprintf(szTrace,_T("#T2 CCarteJbusSlave::bRead : bNumEsclave: %d , bNumFct : %d, wAddress : %d , wNbr : %d, wCRC : %d \n")
								, bNumEsclave
								, bNumFct
								, wAddress
								, wNbr
								, wCRC);
		TRACE_DEBUG(eError,eComJBusSlave,_T(__FILE__),_T(__FUNCTION__),__LINE__,szTrace);*/
			switch (bNumFct)
			{
			case 1:
			case 2:
			case 3:
			case 4:
			case 5:
			case 6:
				// adresse 
				if (bReturn = CSerialPort::bRead(lpData,2,&lLengthRead,bByPass))
				{
					
					wAddress = *((WORD*)lpData);
					lpData += lLengthRead; 
					(*plNbrLu) += lLengthRead;
					// nbr 
					/*_stprintf(szTrace,_T("#T3 CCarteJbusSlave::bRead : bNumEsclave: %d , bNumFct : %d, wAddress : %d , wNbr : %d, wCRC : %d \n")
								, bNumEsclave
								, bNumFct
								, wAddress
								, wNbr
								, wCRC);
		TRACE_DEBUG(eError,eComJBusSlave,_T(__FILE__),_T(__FUNCTION__),__LINE__,szTrace);*/
					if (bReturn = CSerialPort::bRead(lpData,2,&lLengthRead,bByPass))
					{
						
						wNbr = *((WORD*)lpData);
						lpData += lLengthRead; 
						(*plNbrLu) += lLengthRead;
						// CRC16
						/*_stprintf(szTrace,_T("#T4 CCarteJbusSlave::bRead : bNumEsclave: %d , bNumFct : %d, wAddress : %d , wNbr : %d, wCRC : %d \n")
								, bNumEsclave
								, bNumFct
								, wAddress
								, wNbr
								, wCRC);
		TRACE_DEBUG(eError,eComJBusSlave,_T(__FILE__),_T(__FUNCTION__),__LINE__,szTrace);*/
						if (bReturn = CSerialPort::bRead(lpData,2,&lLengthRead,bByPass))
						{
							
							wCRC = *((WORD*)lpData);
							lpData += lLengthRead; 
							(*plNbrLu) += lLengthRead;
						/*_stprintf(szTrace,_T("#T5 CCarteJbusSlave::bRead : bNumEsclave: %d , bNumFct : %d, wAddress : %d , wNbr : %d, wCRC : %d \n")
								, bNumEsclave
								, bNumFct
								, wAddress
								, wNbr
								, wCRC);
		TRACE_DEBUG(eError,eComJBusSlave,_T(__FILE__),_T(__FUNCTION__),__LINE__,szTrace);*/
						}
					}
				}
				break;

			case 15:
			case 16:
				// adresse 
				if (bReturn = CSerialPort::bRead(lpData,2,&lLengthRead,bByPass))
				{
					wAddress = *((WORD*)lpData);
					lpData += lLengthRead; 
					(*plNbrLu) += lLengthRead;
					// nbr 
					if (bReturn = CSerialPort::bRead(lpData,2,&lLengthRead,bByPass))
					{
						wNbr = *((WORD*)lpData);
						wNbr = MAKEWORD(HIBYTE(wNbr),LOBYTE(wNbr));

						lpData += lLengthRead; 
						(*plNbrLu) += lLengthRead;
						// nbr d'octet
						if (bReturn = CSerialPort::bRead(lpData,1,&lLengthRead,bByPass))
						{
							bNbrOctet = *lpData;
							lpData += lLengthRead; 
							(*plNbrLu) += lLengthRead;
							// les octets
							if (bReturn = CSerialPort::bRead(lpData,bNbrOctet,&lLengthRead,bByPass))
							{
								bNbrOctet = *lpData;
								lpData += lLengthRead; 
								(*plNbrLu) += lLengthRead;
								// CRC16
								if (bReturn = CSerialPort::bRead(lpData,2,&lLengthRead,bByPass))
								{
									//wCRC = *((WORD*)lpData);
									lpData += lLengthRead; 
									(*plNbrLu) += lLengthRead;
								}
							}
						}
					}
				}
				break;

			default:
				break;

			}
		}
		if (!bReturn)
		{
			// purge  reads/writes 
			PurgeComm( m_hTTY, PURGE_TXABORT | PURGE_RXABORT);
			m_lNbrErrCom++;
			m_bError = TRUE;
			//TRACE_DEBUG(eError,eComJBusSlave,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("BOOL CCarteJbusSlave::bRead"));
			TRACE_DEBUG(eDebug,eComJBusSlave,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("BOOL CCarteJbusSlave::bRead"));
			TRACE_DEBUG_IHM(eError,eComJBusSlave,eErrorCarteJBusSlaveRead);
		}
		else m_bError = FALSE;
	}
	return (bReturn); 
}

long CCarteJbusSlave::lDispatchTrame(BYTE* lpData,long lSizeTotal)
{
#define MAX_TEXT				512
	BOOL bReturn = FALSE;
	BYTE szResponse[MAX_TEXT];
	long iSizeOut = 0;
	BYTE bNumFct;
	BYTE bFirstBit;
	short nAddress;
	short nNbrBits;
	short nNbr;
	BYTE* lpDataOut = lpData;
	long lSizeOut = 0;
	int i;
	WORD wCRC;
	CContext Context(TRUE,NULL,szResponse,MAX_TEXT,TRUE,FALSE);

	if (lSizeTotal >= 8) // taille mini d'une trame RQ JBUS 
	{
		// calcul du CRC
		if (wCalculCRC16(lpData,lSizeTotal - 2) == MAKEWORD(*(lpData + lSizeTotal - 1),*(lpData + lSizeTotal - 2)))
		{
			if (*lpData == m_bNumInterface) // c'est pour moi
			{
				lpData++;lSizeTotal--;
				bNumFct = *lpData;
				lpData++;lSizeTotal--;
				switch (bNumFct)
				{
				case 1:
				case 2:
					if (m_bCanRead)
					{
						Context.Reset(TRUE,NULL,szResponse,MAX_TEXT,TRUE,FALSE);
						// calcul addr + pos du 1° bit
						nAddress = *((short*)lpData);
						nAddress = MAKEWORD(HIBYTE(nAddress),LOBYTE(nAddress));

						bFirstBit = nAddress & 0x000F;
						nAddress = (nAddress >> 4) | (BASE_ADDR_READ & 0xF000);
						nAddress -= (short)BASE_ADDR_READ;
						if (nAddress >= 0)
						{
							// nbr de bit
							nNbrBits =  *((WORD*)(lpData+2)); 
							nNbrBits = MAKEWORD(HIBYTE(nNbrBits),LOBYTE(nNbrBits));
							// calcul nbr octets lus
							nNbr = (nNbrBits % 8) ? (nNbrBits / 8 + 1) : (nNbrBits / 8);
							// copie du nbr
							*lpData = (BYTE)nNbr;
							lpData++;
							lSizeTotal--;
							// recup buffer data
							if (m_ListDataCanRead.bSerialize(Context))
							{
								if ((nAddress + nNbr) <= Context.iGetCurrentSize())
								{
									// copy des datas à partir de l'address
									Context.m_pBuffStart += nAddress;
									*lpData = 0;
									for (i = 0; (i < nNbr) && (nNbrBits > 0); i++)
									{
										//if (wNbrBits > 8)
										*lpData |= (*(Context.m_pBuffStart)) >> bFirstBit;
										nNbrBits -= (8 - bFirstBit);
										Context.m_pBuffStart++;
										if ((bFirstBit > 0) && (nNbrBits > 0))
										{
											*lpData |= (*(Context.m_pBuffStart)) << (8 - bFirstBit);
											nNbrBits -= bFirstBit;
										}
										if (nNbrBits < 0)
										{
											// mise à 0 des bits en trop
											*lpData &= (0xFF >> (-nNbrBits));
										}
										lpData++;
									}

									wCRC = wCalculCRC16(lpDataOut,3 + nNbr);
									*lpData = HIBYTE(wCRC);
									lpData++;
									*lpData = LOBYTE(wCRC);
//									memcpy(lpData,&wCRC,2);
									bReturn = bWrite (lpDataOut,3 + nNbr + 2);
								}
							}
						}
					}
					else bReturn = TRUE;
					break;

				case 3:
				case 4:
					if (m_bCanRead)
					{
						Context.Reset(TRUE,NULL,szResponse,MAX_TEXT,TRUE,FALSE);
						nAddress = *((short*)lpData);
						nAddress = MAKEWORD(HIBYTE(nAddress),LOBYTE(nAddress)) - BASE_ADDR_READ;
						if (nAddress >= 0)
						{
							nNbr =  *((WORD*)(lpData+2));
							nNbr = MAKEWORD(HIBYTE(nNbr),LOBYTE(nNbr)) * sizeof(WORD);
							// copie du nbr
							*lpData = (BYTE)nNbr;
							lpData++;
							lSizeTotal--;
							// recup buffer data
							if (m_ListDataCanRead.bSerialize(Context))
							{
								if ((nAddress  + nNbr) <= Context.iGetCurrentSize())
								{
									// copy des datas à partir de l'address
									memcpy(lpData,Context.m_pBuffStart + nAddress,nNbr);
									lpData += nNbr;
									// copie du CRC
									wCRC = wCalculCRC16(lpDataOut,3 + nNbr);
									*lpData = HIBYTE(wCRC);
									lpData++;
									*lpData = LOBYTE(wCRC);
									bReturn = bWrite (lpDataOut,3 + nNbr + 2);
								}
							}
						}
					}
					else bReturn = TRUE;

					break;

				// ecriture d'un bit
				case 5:
					{
						Context.Reset(TRUE,NULL,szResponse,MAX_TEXT,TRUE,FALSE);
						// calcul addr + pos du 1° bit
						nAddress = *((short*)lpData);
						nAddress = MAKEWORD(HIBYTE(nAddress),LOBYTE(nAddress));

						bFirstBit = nAddress & 0x000F;
						nAddress = (nAddress >> 4) | (BASE_ADDR_READ & 0xF000);
						nAddress -= (short)BASE_ADDR_WRITE;
						if (nAddress >= 0)
						{
							lpData += 2;lSizeTotal -= 2;
							nNbr = *lpData;
							// recup buffer data
							if (m_ListDataCanWrite.bSerialize(Context))
							{
								// si on est dans la plage
								if (nAddress <= Context.iGetCurrentSize())
								{
									// copy des datas à partir de l'address
									if (nNbr == 0) szResponse[nAddress] &= ~(0x01 << bFirstBit);
									else szResponse[nAddress] |= (0x01 << bFirstBit);
									Context.Reset(FALSE,NULL,szResponse,MAX_TEXT,TRUE,FALSE);
									// mise à jour des données
									if (m_bCanWrite) bReturn = m_ListDataCanWrite.bSerialize(Context);
									if (bReturn || !m_bCanWrite) bReturn = bWrite (lpDataOut,8);
								}
							}
						}
					}

					break;

				// ecriture d'un mot
				case 6:
					{
						nAddress = *((short*)lpData);
						nAddress = MAKEWORD(HIBYTE(nAddress),LOBYTE(nAddress));
						nAddress -= (short)BASE_ADDR_WRITE;
						if (nAddress >= 0)
						{
							lpData += 2;lSizeTotal -= 2;
							nNbr = *((short*)lpData); // c'est la donnée
							// recup buffer data
							if (m_ListDataCanWrite.bSerialize(Context))
							{
								if (nAddress <= Context.iGetCurrentSize())
								{
									// copy des datas à partir de l'address
									memcpy(&szResponse[nAddress], &nNbr, 2);
									Context.Reset(FALSE,NULL,szResponse,MAX_TEXT,TRUE,FALSE);
									if (m_bCanWrite) bReturn = m_ListDataCanWrite.bSerialize(Context);
									if (bReturn || !m_bCanWrite) bReturn = bWrite (lpDataOut,8);
								}
							}
						}
					}

					break;
				// ecriture de n bits
				case 15:
					{
						Context.Reset(TRUE,NULL,szResponse,MAX_TEXT,TRUE,FALSE);
						// calcul addr + pos du 1° bit
						nAddress = *((short*)lpData);
						nAddress = MAKEWORD(HIBYTE(nAddress),LOBYTE(nAddress));

						bFirstBit = nAddress & 0x000F;
						nAddress = (nAddress >> 4) | (BASE_ADDR_READ & 0xF000);
						nAddress -= (short)BASE_ADDR_WRITE;
						if (nAddress >= 0)
						{
							lpData += 2;lSizeTotal -= 2;
							nNbrBits =  *((WORD*)lpData);
							nNbrBits = MAKEWORD(HIBYTE(nNbrBits),LOBYTE(nNbrBits));
							if (nNbrBits > 0)
							{
								lpData += 2;lSizeTotal -= 2;
								BYTE bNbrOctet = *lpData;
								// recup buffer data
								if (m_ListDataCanWrite.bSerialize(Context))
								{
									if (nAddress <= Context.iGetCurrentSize())
									{
										// copy des datas à partir de l'address
										// cas du premier octet
										BYTE *pStart = lpData + 1;
										stBitField8 BitField8In;
										stBitField8 BitField8Out;
										Context.m_pBuffStart += nAddress;
										BitField8Out.value = *(Context.m_pBuffStart);

										for (i = 0; (i < bNbrOctet) && (nNbrBits > 0); i++)
										{
											BitField8In.value = *pStart;
											// mise à zero de bits a modifer
											if (bFirstBit == 0) 
											{
												if (nNbrBits-->0) BitField8Out.bitfield.bBit0 = BitField8In.bitfield.bBit0;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit1 = BitField8In.bitfield.bBit1;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit2 = BitField8In.bitfield.bBit2;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit3 = BitField8In.bitfield.bBit3;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit4 = BitField8In.bitfield.bBit4;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit5 = BitField8In.bitfield.bBit5;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit6 = BitField8In.bitfield.bBit6;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit7 = BitField8In.bitfield.bBit7;
												// mise a jour
												*(Context.m_pBuffStart) = BitField8Out.value;
												// le suivant
												Context.m_pBuffStart++;
												BitField8Out.value = *(Context.m_pBuffStart);
											}
											if (bFirstBit == 1) 
											{
												if (nNbrBits-->0) BitField8Out.bitfield.bBit1 = BitField8In.bitfield.bBit0;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit2 = BitField8In.bitfield.bBit1;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit3 = BitField8In.bitfield.bBit2;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit4 = BitField8In.bitfield.bBit3;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit5 = BitField8In.bitfield.bBit4;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit6 = BitField8In.bitfield.bBit5;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit7 = BitField8In.bitfield.bBit6;
												// mise a jour
												*(Context.m_pBuffStart) = BitField8Out.value;
												// le suivant
												Context.m_pBuffStart++;
												BitField8Out.value = *(Context.m_pBuffStart);
												// la suite des bits
												if (nNbrBits-->0) BitField8Out.bitfield.bBit0 = BitField8In.bitfield.bBit7;
											}
											if (bFirstBit == 2) 
											{
												if (nNbrBits-->0) BitField8Out.bitfield.bBit2 = BitField8In.bitfield.bBit0;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit3 = BitField8In.bitfield.bBit1;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit4 = BitField8In.bitfield.bBit2;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit5 = BitField8In.bitfield.bBit3;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit6 = BitField8In.bitfield.bBit4;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit7 = BitField8In.bitfield.bBit5;
												// mise a jour
												*(Context.m_pBuffStart) = BitField8Out.value;
												// le suivant
												Context.m_pBuffStart++;
												BitField8Out.value = *(Context.m_pBuffStart);
												// la suite des bits
												if (nNbrBits-->0) BitField8Out.bitfield.bBit0 = BitField8In.bitfield.bBit6;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit1 = BitField8In.bitfield.bBit7;
											}
											if (bFirstBit == 3) 
											{
												if (nNbrBits-->0) BitField8Out.bitfield.bBit3 = BitField8In.bitfield.bBit0;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit4 = BitField8In.bitfield.bBit1;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit5 = BitField8In.bitfield.bBit2;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit6 = BitField8In.bitfield.bBit3;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit7 = BitField8In.bitfield.bBit4;
												// mise a jour
												*(Context.m_pBuffStart) = BitField8Out.value;
												// le suivant
												Context.m_pBuffStart++;
												BitField8Out.value = *(Context.m_pBuffStart);
												// la suite des bits
												if (nNbrBits-->0) BitField8Out.bitfield.bBit0 = BitField8In.bitfield.bBit5;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit1 = BitField8In.bitfield.bBit6;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit2 = BitField8In.bitfield.bBit7;
											}
											if (bFirstBit == 4) 
											{
												if (nNbrBits-->0) BitField8Out.bitfield.bBit4 = BitField8In.bitfield.bBit0;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit5 = BitField8In.bitfield.bBit1;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit6 = BitField8In.bitfield.bBit2;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit7 = BitField8In.bitfield.bBit3;
												// mise a jour
												*(Context.m_pBuffStart) = BitField8Out.value;
												// le suivant
												Context.m_pBuffStart++;
												BitField8Out.value = *(Context.m_pBuffStart);
												// la suite des bits
												if (nNbrBits-->0) BitField8Out.bitfield.bBit0 = BitField8In.bitfield.bBit4;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit1 = BitField8In.bitfield.bBit5;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit2 = BitField8In.bitfield.bBit6;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit3 = BitField8In.bitfield.bBit7;
											}
											if (bFirstBit == 5) 
											{
												if (nNbrBits-->0) BitField8Out.bitfield.bBit5 = BitField8In.bitfield.bBit0;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit6 = BitField8In.bitfield.bBit1;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit7 = BitField8In.bitfield.bBit2;
												// mise a jour
												*(Context.m_pBuffStart) = BitField8Out.value;
												// le suivant
												Context.m_pBuffStart++;
												BitField8Out.value = *(Context.m_pBuffStart);
												// la suite des bits
												if (nNbrBits-->0) BitField8Out.bitfield.bBit0 = BitField8In.bitfield.bBit3;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit1 = BitField8In.bitfield.bBit4;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit2 = BitField8In.bitfield.bBit5;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit3 = BitField8In.bitfield.bBit6;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit4 = BitField8In.bitfield.bBit7;
											}
											if (bFirstBit == 6) 
											{
												if (nNbrBits-->0) BitField8Out.bitfield.bBit6 = BitField8In.bitfield.bBit0;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit7 = BitField8In.bitfield.bBit1;
												// mise a jour
												*(Context.m_pBuffStart) = BitField8Out.value;
												// le suivant
												Context.m_pBuffStart++;
												BitField8Out.value = *(Context.m_pBuffStart);
												// la suite des bits
												if (nNbrBits-->0) BitField8Out.bitfield.bBit0 = BitField8In.bitfield.bBit2;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit1 = BitField8In.bitfield.bBit3;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit2 = BitField8In.bitfield.bBit4;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit3 = BitField8In.bitfield.bBit5;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit4 = BitField8In.bitfield.bBit6;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit5 = BitField8In.bitfield.bBit7;
											}
											if (bFirstBit == 7) 
											{
												if (nNbrBits-->0) BitField8Out.bitfield.bBit7 = BitField8In.bitfield.bBit0;
												// mise a jour
												*(Context.m_pBuffStart) = BitField8Out.value;
												// le suivant
												Context.m_pBuffStart++;
												BitField8Out.value = *(Context.m_pBuffStart);
												// la suite des bits
												if (nNbrBits-->0) BitField8Out.bitfield.bBit0 = BitField8In.bitfield.bBit1;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit1 = BitField8In.bitfield.bBit2;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit2 = BitField8In.bitfield.bBit3;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit3 = BitField8In.bitfield.bBit4;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit4 = BitField8In.bitfield.bBit5;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit5 = BitField8In.bitfield.bBit6;
												if (nNbrBits-->0) BitField8Out.bitfield.bBit6 = BitField8In.bitfield.bBit7;
											}


											pStart++;
										}
										// mise a jour
										*(Context.m_pBuffStart) = BitField8Out.value;
																		
										Context.Reset(FALSE,NULL,szResponse,MAX_TEXT,TRUE,FALSE);
										if (m_bCanWrite) bReturn = m_ListDataCanWrite.bSerialize(Context);
										if (bReturn || !m_bCanWrite)
										{
											wCRC = wCalculCRC16(lpDataOut,6);
											*lpData = HIBYTE(wCRC);
											lpData++;
											*lpData = LOBYTE(wCRC);
//											memcpy(lpData,&wCRC,2);
											bReturn = bWrite (lpDataOut,8);
										}
									}
								}
							}
						}
					}

					break;

				case 16:
					{
						nAddress = *((short*)lpData);
						nAddress = MAKEWORD(HIBYTE(nAddress),LOBYTE(nAddress));
						nAddress -= (short)BASE_ADDR_WRITE;
						if (nAddress >= 0)
						{
							lpData += 2;lSizeTotal -= 2;
							nNbr =  *((WORD*)lpData);
							nNbr = MAKEWORD(HIBYTE(nNbr),LOBYTE(nNbr));
							if (nNbr > 0)
							{
								lpData += 2;lSizeTotal -= 2;
								BYTE bNbrOctet = *lpData;
								if (bNbrOctet = 2*nNbr)
								{
									// recup buffer data
									if (m_ListDataCanWrite.bSerialize(Context))
									{
										if (nAddress <= Context.iGetCurrentSize())
										{
											// copy des datas à partir de l'address
											memcpy(szResponse + nAddress,lpData + 1,bNbrOctet);
											Context.Reset(FALSE,NULL,szResponse,MAX_TEXT,TRUE,FALSE);
											if (m_bCanWrite) bReturn = m_ListDataCanWrite.bSerialize(Context);
											if (bReturn || !m_bCanWrite)
											{
												wCRC = wCalculCRC16(lpDataOut,6);
												*lpData = HIBYTE(wCRC);
												lpData++;
												*lpData = LOBYTE(wCRC);
												bReturn = bWrite (lpDataOut,8);
											}
										}
									}
								}
							}
						}
					}

					break;

				default:
					break;

				}
				if (!bReturn)
				{
					// purge  reads/writes 
					m_lNbrErrCom++;
					m_bError = TRUE;
					PurgeComm( m_hTTY, PURGE_TXABORT | PURGE_RXABORT);
					TRACE_DEBUG(eDebug,eComJBusSlave,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("long CCarteJbusSlave::lDispatchTrame"));
					TRACE_DEBUG_IHM(eError,eComJBusSlave,eErrorCarteJBusSlaveDispatchTrame);
				}
				else m_bError = FALSE;
			}
		}
	}

	return 0;//bReturn; // 0 pour continuer reinitialiser le buffer de lecture
}

