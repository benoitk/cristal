#include "stdafx.h"
#include "network.h"



//========================================================================
//=== Fonction	: CalculeCrc16Msg
//=== Paramètres passés	: Chaine d octet dont on veut le CRC16
//===                     Longueur de la chaine
//=== En retour	: CRC16
//=== Action: Calcule le CRC16 suivant le polynome defini par POLYNOME
//========================================================================
#define POLYNOME    0xA001 // <=> polynome generateur 1+x2+x15+x16
WORD wCalculCRC16(BYTE* pucBuffer, long lSize)
{
#define POLYNOME    0xA001 // <=> polynome generateur 1+x2+x15+x16
	USHORT  us16CRC     = 0xFFFF;
	//USHORT  us16CRCmem     = 0xFFFF;
	int   i    = 0;
	BOOL boolLsb       = 0;
	BYTE a;
	BYTE b;

	us16CRC     = 0xFFFF;
	while (lSize-- > 0)
	{
		us16CRC ^= (*pucBuffer);

		// pour les 8 1ers bits du CRC:
		for(i=0;i<8;i++)
		{
			boolLsb = us16CRC & 0x0001;
			us16CRC>>=1;
			if(boolLsb == 0x0001)
			{
				us16CRC ^= POLYNOME;
			}
		}
		pucBuffer++;
	}

	a = HIBYTE(us16CRC);
	b = LOBYTE(us16CRC);

	us16CRC = MAKEWORD(a,b);
	return us16CRC;//;us16CRCmem
}


/*(@!*****************************************************************************************
* Nom     : CElemTrameJbus
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemTrameJbus::CElemTrameJbus(): CElemBase(),m_ListParams(NBR_PARAM_MAX)
{
	m_iType = MAKE_ID(0xFF,0xFF,eTYPE_JBUS_TRAME,0xFF);
	SetLabel(_T("CElemTrameJbus"));
}

CElemTrameJbus::~CElemTrameJbus()
{
	m_ListParams.RemoveAll();
}

BOOL CElemTrameJbus::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;

	bReturn = CElemBase::bSerialize(Context);
	if (bReturn) bReturn = m_NumDest.bSerialize(Context);
	if (bReturn) bReturn = m_CodeFct.bSerialize(Context);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}
int CElemTrameJbus::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	iSize = CElemBase::iGetStreamSize(Context);
	iSize += m_NumDest.iGetStreamSize(Context);
	iSize += m_CodeFct.iGetStreamSize(Context);
	return iSize;
}

BOOL CElemTrameJbus::bUpdateData(BYTE *pBuffer,int iSize,BOOL bModeInteger)
{
	BOOL bReturn = TRUE;
	CContext Context(FALSE,NULL,NULL,0,bModeInteger,FALSE);

	bReturn = /*(iSize == iGetStreamSize(Context)) && */(pBuffer[0] == m_NumDest.ucGetVal()) && (pBuffer[1] == m_CodeFct.ucGetVal());

	if (bReturn)
	{
		Context.Reset(FALSE,NULL,pBuffer,iSize,bModeInteger,FALSE);
		bReturn = bSerialize(Context);
	}
	else 
	{
		TRACE_DEBUG(eError,eComJBus,_T(__FILE__),_T(__FUNCTION__),__LINE__,
		_T("Error: frame JBUS configuration: %s (iSize(%d) == iGetStreamSize(Context)(%d)) && (pBuffer[0](%d) == m_NumDest.ucGetVal()(%d)) && (pBuffer[1](%d) == m_CodeFct.ucGetVal()(%d))"),
		szGetLabel(),iSize,iGetStreamSize(Context),pBuffer[0],m_NumDest.ucGetVal(),pBuffer[1],m_CodeFct.ucGetVal());
	}

	return bReturn;
}
BOOL CElemTrameJbus::bSetConfig(LPTSTR pszText,int &iCurrentPos,CListStream *pListStream)
{
	BOOL bReturn = FALSE;
	TCHAR szSeps[]   = _T("|");
	TCHAR *pcToken;

	m_ListParams.RemoveAll();
	// num d'esclave (destinataire)
	pcToken = _tcstok( pszText, szSeps ); 
	if (pcToken != NULL)
	{
		iCurrentPos += (lstrlen(pcToken) + 1);
		bReturn = m_NumDest.bSetTextVal(pcToken);
		pcToken = _tcstok( NULL, szSeps ); 
	}
	// code fonction
	if (pcToken != NULL && bReturn)
	{
		iCurrentPos += (lstrlen(pcToken) + 1);
		bReturn = m_CodeFct.bSetTextVal(pcToken);
	}
	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}

LPTSTR CElemTrameJbus::szGetConfig(LPTSTR pszText, int iSizeMax)
{
	TCHAR szSeps[]   = _T("|");
	TCHAR szTemp[CONV_BUFFER_SIZE];

	// num d'esclave (destinataire)
	_stprintf(pszText,_T("%d"),m_NumDest.ucGetVal());
	lstrcat(pszText,szSeps);
	// code fonction
	_stprintf(szTemp,_T("%d"),m_CodeFct.ucGetVal());
	lstrcat(pszText,szTemp);
	lstrcat(pszText,szSeps);

	return pszText;
}




BOOL CElemTrameJbus::bSerializeCRC16(BYTE* pucBuffer, long lSize,CContext &Context)
{
	BOOL bReturn = TRUE;

	if (Context.m_bSave) 
	{
		// calcul du CRC16
		if (bReturn) bReturn = m_CRC16.bSetVal((short)wCalculCRC16(pucBuffer, lSize));
	}
	if (bReturn) bReturn = m_CRC16.bSerialize(Context);
	if (!Context.m_bSave) 
	{
		// calcul du CRC16
		bReturn = (m_CRC16.nGetVal() == (short)wCalculCRC16(pucBuffer, lSize));
	}
	if (!bReturn) 
	{
		TRACE_DEBUG(eError,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error CRC: %s"),szGetLabel());
	}

	return bReturn;
}

BOOL CElemTrameJbus::bAccessAllowed(BOOL bCanRead,BOOL bCanWrite)
{
	return ((m_CodeFct.ucGetVal() < 5) ? bCanRead : bCanWrite);
}


/*(@!*****************************************************************************************
* Nom     : Fonction JBUS 1 et 2
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
/*(@!*****************************************************************************************
* Nom     : CElemTrameJbusReadBitsRQ_1_2
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemTrameJbusReadBitsRQ_1_2::CElemTrameJbusReadBitsRQ_1_2(): CElemTrameJbus()
{
	SetLabel(_T("CElemTrameJbusReadBitsRQ_1_2"));
}

CElemTrameJbusReadBitsRQ_1_2::~CElemTrameJbusReadBitsRQ_1_2()
{
}

BOOL CElemTrameJbusReadBitsRQ_1_2::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;
	int iPos = Context.iGetCurrentSize();
	BYTE* pStart = Context.m_pBuffCurrent;

	bReturn = CElemTrameJbus::bSerialize(Context);
	if (bReturn) bReturn = m_StartAddr.bSerialize(Context);
	if (bReturn) bReturn = m_NbrBits.bSerialize(Context);
	if (bReturn) bReturn = bSerializeCRC16(pStart, Context.iGetCurrentSize() - iPos,Context);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}
int CElemTrameJbusReadBitsRQ_1_2::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	iSize = CElemTrameJbus::iGetStreamSize(Context);
	iSize += m_StartAddr.iGetStreamSize(Context);
	iSize += m_NbrBits.iGetStreamSize(Context);
	iSize += m_CRC16.iGetStreamSize(Context);
	return iSize;
}

BOOL CElemTrameJbusReadBitsRQ_1_2::bSetConfig(LPTSTR pszText,int &iCurrentPos,CListStream *pListStream)
{
	BOOL bReturn = FALSE;
	TCHAR szSeps[]   = _T("|");
	TCHAR *pcToken;
	TCHAR szText[MAX_PATH];

	pszText += iCurrentPos;
	iCurrentPos = 0;

	_stprintf(szText,_T("CElemTrameJbusReadBitsRQ_1_2 : %s"),pszText);
	SetLabel(szText);
	if (bReturn = CElemTrameJbus::bSetConfig(pszText,iCurrentPos,pListStream))
	{
		pszText += iCurrentPos;
		iCurrentPos = 0;
		// adresse 
		pcToken = _tcstok( pszText, szSeps ); 
		if (pcToken != NULL)
		{
			iCurrentPos += (lstrlen(pcToken) + 1);
			bReturn = m_StartAddr.bSetTextVal(pcToken);
			pcToken = _tcstok( NULL, szSeps ); 
		}
		// nbr de bit
		if (pcToken != NULL && bReturn)
		{
			iCurrentPos += (lstrlen(pcToken) + 1);
			bReturn = m_NbrBits.bSetTextVal(pcToken);
			pcToken = _tcstok( NULL, szSeps ); 
		}
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

LPTSTR CElemTrameJbusReadBitsRQ_1_2::szGetConfig(LPTSTR pszText, int iSizeMax)
{
	TCHAR szSeps[]   = _T("|");
	TCHAR szTemp[CONV_BUFFER_SIZE];

	CElemTrameJbus::szGetConfig(pszText, iSizeMax);
	iSizeMax -= lstrlen(pszText);
	// adresse
	_stprintf(szTemp,_T("0x%08x"),m_StartAddr.nGetVal());
	lstrcat(pszText,szTemp);
	lstrcat(pszText,szSeps);
	// nbr bit
	_stprintf(szTemp,_T("%d"),m_NbrBits.nGetVal());
	lstrcat(pszText,szTemp);

	return pszText;
}



/*(@!*****************************************************************************************
* Nom     : CElemTrameJbusReadBitsRP_1_2
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemTrameJbusReadBitsRP_1_2::CElemTrameJbusReadBitsRP_1_2(): CElemTrameJbus()
{
	SetLabel(_T("CElemTrameJbusReadBitsRP_1_2"));
}

CElemTrameJbusReadBitsRP_1_2::~CElemTrameJbusReadBitsRP_1_2()
{
}

BOOL CElemTrameJbusReadBitsRP_1_2::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;
	int iPos = Context.iGetCurrentSize();
	BYTE* pStart = Context.m_pBuffCurrent;


	bReturn = CElemTrameJbus::bSerialize(Context);
	if (bReturn) bReturn = m_NbrBytes.bSerialize(Context);
	// vérification nbr demandé == nbr configuré
	if (bReturn) bReturn = (m_NbrBytes.ucGetVal() == m_ListParams.iGetCount());
	if (bReturn) bReturn = m_ListParams.bSerialize(Context);
	if (bReturn) bReturn = bSerializeCRC16(pStart, Context.iGetCurrentSize() - iPos,Context);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}


int CElemTrameJbusReadBitsRP_1_2::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	iSize = CElemTrameJbus::iGetStreamSize(Context);
	iSize += m_NbrBytes.iGetStreamSize(Context);
	iSize += m_ListParams.iGetStreamSize(Context);
	iSize += m_CRC16.iGetStreamSize(Context);
	return iSize;
}

BOOL CElemTrameJbusReadBitsRP_1_2::bSetConfig(LPTSTR pszText,int &iCurrentPos,CListStream *pListStream)
{
	BOOL bReturn = FALSE;
	TCHAR szSeps[]   = _T("|");
	TCHAR *pcToken;
	int i;
	int j;
	long lID = 0;
	CElemFieldBit8 *pElemFieldBit8 = NULL;
	CElemBase *pElem = NULL;
	TCHAR szText[MAX_PATH];

	pszText += iCurrentPos;
	iCurrentPos = 0;

	_stprintf(szText,_T("CElemTrameJbusReadBitsRP_1_2 : %s"),pszText);
	SetLabel(szText);
	if (bReturn = CElemTrameJbus::bSetConfig(pszText,iCurrentPos,pListStream))
	{
		pszText += iCurrentPos;
		iCurrentPos = 0;
		// nbr de byte
		pcToken = _tcstok(pszText, szSeps ); 
		if (pcToken)
		{
			iCurrentPos += (lstrlen(pcToken) + 1);
			bReturn = m_NbrBytes.bSetTextVal(pcToken);
			// les params
			pcToken = _tcstok( NULL, szSeps ); 
			for (i = 0;bReturn && (pcToken != NULL) && (i < m_NbrBytes.ucGetVal());i++)
			{
				pElemFieldBit8 = (CElemFieldBit8 *)m_ListParams.pAdd(new CElemFieldBit8());
				bReturn = (pElemFieldBit8 != NULL);
				if (bReturn)
				{
					pElemFieldBit8->SetAutoDelete(TRUE);
					for (j = 0; bReturn && (j < 8); j++)
					{
						if ((pcToken != NULL) && bReturn)
						{
							iCurrentPos += (lstrlen(pcToken) + 1);
							lID = 0;
							// valeur de ref à une variable interne
							if ((_tcsstr(pcToken,_T("0x")) != NULL) || (_tcsstr(pcToken,_T("0X")) != NULL))
							{
								_stscanf(pcToken,_T("%x"),&lID);
								if (bReturn = (NUM_TYPE(lID) == eTYPE_INT8))
								{
									pElem = pListStream->pFindElemFromID(lID);
									bReturn = (pElem != NULL);
								}
								else TRACE_DEBUG(eError,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),_T("les références doivent être du type eTYPE_INT8 dans une trame JBUS1_2"));
							}
							else
							{
								pElem = new CElemInt8();
								bReturn = (pElem != NULL);
								if (bReturn)
								{
									pElem->SetAutoDelete(TRUE);
									bReturn = ((CElemInt8*)pElem)->bSetTextVal(pcToken);
								}
							}
							if (bReturn)
							{
								pElemFieldBit8->pAdd(pElem);
							}
							pcToken = _tcstok( NULL, szSeps ); 
						}
					}
				}
			}
		}
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

LPTSTR CElemTrameJbusReadBitsRP_1_2::szGetConfig(LPTSTR pszText, int iSizeMax)
{
	TCHAR szSeps[]   = _T("|");
	TCHAR szTemp[CONV_BUFFER_SIZE];
	int i;
	int j;
	CElemFieldBit8 *pElemFieldBit8 = NULL;
	CElemInt8 *pElem = NULL;

	CElemTrameJbus::szGetConfig(pszText, iSizeMax);
	iSizeMax -= lstrlen(pszText);
	// nbr byte
	_stprintf(szTemp,_T("%d"),m_NbrBytes.ucGetVal());
	lstrcat(pszText,szTemp);
	// adresse bit
	for (i = 0; i < m_ListParams.iGetCount();i++)
	{
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListParams.pGetAt(i);
		for (j = 0; pElemFieldBit8 && (j < 8); j++)
		{
			pElem = (CElemInt8*)pElemFieldBit8->pGetAt(j);
			lstrcat(pszText,szSeps);
			if (pElem)
			{
				if (NUM_ID(pElem->iGetType()) == 0x000000FF)
				{
					_stprintf(szTemp,_T("%d"),pElem->ucGetVal());
				}
				else
				{
					_stprintf(szTemp,_T("0x%08x"),pElem->iGetType());
				}
				lstrcat(pszText,szTemp);
			}
			else
			{
				lstrcat(pszText,_T("0"));
			}
		}
	}
	return pszText;
}



////////////////////////////////////////////////////////////////////////////////////////////////////
/*(@!*****************************************************************************************
* Nom     : Fonction JBUS 3 et 4
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
/*(@!*****************************************************************************************
* Nom     : CElemTrameJbusReadWordsRQ_3_4
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemTrameJbusReadWordsRQ_3_4::CElemTrameJbusReadWordsRQ_3_4(): CElemTrameJbus()
{
	SetLabel(_T("CElemTrameJbusReadWordsRQ_3_4"));
}

CElemTrameJbusReadWordsRQ_3_4::~CElemTrameJbusReadWordsRQ_3_4()
{
}

BOOL CElemTrameJbusReadWordsRQ_3_4::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;
	int iPos = Context.iGetCurrentSize();
	BYTE* pStart = Context.m_pBuffCurrent;


	bReturn = CElemTrameJbus::bSerialize(Context);
	if (bReturn) bReturn = m_StartAddr.bSerialize(Context);
	if (bReturn) bReturn = m_NbrWords.bSerialize(Context);
	if (bReturn) bReturn = bSerializeCRC16(pStart, Context.iGetCurrentSize() - iPos,Context);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}
int CElemTrameJbusReadWordsRQ_3_4::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	iSize = CElemTrameJbus::iGetStreamSize(Context);
	iSize += m_StartAddr.iGetStreamSize(Context);
	iSize += m_NbrWords.iGetStreamSize(Context);
	iSize += m_CRC16.iGetStreamSize(Context);
	return iSize;
}

BOOL CElemTrameJbusReadWordsRQ_3_4::bSetConfig(LPTSTR pszText,int &iCurrentPos,CListStream *pListStream)
{
	BOOL bReturn = FALSE;
	TCHAR szSeps[]   = _T("|");
	TCHAR *pcToken;
	TCHAR szText[MAX_PATH];

	pszText += iCurrentPos;
	iCurrentPos = 0;

	_stprintf(szText,_T("CElemTrameJbusReadWordsRQ_3_4 : %s"),pszText);
	SetLabel(szText);
	if (bReturn = CElemTrameJbus::bSetConfig(pszText,iCurrentPos,pListStream))
	{
		pszText += iCurrentPos;
		iCurrentPos = 0;
		// adresse 
		pcToken = _tcstok( pszText, szSeps ); 
		if (pcToken != NULL)
		{
			iCurrentPos += (lstrlen(pcToken) + 1);
			bReturn = m_StartAddr.bSetTextVal(pcToken);
			pcToken = _tcstok( NULL, szSeps ); 
		}
		// nbr de words
		if (pcToken != NULL && bReturn)
		{
			iCurrentPos += (lstrlen(pcToken) + 1);
			bReturn = m_NbrWords.bSetTextVal(pcToken);
			pcToken = _tcstok( NULL, szSeps ); 
		}
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

LPTSTR CElemTrameJbusReadWordsRQ_3_4::szGetConfig(LPTSTR pszText, int iSizeMax)
{
	TCHAR szSeps[]   = _T("|");
	TCHAR szTemp[CONV_BUFFER_SIZE];

	CElemTrameJbus::szGetConfig(pszText, iSizeMax);
	iSizeMax -= lstrlen(pszText);
	// adresse
	_stprintf(szTemp,_T("0x%08x"),m_StartAddr.nGetVal());
	lstrcat(pszText,szTemp);
	lstrcat(pszText,szSeps);
	// nbr words
	_stprintf(szTemp,_T("%d"),m_NbrWords.nGetVal());
	lstrcat(pszText,szTemp);

	return pszText;
}



/*(@!*****************************************************************************************
* Nom     : CElemTrameJbusReadWordsRP_3_4
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemTrameJbusReadWordsRP_3_4::CElemTrameJbusReadWordsRP_3_4(): CElemTrameJbus()
{
	SetLabel(_T("CElemTrameJbusReadWordsRP_3_4"));
}

CElemTrameJbusReadWordsRP_3_4::~CElemTrameJbusReadWordsRP_3_4()
{
}

BOOL CElemTrameJbusReadWordsRP_3_4::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;
	int iPos = Context.iGetCurrentSize();
	BYTE* pStart = Context.m_pBuffCurrent;


	BOOL bForceWord = Context.bGetForceWord();
	bReturn = CElemTrameJbus::bSerialize(Context);
	if (bReturn) bReturn = m_NbrBytes.bSerialize(Context);
	// vérification nbr demandé == nbr configuré
	Context.SetForceWord(TRUE);
	if (bReturn) bReturn = (m_NbrBytes.ucGetVal() == (m_ListParams.iGetStreamSize(Context)/*m_ListParams.iGetCount()*2*/));//2009_06_25
	if (bReturn) bReturn = m_ListParams.bSerialize(Context);
	Context.SetForceWord(bForceWord);
	if (bReturn) bReturn = bSerializeCRC16(pStart, Context.iGetCurrentSize() - iPos,Context);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}


int CElemTrameJbusReadWordsRP_3_4::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	BOOL bForceWord = Context.bGetForceWord();

	iSize = CElemTrameJbus::iGetStreamSize(Context);
	iSize += m_NbrBytes.iGetStreamSize(Context);
	Context.SetForceWord(TRUE);
	iSize += m_ListParams.iGetStreamSize(Context);
	Context.SetForceWord(bForceWord);
	iSize += m_CRC16.iGetStreamSize(Context);
	return iSize;
}

BOOL CElemTrameJbusReadWordsRP_3_4::bSetConfig(LPTSTR pszText,int &iCurrentPos,CListStream *pListStream)
{
	BOOL bReturn = FALSE;
	TCHAR szSeps[]   = _T("|");
	TCHAR *pcToken;
	int i;
	long lID = 0;
	CElemBase *pElem = NULL;
	TCHAR szText[MAX_PATH];

	pszText += iCurrentPos;
	iCurrentPos = 0;

	_stprintf(szText,_T("CElemTrameJbusReadWordsRP_3_4 : %s"),pszText);
	SetLabel(szText);
	if (bReturn = CElemTrameJbus::bSetConfig(pszText,iCurrentPos,pListStream))
	{
		pszText += iCurrentPos;
		iCurrentPos = 0;
		// nbr de byte
		pcToken = _tcstok(pszText, szSeps ); 
		if (pcToken)
		{
			iCurrentPos += (lstrlen(pcToken) + 1);
			bReturn = m_NbrBytes.bSetTextVal(pcToken);
			// les params
			pcToken = _tcstok( NULL, szSeps ); 
			for (i = 0;bReturn && (pcToken != NULL) && (i < m_NbrBytes.ucGetVal()/2);i++)
			{
				iCurrentPos += (lstrlen(pcToken) + 1);
				lID = 0;
				if ((_tcsstr(pcToken,_T("0x")) != NULL) || (_tcsstr(pcToken,_T("0X")) != NULL))// c'est une adresse
				{
					_stscanf(pcToken,_T("%x"),&lID);
					pElem = pListStream->pFindElemFromID(lID);
					bReturn = (pElem != NULL);
				}
				else // c'est une valeur
				{
					pElem = new CElemInt16();
					bReturn = (pElem != NULL);
					if (bReturn)
					{
						pElem->SetAutoDelete(TRUE);
						bReturn = ((CElemInt16*)pElem)->bSetTextVal(pcToken);
					}
				}
				if (bReturn)
				{
					bReturn = (m_ListParams.pAdd(pElem) != NULL);
				}
				pcToken = _tcstok( NULL, szSeps ); 
			}
		}
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

LPTSTR CElemTrameJbusReadWordsRP_3_4::szGetConfig(LPTSTR pszText, int iSizeMax)
{
	TCHAR szSeps[]   = _T("|");
	TCHAR szTemp[CONV_BUFFER_SIZE];
	int i;
	CElemInt16 *pElem = NULL;

	CElemTrameJbus::szGetConfig(pszText, iSizeMax);
	iSizeMax -= lstrlen(pszText);
	// nbr byte
	_stprintf(szTemp,_T("%d"),m_NbrBytes.ucGetVal());
	lstrcat(pszText,szTemp);
	// adresse word
	for (i = 0; i < m_ListParams.iGetCount();i++)
	{
		pElem = (CElemInt16*)m_ListParams.pGetAt(i);
		if (pElem)
		{
			if (NUM_ID(pElem->iGetType()) == 0x000000FF)
			{
				_stprintf(szTemp,_T("%d"),((CElemInt16*)pElem)->nGetVal());
			}
			else
			{
				_stprintf(szTemp,_T("0x%08x"),pElem->iGetType());
			}
			lstrcat(pszText,szSeps);
			lstrcat(pszText,szTemp);
		}
	}
	return pszText;
}



/*(@!*****************************************************************************************
* Nom     : Fonction JBUS 5
* Role    : definition d'une trame JBUS 5
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
/*(@!*****************************************************************************************
* Nom     : CElemTrameJbusWriteBit_5
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemTrameJbusWriteBit_5::CElemTrameJbusWriteBit_5(): CElemTrameJbus()
{
	SetLabel(_T("CElemTrameJbusWriteBit_5"));
}

CElemTrameJbusWriteBit_5::~CElemTrameJbusWriteBit_5()
{
}

BOOL CElemTrameJbusWriteBit_5::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;
	int iPos = Context.iGetCurrentSize();
	BYTE* pStart = Context.m_pBuffCurrent;


	BOOL bForce = Context.bGetForceByte();
	bReturn = CElemTrameJbus::bSerialize(Context);
	if (bReturn) bReturn = m_StartAddr.bSerialize(Context);
	Context.SetForceByte(TRUE);
	if (bReturn) bReturn = m_ListParams.bSerialize(Context);
	Context.SetForceByte(bForce);
	if (bReturn) bReturn = bSerializeCRC16(pStart, Context.iGetCurrentSize() - iPos,Context);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}


int CElemTrameJbusWriteBit_5::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	BOOL bForce = Context.bGetForceByte();
	iSize = CElemTrameJbus::iGetStreamSize(Context);
	iSize += m_StartAddr.iGetStreamSize(Context);
	Context.SetForceByte(TRUE);
	iSize += m_ListParams.iGetStreamSize(Context);
	Context.SetForceByte(bForce);
	iSize += m_CRC16.iGetStreamSize(Context);
	return iSize;
}

BOOL CElemTrameJbusWriteBit_5::bSetConfig(LPTSTR pszText,int &iCurrentPos,CListStream *pListStream)
{
	BOOL bReturn = FALSE;
	TCHAR szSeps[]   = _T("|");
	TCHAR *pcToken;
	long lID = 0;
	CElemBase *pElem = NULL;
	TCHAR szText[MAX_PATH];

	pszText += iCurrentPos;
	iCurrentPos = 0;

	_stprintf(szText,_T("CElemTrameJbusWriteBit_5 : %s"),pszText);
	SetLabel(szText);
	if (bReturn = CElemTrameJbus::bSetConfig(pszText,iCurrentPos,pListStream))
	{
		pszText += iCurrentPos;
		iCurrentPos = 0;
		// valeur de l'adresse
		pcToken = _tcstok(pszText, szSeps ); 
		if (pcToken)
		{
			iCurrentPos += (lstrlen(pcToken) + 1);
			m_StartAddr.bSetTextVal(pcToken);
			// valeur du bit
			pcToken = _tcstok(NULL, szSeps ); 
			if (pcToken)
			{
				iCurrentPos += (lstrlen(pcToken) + 1);
				lID = 0;
				if ((_tcsstr(pcToken,_T("0x")) != NULL) || (_tcsstr(pcToken,_T("0X")) != NULL))// c'est une adresse
				{
					_stscanf(pcToken,_T("%x"),&lID);
					pElem = pListStream->pFindElemFromID(lID);
					bReturn = (pElem != NULL);
				}
				else // c'est une valeur
				{
					pElem = new CElemInt8();
					bReturn = (pElem != NULL);
					if (bReturn)
					{
						pElem->SetAutoDelete(TRUE);
						bReturn = ((CElemInt8*)pElem)->bSetTextVal(pcToken);
					}
				}
				if (bReturn)
				{
					bReturn = (m_ListParams.pAdd(pElem) != NULL);
				}
				// le zero pour terminer
				if (bReturn)
				{
					bReturn = (m_ListParams.pAdd(new CElemInt8()) != NULL);
				}
			}
		}
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

LPTSTR CElemTrameJbusWriteBit_5::szGetConfig(LPTSTR pszText, int iSizeMax)
{
	TCHAR szSeps[]   = _T("|");
	TCHAR szTemp[CONV_BUFFER_SIZE];
	CElemInt8 *pElem = NULL;

	CElemTrameJbus::szGetConfig(pszText, iSizeMax);
	iSizeMax -= lstrlen(pszText);
	// adresse
	_stprintf(szTemp,_T("0x%08x"),m_StartAddr.nGetVal());
	lstrcat(pszText,szTemp);
	// valeur du bit
	pElem = (CElemInt8*)m_ListParams.pGetAt(0);
	if (pElem)
	{
		if (NUM_ID(pElem->iGetType()) == 0x000000FF)
		{
			_stprintf(szTemp,_T("%d"),((CElemInt8*)pElem)->ucGetVal());
		}
		else
		{
			_stprintf(szTemp,_T("0x%08x"),pElem->iGetType());
		}
		lstrcat(pszText,szSeps);
		lstrcat(pszText,szTemp);
	}
	return pszText;
}


/*(@!*****************************************************************************************
* Nom     : Fonction JBUS 6
* Role    : definition d'une trame JBUS 6
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
/*(@!*****************************************************************************************
* Nom     : CElemTrameJbusWriteWord_6
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemTrameJbusWriteWord_6::CElemTrameJbusWriteWord_6(): CElemTrameJbus()
{
	SetLabel(_T("CElemTrameJbusWriteWord_6"));
}

CElemTrameJbusWriteWord_6::~CElemTrameJbusWriteWord_6()
{
}

BOOL CElemTrameJbusWriteWord_6::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;
	int iPos = Context.iGetCurrentSize();
	BYTE* pStart = Context.m_pBuffCurrent;


	BOOL bForceWord = Context.bGetForceWord();
	bReturn = CElemTrameJbus::bSerialize(Context);
	if (bReturn) bReturn = m_StartAddr.bSerialize(Context);
	Context.SetForceWord(TRUE);
	if (bReturn) bReturn = m_ListParams.bSerialize(Context);
	Context.SetForceWord(bForceWord);
	if (bReturn) bReturn = bSerializeCRC16(pStart, Context.iGetCurrentSize() - iPos,Context);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}
int CElemTrameJbusWriteWord_6::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	BOOL bForceWord = Context.bGetForceWord();
	iSize = CElemTrameJbus::iGetStreamSize(Context);
	iSize += m_StartAddr.iGetStreamSize(Context);
	Context.SetForceWord(TRUE);
	iSize += m_ListParams.iGetStreamSize(Context);
	Context.SetForceWord(bForceWord);
	iSize += m_CRC16.iGetStreamSize(Context);
	return iSize;
}



BOOL CElemTrameJbusWriteWord_6::bSetConfig(LPTSTR pszText,int &iCurrentPos,CListStream *pListStream)
{
	BOOL bReturn = FALSE;
	TCHAR szSeps[]   = _T("|");
	TCHAR *pcToken;
	long lID = 0;
	CElemBase *pElem = NULL;
	TCHAR szText[MAX_PATH];

	pszText += iCurrentPos;
	iCurrentPos = 0;

	_stprintf(szText,_T("CElemTrameJbusWriteWord_6 : %s"),pszText);
	SetLabel(szText);
	if (bReturn = CElemTrameJbus::bSetConfig(pszText,iCurrentPos,pListStream))
	{
		pszText += iCurrentPos;
		iCurrentPos = 0;
		// valeur de l'adresse
		pcToken = _tcstok(pszText, szSeps ); 
		if (pcToken)
		{
			iCurrentPos += (lstrlen(pcToken) + 1);
			m_StartAddr.bSetTextVal(pcToken);
			// valeur du word
			pcToken = _tcstok(NULL, szSeps ); 
			if (pcToken)
			{
				iCurrentPos += (lstrlen(pcToken) + 1);
				lID = 0;
				if ((_tcsstr(pcToken,_T("0x")) != NULL) || (_tcsstr(pcToken,_T("0X")) != NULL))// c'est une adresse
				{
					_stscanf(pcToken,_T("%x"),&lID);
					pElem = pListStream->pFindElemFromID(lID);
					bReturn = (pElem != NULL);
				}
				else // c'est une valeur
				{
					pElem = new CElemInt16();
					bReturn = (pElem != NULL);
					if (bReturn)
					{
						pElem->SetAutoDelete(TRUE);
						bReturn = ((CElemInt16*)pElem)->bSetTextVal(pcToken);
					}
				}
				if (bReturn)
				{
					bReturn = (m_ListParams.pAdd(pElem) != NULL);
				}
			}
		}
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

LPTSTR CElemTrameJbusWriteWord_6::szGetConfig(LPTSTR pszText, int iSizeMax)
{
	TCHAR szSeps[]   = _T("|");
	TCHAR szTemp[CONV_BUFFER_SIZE];
	CElemInt16 *pElem = NULL;

	CElemTrameJbus::szGetConfig(pszText, iSizeMax);
	iSizeMax -= lstrlen(pszText);
	// adresse
	_stprintf(szTemp,_T("0x%08x"),m_StartAddr.nGetVal());
	lstrcat(pszText,szTemp);
	// valeur du bit
	pElem = (CElemInt16*)m_ListParams.pGetAt(0);
	if (pElem)
	{
		if (NUM_ID(pElem->iGetType()) == 0x000000FF)
		{
			_stprintf(szTemp,_T("%d"),((CElemInt16*)pElem)->nGetVal());
		}
		else
		{
			_stprintf(szTemp,_T("0x%08x"),pElem->iGetType());
		}
		lstrcat(pszText,szSeps);
		lstrcat(pszText,szTemp);
	}
	return pszText;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
/*(@!*****************************************************************************************
* Nom     : Fonction JBUS 15
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
/*(@!*****************************************************************************************
* Nom     : CElemTrameJbusWriteBitsRQ_15
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemTrameJbusWriteBitsRQ_15::CElemTrameJbusWriteBitsRQ_15(): CElemTrameJbus()
{
	SetLabel(_T("CElemTrameJbusWriteBitsRQ_15"));
}

CElemTrameJbusWriteBitsRQ_15::~CElemTrameJbusWriteBitsRQ_15()
{
}

BOOL CElemTrameJbusWriteBitsRQ_15::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;
	int iPos = Context.iGetCurrentSize();
	BYTE* pStart = Context.m_pBuffCurrent;


	bReturn = CElemTrameJbus::bSerialize(Context);
	if (bReturn) bReturn = m_StartAddr.bSerialize(Context);
	if (bReturn) bReturn = m_NbrBits.bSerialize(Context);
	if (bReturn) bReturn = m_NbrBytes.bSerialize(Context);
	if (bReturn) bReturn = m_ListParams.bSerialize(Context);
	if (bReturn) bReturn = bSerializeCRC16(pStart, Context.iGetCurrentSize() - iPos,Context);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}

int CElemTrameJbusWriteBitsRQ_15::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	iSize = CElemTrameJbus::iGetStreamSize(Context);
	iSize += m_StartAddr.iGetStreamSize(Context);
	iSize += m_NbrBits.iGetStreamSize(Context);
	iSize += m_NbrBytes.iGetStreamSize(Context);
	iSize += m_ListParams.iGetStreamSize(Context);
	iSize += m_CRC16.iGetStreamSize(Context);
	return iSize;
}

BOOL CElemTrameJbusWriteBitsRQ_15::bSetConfig(LPTSTR pszText,int &iCurrentPos,CListStream *pListStream)
{
	BOOL bReturn = FALSE;
	TCHAR szSeps[]   = _T("|");
	TCHAR *pcToken;
	int i;
	int j;
	CElemFieldBit8 *pElemFieldBit8;
	CElemBase *pElem;
	long lID;
	TCHAR szText[MAX_PATH];

	pszText += iCurrentPos;
	iCurrentPos = 0;

	_stprintf(szText,_T("CElemTrameJbusWriteBitsRQ_15 : %s"),pszText);
	SetLabel(szText);
	if (bReturn = CElemTrameJbus::bSetConfig(pszText,iCurrentPos,pListStream))
	{
		pszText += iCurrentPos;
		iCurrentPos = 0;
		// adresse 
		pcToken = _tcstok( pszText, szSeps ); 
		if (pcToken != NULL)
		{
			iCurrentPos += (lstrlen(pcToken) + 1);
			bReturn = m_StartAddr.bSetTextVal(pcToken);
			pcToken = _tcstok( NULL, szSeps ); 
		}
		// nbr de bit
		if (pcToken != NULL && bReturn)
		{
			iCurrentPos += (lstrlen(pcToken) + 1);
			bReturn = m_NbrBits.bSetTextVal(pcToken);
			pcToken = _tcstok( NULL, szSeps ); 
		}
		// nbr de octets
		if (pcToken != NULL && bReturn)
		{
			iCurrentPos += (lstrlen(pcToken) + 1);
			bReturn = m_NbrBytes.bSetTextVal(pcToken);
			if (bReturn)
			{
				// les params
				pcToken = _tcstok( NULL, szSeps ); 
				for (i = 0;bReturn && (pcToken != NULL) && (i < m_NbrBits.nGetVal());)
				{
					pElemFieldBit8 = (CElemFieldBit8 *)m_ListParams.pAdd(new CElemFieldBit8());
					bReturn = (pElemFieldBit8 != NULL);
					if (bReturn)
					{
						pElemFieldBit8->SetAutoDelete(TRUE);
						for (j = 0; bReturn && (j < 8); j++,i++)
						{
							if ((pcToken != NULL) && bReturn)
							{
								iCurrentPos += (lstrlen(pcToken) + 1);
								lID = 0;
								// valeur de ref à une variable interne
								if ((_tcsstr(pcToken,_T("0x")) != NULL) || (_tcsstr(pcToken,_T("0X")) != NULL))
								{
									_stscanf(pcToken,_T("%x"),&lID);
									pElem = pListStream->pFindElemFromID(lID);
									bReturn = (pElem != NULL);
								}
								else
								{
									pElem = new CElemInt8();
									bReturn = (pElem != NULL);
									if (bReturn)
									{
										pElem->SetAutoDelete(TRUE);
										bReturn = ((CElemInt8*)pElem)->bSetTextVal(pcToken);
									}
								}
								if (bReturn)
								{
									pElemFieldBit8->pAdd(pElem);
								}
								pcToken = _tcstok( NULL, szSeps ); 
							}
						}
					}
				}
			}
		}
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

LPTSTR CElemTrameJbusWriteBitsRQ_15::szGetConfig(LPTSTR pszText, int iSizeMax)
{
	int i;
	int j;
	CElemFieldBit8 *pElemFieldBit8;
	CElemInt8 *pElem;

	TCHAR szSeps[]   = _T("|");
	TCHAR szTemp[CONV_BUFFER_SIZE];

	CElemTrameJbus::szGetConfig(pszText, iSizeMax);
	iSizeMax -= lstrlen(pszText);
	// adresse
	_stprintf(szTemp,_T("0x%08x"),m_StartAddr.nGetVal());
	lstrcat(pszText,szTemp);
	lstrcat(pszText,szSeps);
	// nbr bit
	_stprintf(szTemp,_T("%d"),m_NbrBits.nGetVal());
	lstrcat(pszText,szTemp);
	lstrcat(pszText,szSeps);
	// nbr octets
	_stprintf(szTemp,_T("%d"),m_NbrBytes.ucGetVal());
	lstrcat(pszText,szTemp);
	// adresse bit
	for (i = 0; i < m_ListParams.iGetCount();i++)
	{
		pElemFieldBit8 = (CElemFieldBit8 *)m_ListParams.pGetAt(i);
		for (j = 0; pElemFieldBit8 && (j < 8); j++)
		{
			pElem = (CElemInt8*)pElemFieldBit8->pGetAt(j);
			lstrcat(pszText,szSeps);
			if (pElem)
			{
				if (NUM_ID(pElem->iGetType()) == 0x000000FF)
				{
					_stprintf(szTemp,_T("%d"),pElem->ucGetVal());
				}
				else
				{
					_stprintf(szTemp,_T("0x%08x"),pElem->iGetType());
				}
				lstrcat(pszText,szTemp);
			}
			else
			{
				lstrcat(pszText,_T("0"));
			}
		}
	}

	return pszText;
}



/*(@!*****************************************************************************************
* Nom     : CElemTrameJbusWriteBitsRP_15
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemTrameJbusWriteBitsRP_15::CElemTrameJbusWriteBitsRP_15(): CElemTrameJbus()
{
	SetLabel(_T("CElemTrameJbusWriteBitsRP_15"));
}

CElemTrameJbusWriteBitsRP_15::~CElemTrameJbusWriteBitsRP_15()
{
}

BOOL CElemTrameJbusWriteBitsRP_15::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;
	int iPos = Context.iGetCurrentSize();
	BYTE* pStart = Context.m_pBuffCurrent;


	bReturn = CElemTrameJbus::bSerialize(Context);
	if (bReturn) bReturn = m_StartAddr.bSerialize(Context);
	if (bReturn) bReturn = m_NbrBits.bSerialize(Context);
	if (bReturn) bReturn = bSerializeCRC16(pStart, Context.iGetCurrentSize() - iPos,Context);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}


int CElemTrameJbusWriteBitsRP_15::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	iSize = CElemTrameJbus::iGetStreamSize(Context);
	iSize += m_StartAddr.iGetStreamSize(Context);
	iSize += m_NbrBits.iGetStreamSize(Context);
	iSize += m_CRC16.iGetStreamSize(Context);
	return iSize;
}

BOOL CElemTrameJbusWriteBitsRP_15::bSetConfig(LPTSTR pszText,int &iCurrentPos,CListStream *pListStream)
{
	BOOL bReturn = FALSE;
	TCHAR szSeps[]   = _T("|");
	TCHAR *pcToken;
	TCHAR szText[MAX_PATH];

	pszText += iCurrentPos;
	iCurrentPos = 0;

	_stprintf(szText,_T("CElemTrameJbusWriteBitsRP_15 : %s"),pszText);
	SetLabel(szText);
	if (bReturn = CElemTrameJbus::bSetConfig(pszText,iCurrentPos,pListStream))
	{
		pszText += iCurrentPos;
		iCurrentPos = 0;
		// adresse debut
		pcToken = _tcstok(pszText, szSeps ); 
		if (pcToken)
		{
			iCurrentPos += (lstrlen(pcToken) + 1);
			bReturn = m_StartAddr.bSetTextVal(pcToken);
			// nbr de bits
			pcToken = _tcstok(NULL, szSeps ); 
			if (pcToken)
			{
				iCurrentPos += (lstrlen(pcToken) + 1);
				bReturn = m_NbrBits.bSetTextVal(pcToken);
			}
		}
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

LPTSTR CElemTrameJbusWriteBitsRP_15::szGetConfig(LPTSTR pszText, int iSizeMax)
{
	TCHAR szSeps[]   = _T("|");
	TCHAR szTemp[CONV_BUFFER_SIZE];

	CElemTrameJbus::szGetConfig(pszText, iSizeMax);
	iSizeMax -= lstrlen(pszText);
	// adresse
	_stprintf(szTemp,_T("0x%08x"),m_StartAddr.nGetVal());
	lstrcat(pszText,szTemp);
	lstrcat(pszText,szSeps);
	// nbr bit
	_stprintf(szTemp,_T("%d"),m_NbrBits.nGetVal());
	lstrcat(pszText,szTemp);
	return pszText;
}



////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
/*(@!*****************************************************************************************
* Nom     : Fonction JBUS 16
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
/*(@!*****************************************************************************************
* Nom     : CElemTrameJbusWriteWordsRQ_16
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemTrameJbusWriteWordsRQ_16::CElemTrameJbusWriteWordsRQ_16(): CElemTrameJbus()
{
	SetLabel(_T("CElemTrameJbusWriteWordsRQ_16"));
}

CElemTrameJbusWriteWordsRQ_16::~CElemTrameJbusWriteWordsRQ_16()
{
}

BOOL CElemTrameJbusWriteWordsRQ_16::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;
	BOOL bForceWord = Context.bGetForceWord();
	int iPos = Context.iGetCurrentSize();
	BYTE* pStart = Context.m_pBuffCurrent;


	bReturn = CElemTrameJbus::bSerialize(Context);
	if (bReturn) bReturn = m_StartAddr.bSerialize(Context);
	if (bReturn) bReturn = m_NbrWords.bSerialize(Context);
	if (bReturn) bReturn = m_NbrBytes.bSerialize(Context);
	Context.SetForceWord(TRUE);
	if (bReturn) bReturn = m_ListParams.bSerialize(Context);
	Context.SetForceWord(bForceWord);
	if (bReturn) bReturn = bSerializeCRC16(pStart, Context.iGetCurrentSize() - iPos,Context);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}



int CElemTrameJbusWriteWordsRQ_16::iGetStreamSize(CContext &Context)
{
	int iSize = 0;
	BOOL bForceWord = Context.bGetForceWord();

	iSize = CElemTrameJbus::iGetStreamSize(Context);
	iSize += m_StartAddr.iGetStreamSize(Context);
	iSize += m_NbrWords.iGetStreamSize(Context);
	iSize += m_NbrBytes.iGetStreamSize(Context);
	Context.SetForceWord(TRUE);
	iSize += m_ListParams.iGetStreamSize(Context);
	Context.SetForceWord(bForceWord);
	iSize += m_CRC16.iGetStreamSize(Context);
	return iSize;
}

BOOL CElemTrameJbusWriteWordsRQ_16::bSetConfig(LPTSTR pszText,int &iCurrentPos,CListStream *pListStream)
{
	BOOL bReturn = FALSE;
	TCHAR szSeps[]   = _T("|");
	TCHAR *pcToken;
	int i;
	long lID;
	CElemBase *pElem;
	TCHAR szText[MAX_PATH];

	pszText += iCurrentPos;
	iCurrentPos = 0;

	_stprintf(szText,_T("CElemTrameJbusWriteWordsRQ_16 : %s"),pszText);
	SetLabel(szText);
	if (bReturn = CElemTrameJbus::bSetConfig(pszText,iCurrentPos,pListStream))
	{
		pszText += iCurrentPos;
		iCurrentPos = 0;
		// adresse 
		pcToken = _tcstok( pszText, szSeps ); 
		if (pcToken != NULL)
		{
			iCurrentPos += (lstrlen(pcToken) + 1);
			bReturn = m_StartAddr.bSetTextVal(pcToken);
			pcToken = _tcstok( NULL, szSeps ); 
		}
		// nbr de words
		if (pcToken != NULL && bReturn)
		{
			iCurrentPos += (lstrlen(pcToken) + 1);
			bReturn = m_NbrWords.bSetTextVal(pcToken);
			pcToken = _tcstok( NULL, szSeps ); 
		}
		// nbr de  bytes
		if (pcToken != NULL && bReturn)
		{
			iCurrentPos += (lstrlen(pcToken) + 1);
			bReturn = m_NbrBytes.bSetTextVal(pcToken);
			// les params
			pcToken = _tcstok( NULL, szSeps ); 
			for (i = 0;bReturn && (pcToken != NULL) && (i < m_NbrWords.nGetVal());i++)
			{
				iCurrentPos += (lstrlen(pcToken) + 1);
				lID = 0;
				if ((_tcsstr(pcToken,_T("0x")) != NULL) || (_tcsstr(pcToken,_T("0X")) != NULL))// c'est une adresse
				{
					_stscanf(pcToken,_T("%x"),&lID);
					pElem = pListStream->pFindElemFromID(lID);
					bReturn = (pElem != NULL);
					if (!bReturn) 
					{
						OutputDebugString(_T("ID inconnu!!\n"));
						OutputDebugString(pcToken);
						
					}
				}
				else // c'est une valeur
				{
					pElem = new CElemInt16();
					bReturn = (pElem != NULL);
					if (bReturn)
					{
						pElem->SetAutoDelete(TRUE);
						bReturn = ((CElemInt16*)pElem)->bSetTextVal(pcToken);
					}
				}
				if (bReturn)
				{
					bReturn = (m_ListParams.pAdd(pElem) != NULL);
				}
				pcToken = _tcstok( NULL, szSeps ); 
			}
		}
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

LPTSTR CElemTrameJbusWriteWordsRQ_16::szGetConfig(LPTSTR pszText, int iSizeMax)
{
	TCHAR szSeps[]   = _T("|");
	TCHAR szTemp[CONV_BUFFER_SIZE];
	int i;
	CElemInt16 *pElem;

	CElemTrameJbus::szGetConfig(pszText, iSizeMax);
	iSizeMax -= lstrlen(pszText);
	// adresse
	_stprintf(szTemp,_T("0x%08x"),m_StartAddr.nGetVal());
	lstrcat(pszText,szTemp);
	lstrcat(pszText,szSeps);
	// nbr words
	_stprintf(szTemp,_T("%d"),m_NbrWords.nGetVal());
	lstrcat(pszText,szTemp);
	lstrcat(pszText,szSeps);
	// nbr bytes
	_stprintf(szTemp,_T("%d"),m_NbrBytes.ucGetVal());
	lstrcat(pszText,szTemp);

	// adresse word
	for (i = 0; i < m_ListParams.iGetCount();i++)
	{
		pElem = (CElemInt16*)m_ListParams.pGetAt(i);
		if (pElem)
		{
			if (NUM_ID(pElem->iGetType()) == 0x000000FF)
			{
				_stprintf(szTemp,_T("%d"),((CElemInt16*)pElem)->nGetVal());
			}
			else
			{
				_stprintf(szTemp,_T("0x%08x"),pElem->iGetType());
			}
			lstrcat(pszText,szSeps);
			lstrcat(pszText,szTemp);
		}
	}
	return pszText;
}



/*(@!*****************************************************************************************
* Nom     : CElemTrameJbusWriteWordsRP_16
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemTrameJbusWriteWordsRP_16::CElemTrameJbusWriteWordsRP_16(): CElemTrameJbus()
{
	SetLabel(_T("CElemTrameJbusWriteWordsRP_16"));
}

CElemTrameJbusWriteWordsRP_16::~CElemTrameJbusWriteWordsRP_16()
{
}

BOOL CElemTrameJbusWriteWordsRP_16::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;
	int iPos = Context.iGetCurrentSize();
	BYTE* pStart = Context.m_pBuffCurrent;


	bReturn = CElemTrameJbus::bSerialize(Context);
	if (bReturn) bReturn = m_StartAddr.bSerialize(Context);
	if (bReturn) bReturn = m_NbrWords.bSerialize(Context);
	if (bReturn) bReturn = bSerializeCRC16(pStart, Context.iGetCurrentSize() - iPos,Context);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}

int CElemTrameJbusWriteWordsRP_16::iGetStreamSize(CContext &Context)
{
	int iSize = 0;


	iSize = CElemTrameJbus::iGetStreamSize(Context);
	iSize += m_StartAddr.iGetStreamSize(Context);
	iSize += m_NbrWords.iGetStreamSize(Context);
	iSize += m_CRC16.iGetStreamSize(Context);
	return iSize;
}

BOOL CElemTrameJbusWriteWordsRP_16::bSetConfig(LPTSTR pszText,int &iCurrentPos,CListStream *pListStream)
{
	BOOL bReturn = FALSE;
	TCHAR szSeps[]   = _T("|");
	TCHAR *pcToken;
	long lID = 0;
	CElemBase *pElem = NULL;
	TCHAR szText[MAX_PATH];

	pszText += iCurrentPos;
	iCurrentPos = 0;

	_stprintf(szText,_T("CElemTrameJbusWriteWordsRP_16 : %s"),pszText);
	SetLabel(szText);
	if (bReturn = CElemTrameJbus::bSetConfig(pszText,iCurrentPos,pListStream))
	{
		pszText += iCurrentPos;
		iCurrentPos = 0;
		// addresse
		pcToken = _tcstok(pszText, szSeps ); 
		if (pcToken)
		{
			iCurrentPos += (lstrlen(pcToken) + 1);
			bReturn = m_StartAddr.bSetTextVal(pcToken);
			// nbr word
			pcToken = _tcstok(NULL, szSeps ); 
			if (pcToken)
			{
				iCurrentPos += (lstrlen(pcToken) + 1);
				bReturn = m_NbrWords.bSetTextVal(pcToken);
			}
		}
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

LPTSTR CElemTrameJbusWriteWordsRP_16::szGetConfig(LPTSTR pszText, int iSizeMax)
{
	TCHAR szSeps[]   = _T("|");
	TCHAR szTemp[CONV_BUFFER_SIZE];
	CElemInt16 *pElem = NULL;

	CElemTrameJbus::szGetConfig(pszText, iSizeMax);
	iSizeMax -= lstrlen(pszText);
	// addresse
	_stprintf(szTemp,_T("0x%08x"),m_StartAddr.nGetVal());
	lstrcat(pszText,szTemp);
	lstrcat(pszText,szSeps);
	// nbr byte
	_stprintf(szTemp,_T("%d"),m_NbrWords.nGetVal());
	lstrcat(pszText,szTemp);
	return pszText;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
/*(@!*****************************************************************************************
* Nom     : Fonction JBUS socket 20
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
/*(@!*****************************************************************************************
* Nom     : CElemTrameJbusSocket_20
* Role    : definition d'une trame JBUS socket
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemTrameJbusSocket_20::CElemTrameJbusSocket_20(): CElemTrameJbus()
{
	SetLabel(_T("CElemTrameJbusSocket_20"));
}

CElemTrameJbusSocket_20::~CElemTrameJbusSocket_20()
{
}

BOOL CElemTrameJbusSocket_20::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;
	int iPos = Context.iGetCurrentSize();
	BYTE* pStart = Context.m_pBuffCurrent;
	short sNbrElem;
	BOOL bMemoAll;

	bMemoAll = Context.m_bAllData;

	bReturn = CElemTrameJbus::bSerialize(Context);
	// nbr elem ne sert pas: utile que pour la cohérence de la messagerie
	sNbrElem = (short)m_ListParams.iGetCount();
	sNbrElem = MAKEWORD(HIBYTE(sNbrElem),LOBYTE(sNbrElem));
	if (bReturn) bReturn = bLoadSaveInt16(sNbrElem,Context);


	if (m_CodeFct.ucGetVal() == 21) Context.m_bAllData = TRUE;
	if (bReturn) bReturn = m_ListParams.bSerialize(Context);
	if (m_CodeFct.ucGetVal() == 21) Context.m_bAllData = bMemoAll;
	if (bReturn) bReturn = bSerializeCRC16(pStart, Context.iGetCurrentSize() - iPos,Context);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}



int CElemTrameJbusSocket_20::iGetStreamSize(CContext &Context)
{
	int iSize = 0;
	BOOL bMemoAll;

	bMemoAll = Context.m_bAllData;

	iSize = CElemTrameJbus::iGetStreamSize(Context);
	iSize += 2; // contient le nbr d'element m_ListParams.iGetCount()
	if (m_CodeFct.ucGetVal() == 21) Context.m_bAllData = TRUE;
	iSize += m_ListParams.iGetStreamSize(Context);
	if (m_CodeFct.ucGetVal() == 21) Context.m_bAllData = bMemoAll;
	iSize += m_CRC16.iGetStreamSize(Context);
	return iSize;
}

BOOL CElemTrameJbusSocket_20::bSetConfig(LPTSTR pszText,int &iCurrentPos,CListStream *pListStream)
{
	BOOL bReturn = FALSE;
	TCHAR szSeps[]   = _T("|");
	TCHAR *pcToken;
	int i;
	long lID;
	CElemBase *pElem;
	TCHAR szText[MAX_PATH*2];

	pszText += iCurrentPos;
	iCurrentPos = 0;

	_stprintf(szText,_T("CElemTrameJbusSocket_20 : %s"),pszText);
	SetLabel(szText);
	if (bReturn = CElemTrameJbus::bSetConfig(pszText,iCurrentPos,pListStream))
	{
		pszText += iCurrentPos;
		iCurrentPos = 0;
		// m_NbrParams 
		pcToken = _tcstok( pszText, szSeps ); 
		if (pcToken != NULL)
		{
			iCurrentPos += (lstrlen(pcToken) + 1);
			bReturn = m_NbrParams.bSetTextVal(pcToken);
			// les params
			pcToken = _tcstok( NULL, szSeps ); 
			for (i = 0;bReturn && (pcToken != NULL) && (i < m_NbrParams.nGetVal());i++)
			{
				iCurrentPos += (lstrlen(pcToken) + 1);
				lID = 0;
				if ((_tcsstr(pcToken,_T("0x")) != NULL) || (_tcsstr(pcToken,_T("0X")) != NULL))// c'est une adresse
				{
					_stscanf(pcToken,_T("%x"),&lID);
					pElem = pListStream->pFindElemFromID(lID);
					bReturn = (pElem != NULL);
					if (!bReturn) 
					{
						TRACE_DEBUG(eError,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error:ID inconnu= %s"),pcToken);
					}
				}
				else // c'est une valeur
				{
					pElem = new CElemFloat();
					bReturn = (pElem != NULL);
					if (bReturn)
					{
						pElem->SetAutoDelete(TRUE);
						bReturn = ((CElemFloat*)pElem)->bSetTextVal(pcToken);
					}
				}
				if (bReturn)
				{
					bReturn = (m_ListParams.pAdd(pElem) != NULL);
				}
				pcToken = _tcstok( NULL, szSeps ); 
			}
		}
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

LPTSTR CElemTrameJbusSocket_20::szGetConfig(LPTSTR pszText, int iSizeMax)
{
	TCHAR szSeps[]   = _T("|");
	TCHAR szTemp[CONV_BUFFER_SIZE];
	int i;
	CElemFloat *pElem;

	CElemTrameJbus::szGetConfig(pszText, iSizeMax);
	iSizeMax -= lstrlen(pszText);
	// nbr m_NbrParams
	_stprintf(szTemp,_T("%d"),m_NbrParams.nGetVal());
	lstrcat(pszText,szTemp);
	lstrcat(pszText,szSeps);

	// adresse params
	for (i = 0; i < m_ListParams.iGetCount();i++)
	{
		pElem = (CElemFloat*)m_ListParams.pGetAt(i);
		if (pElem)
		{
			if (NUM_ID(pElem->iGetType()) == 0x000000FF)
			{
				_stprintf(szTemp,_T("0x%08f"),((CElemFloat*)pElem)->fGetVal());
			}
			else
			{
				_stprintf(szTemp,_T("0x%08x"),pElem->iGetType());
			}
			lstrcat(pszText,szSeps);
			lstrcat(pszText,szTemp);
		}
	}
	return pszText;
}



	
	
	
	
/*(@!*****************************************************************************************
* Nom     : CElemExchangeJbus
* Role    : definition d'un echange JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemExchangeJbus::CElemExchangeJbus() : CElemBase()
{
	m_iType = MAKE_ID(0xFF,0xFF,eTYPE_JBUS_EXCHANGE,0xFF);
	SetLabel(_T("CElemExchangeJbus"));
	m_pTrameJbusRQ = NULL;
	m_pTrameJbusRP = NULL;
}

CElemExchangeJbus::~CElemExchangeJbus()
{
	RemoveAll();
}

void CElemExchangeJbus::RemoveAll()
{
	if (m_pTrameJbusRQ) delete m_pTrameJbusRQ;
	if (m_pTrameJbusRP) delete m_pTrameJbusRP;
	m_pTrameJbusRQ = NULL;
	m_pTrameJbusRP = NULL;
}

BOOL CElemExchangeJbus::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;

	bReturn = CElemBase::bSerialize(Context);
	if (bReturn && m_pTrameJbusRQ) bReturn = m_pTrameJbusRQ->bSerialize(Context);
	if (bReturn && m_pTrameJbusRP) bReturn = m_pTrameJbusRP->bSerialize(Context);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}

int CElemExchangeJbus::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	iSize = CElemBase::iGetStreamSize(Context);
	if (m_pTrameJbusRQ) iSize += m_pTrameJbusRQ->iGetStreamSize(Context);
	if (m_pTrameJbusRP) iSize += m_pTrameJbusRP->iGetStreamSize(Context);
	return iSize;
}

int CElemExchangeJbus::iGetNumFunction(LPTSTR pszText)
{
	TCHAR szTemp[MAX_PATH];
	CElemInt8 CodeFunc;
	int i = 0;

	szTemp[0] = 0;
	// recherche début 
	while ((*pszText != _T('|')) && (*pszText != 0)) pszText++;
	if (*pszText == _T('|'))
	{
		pszText++;
		while ((*pszText != _T('|')) && (*pszText != 0)) 
		{
			szTemp[i] = *pszText;	
			pszText++;
			i++;
		}
		if (*pszText == _T('|'))
		{
			// fin de chaine
			szTemp[i] = 0;
		}
	}
	return lConvString2Long(szTemp);
}

BOOL CElemExchangeJbus::bSetConfig(BOOL bIsRQ, LPTSTR szText,int &iCurrentPos,CListStream *pListStream)
{
	BOOL bReturn = FALSE;
	TCHAR szSeps[]   = _T("|");
	long lID = 0;
	CElemBase *pElem = NULL;
	int iCodeFunc = 0;

	if (bIsRQ && m_pTrameJbusRQ) 
	{
		delete m_pTrameJbusRQ;
		m_pTrameJbusRQ = NULL;
	}
	else if (m_pTrameJbusRP) 
	{
		delete m_pTrameJbusRP;
		m_pTrameJbusRP = NULL;
	}

	iCodeFunc = iGetNumFunction(szText);
	switch (iCodeFunc)
	{
	case 1:
	case 2:
		if (bIsRQ) m_pTrameJbusRQ = new CElemTrameJbusReadBitsRQ_1_2();
		else m_pTrameJbusRP = new CElemTrameJbusReadBitsRP_1_2();
		break;

	case 3:
	case 4:
		if (bIsRQ) m_pTrameJbusRQ = new CElemTrameJbusReadWordsRQ_3_4();
		else m_pTrameJbusRP = new CElemTrameJbusReadWordsRP_3_4();
		break;

	case 5:
		if (bIsRQ) m_pTrameJbusRQ = new CElemTrameJbusWriteBit_5();
		else m_pTrameJbusRP = new CElemTrameJbusWriteBit_5();
		break;

	case 6:
		if (bIsRQ) m_pTrameJbusRQ = new CElemTrameJbusWriteWord_6();
		else m_pTrameJbusRP = new CElemTrameJbusWriteWord_6();
		break;

	case 15:
		if (bIsRQ) m_pTrameJbusRQ = new CElemTrameJbusWriteBitsRQ_15();
		else m_pTrameJbusRP = new CElemTrameJbusWriteBitsRP_15();
		break;

	case 16:
		if (bIsRQ) m_pTrameJbusRQ = new CElemTrameJbusWriteWordsRQ_16();
		else m_pTrameJbusRP = new CElemTrameJbusWriteWordsRP_16();
		break;

	case 20:
	case 21:
		if (bIsRQ) m_pTrameJbusRQ = new CElemTrameJbusSocket_20();
		else m_pTrameJbusRP = new CElemTrameJbusSocket_20();
		break;

	default:
		break;

	}

	if (bIsRQ && m_pTrameJbusRQ) bReturn = m_pTrameJbusRQ->bSetConfig(szText,iCurrentPos,pListStream);
	else if (m_pTrameJbusRP) bReturn = m_pTrameJbusRP->bSetConfig(szText,iCurrentPos,pListStream);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

LPTSTR CElemExchangeJbus::szGetConfig(BOOL bIsRQ, LPTSTR pszText, int iSizeMax)
{
	TCHAR* pTemp = NULL;

	if (bIsRQ && m_pTrameJbusRQ) pTemp = m_pTrameJbusRQ->szGetConfig(pszText, iSizeMax);
	else if (m_pTrameJbusRP) pTemp = m_pTrameJbusRP->szGetConfig(pszText, iSizeMax);

	return pTemp;
}


