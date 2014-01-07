#include "stdafx.h"
#include "network.h"


/*(@!*****************************************************************************************
* Nom     : CElemBase
* Role    : definition des types élementaires
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemBase::CElemBase()
{
	InitializeCriticalSection(&m_hCriticalSection);
	m_bAutoDelete = FALSE;
	m_pcLabel = NULL;
	m_iLabelLength = 0;
	m_iType = MAKE_ID(0xFF,0xFF,eTYPE_TXT,0xFF);
	SetLabel(_T("CElemBase"));
}

CElemBase::~CElemBase()
{
	if (m_pcLabel) free(m_pcLabel);
	DeleteCriticalSection(&m_hCriticalSection);
}

BOOL CElemBase::bSetLabelLength(int iSize)
{
	if (m_iLabelLength < iSize)
	{
		m_iLabelLength = iSize; 
		if (m_pcLabel == NULL) m_pcLabel=(TCHAR*)malloc((m_iLabelLength));
		else m_pcLabel = (TCHAR*)realloc(m_pcLabel,(m_iLabelLength));
	}

	return ((m_iLabelLength == 0) || (m_pcLabel != NULL));
}

long CElemBase::lGetLabelLength()
{
	return lstrlen(m_pcLabel);
}

void CElemBase::SetLabel(LPCTSTR szText)
{
	int iSize;

	EnterCriticalSection(&m_hCriticalSection);
	iSize = lstrlen(szText);
	if (bSetLabelLength(iSize * (sizeof(TCHAR)+1)))// +1 pour la prise en compte du \0
	{
		lstrcpy(m_pcLabel,szText);
	}
	LeaveCriticalSection(&m_hCriticalSection);
}

void CElemBase::SetElemName(const QString& arg_elemName)
{
    m_elemName = arg_elemName;
}
QString CElemBase::getElemName()const
{
    return m_elemName;
}

BOOL CElemBase::bLoadSave(LPVOID lpData,long lDataSize,CContext &Context)
{
	size_t dwTransmis = 0;

	if ((Context.m_hFile != NULL) && (Context.m_hFile != INVALID_HANDLE_VALUE))
	{
		if (Context.m_bSave)
		{
			dwTransmis = fwrite(lpData,1,lDataSize,Context.m_hFile);
		}  
		else
		{
			dwTransmis = fread(lpData,1,lDataSize,Context.m_hFile);
		}

	}

	if (Context.m_pBuffCurrent && (Context.m_iSize >= lDataSize))
	{
		if (Context.m_bSave) memcpy(Context.m_pBuffCurrent,lpData,lDataSize);
		else memcpy(lpData,Context.m_pBuffCurrent,lDataSize);
		Context.m_pBuffCurrent += lDataSize;
		Context.m_iSize -= lDataSize;
		dwTransmis = lDataSize;
	}

	return ((lDataSize == 0) || (dwTransmis > 0));
}

BOOL CElemBase::bLoadSaveLabel(CContext &Context)
{
	BOOL bReturn;
	long lDataSize;

	EnterCriticalSection(&m_hCriticalSection);
	if (Context.m_bSave) lDataSize = (lstrlen(m_pcLabel) + 1) * sizeof(TCHAR);
	bReturn = bLoadSaveInt32(lDataSize,Context);
	if (!Context.m_bSave) bReturn = bSetLabelLength(lDataSize);
	if (bReturn) bReturn = bLoadSave(m_pcLabel,lDataSize,Context);
	LeaveCriticalSection(&m_hCriticalSection);

	if (bReturn) TRACE_DEBUG(eInformation,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Info:label = %s"),szGetLabel());
	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

BOOL CElemBase::bLoadSaveFloat(float &fData,CContext &Context)
{
	BOOL bReturn;
	short nVal;
	BYTE ucVal;

	EnterCriticalSection(&m_hCriticalSection);
	if (Context.m_bModeInteger && Context.m_bForceWord)
	{
		if (Context.m_bSave) nVal = (short)fData;
		bReturn = bLoadSaveInt16(nVal,Context);
		if (bReturn && !Context.m_bSave) fData = nVal;
	}
	else if (Context.m_bModeInteger && Context.m_bForceByte)
	{
		if (Context.m_bSave) ucVal = (BYTE)fData;
		bReturn = bLoadSaveInt8(ucVal,Context);
		if (bReturn && !Context.m_bSave) fData = ucVal;
	}
	else bReturn = bLoadSave(&fData,sizeof(float),Context);
	LeaveCriticalSection(&m_hCriticalSection);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

BOOL CElemBase::bLoadSaveInt8(BYTE &ucData,CContext &Context)
{
	BOOL bReturn;
	short nVal;

	EnterCriticalSection(&m_hCriticalSection);
	if (/*Context.m_bModeInteger && */Context.m_bForceWord)
	{
		if (Context.m_bSave) nVal = (short)ucData;
		bReturn = bLoadSaveInt16(nVal,Context);
		if (bReturn && !Context.m_bSave) ucData = (BYTE)nVal;
	}
	else bReturn = bLoadSave(&ucData,sizeof(ucData),Context);
	LeaveCriticalSection(&m_hCriticalSection);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}

BOOL CElemBase::bLoadSaveInt16(short &nData,CContext &Context)
{
	BOOL bReturn;
	BYTE ucVal;
	short nDataMemo;

	EnterCriticalSection(&m_hCriticalSection);
	if (Context.m_bModeInteger && Context.m_bForceByte)
	{
		if (Context.m_bSave) ucVal = (BYTE)nData;
		bReturn = bLoadSaveInt8(ucVal,Context);
		if (bReturn && !Context.m_bSave) nData = ucVal;
	}
	else 
	{
		nDataMemo = nData;
		if (Context.m_bSave) nDataMemo = MAKEWORD(HIBYTE(nData),LOBYTE(nData));
		bReturn = bLoadSave(&nDataMemo,sizeof(nDataMemo),Context);
		if (!Context.m_bSave) nData = MAKEWORD(HIBYTE(nDataMemo),LOBYTE(nDataMemo));
	}
	LeaveCriticalSection(&m_hCriticalSection);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}

BOOL CElemBase::bLoadSaveUInt16(unsigned short &nData,CContext &Context)
{
	BOOL bReturn;
	BYTE ucVal;

	EnterCriticalSection(&m_hCriticalSection);
	if (Context.m_bModeInteger && Context.m_bForceByte)
	{
		if (Context.m_bSave) ucVal = (BYTE)nData;
		bReturn = bLoadSaveInt8(ucVal,Context);
		if (bReturn && !Context.m_bSave) nData = ucVal;
	}
	else 
	{
		if (Context.m_bSave) nData = MAKEWORD(HIBYTE(nData),LOBYTE(nData));
		bReturn = bLoadSave(&nData,sizeof(nData),Context);
		if (!Context.m_bSave) nData = MAKEWORD(HIBYTE(nData),LOBYTE(nData));
	}
	LeaveCriticalSection(&m_hCriticalSection);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}

BOOL CElemBase::bLoadSaveInt32(long &iData,CContext &Context)
{
	BOOL bReturn;
	short nVal;

	EnterCriticalSection(&m_hCriticalSection);
	if (Context.m_bModeInteger && Context.m_bForceWord)
	{
		if (Context.m_bSave) nVal = (short)iData;
		bReturn = bLoadSaveInt16(nVal,Context);
		if (bReturn && !Context.m_bSave) iData = nVal;
	}
	else bReturn = bLoadSave(&iData,sizeof(long),Context);
	LeaveCriticalSection(&m_hCriticalSection);
	
	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}

BOOL CElemBase::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;

	if (Context.m_bAllData)
	{
		bReturn = bLoadSaveInt32(m_iType,Context);
		if (bReturn) bReturn = bLoadSaveLabel(Context);
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}

int CElemBase::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	EnterCriticalSection(&m_hCriticalSection);
	if (Context.m_bAllData)
	{
		iSize = sizeof(m_iType);
		iSize += sizeof(m_iLabelLength);
		iSize += (lstrlen(m_pcLabel) + 1) * sizeof(TCHAR);//m_iLabelLength;
	}
	LeaveCriticalSection(&m_hCriticalSection);
	return iSize;
}


BOOL CElemBase::bSetConfig(LPTSTR pszText)
{
	BOOL bReturn = FALSE;
	TCHAR szSeps[]   = _T("|");
	TCHAR *pcToken;

	// ID
	pcToken = _tcstok( pszText, szSeps ); 
	if (pcToken != NULL)
	{
		// on saute la mise à jour de ce champs (champs d'info uniquement)
		//_stscanf(pcToken,_T("%x"),&m_iType);
		pcToken = _tcstok( NULL, szSeps ); 
	}
	// label
	if (pcToken != NULL)
	{
		SetLabel(pcToken);
		bReturn = TRUE;
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

LPTSTR CElemBase::szGetConfig(LPTSTR pszText, int iSizeMax)
{
	TCHAR szSeps[]   = _T("|");

	// ID
	_stprintf(pszText,_T("0x%08x"),iGetType());
	lstrcat(pszText,szSeps);
	// label
	lstrcat(pszText,szGetLabel());

	return pszText;
}


/*(@!*****************************************************************************************
* Nom     : CElemList
* Role    : Collection de valeur numerique
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemList::CElemList(int iNbrElem):CElemBase()
{
	m_iType = MAKE_ID(0xFF,0xFF,eTYPE_LIST,0xFF);
	SetLabel(_T("CElemList"));
	m_iSize = 0;
	m_iSizeMax = 0;
	m_ppElem = NULL;
	if (iNbrElem > 0)
	{
		m_ppElem = (CElemBase**)malloc(iNbrElem * sizeof(CElemBase*));
		if (m_ppElem != NULL)
		{
			memset(m_ppElem,0,iNbrElem * sizeof(CElemBase*));
			m_iSizeMax = iNbrElem; 
		}
	}
}

CElemList::~CElemList()
{
	RemoveAll();
	if (m_ppElem) free(m_ppElem);
	m_ppElem = NULL;
	DeleteCriticalSection(&m_hCriticalSection);
}

void CElemList::RemoveAll()
{
	int i;

	EnterCriticalSection(&m_hCriticalSection);
	i = m_iSize;
	while (i-- > 0)
	{
		if (m_ppElem[i])
		{
			if (m_ppElem[i]->bIsAutoDelete()) 
			{
				m_ppElem[i]->RemoveAll();
				delete m_ppElem[i];
				m_ppElem[i] = NULL;
			}
		}
	}
	m_iSize = 0;
	LeaveCriticalSection(&m_hCriticalSection);
}

CElemBase *CElemList::pGetAt(int iPos)
{
	CElemBase *pElem = NULL;

	EnterCriticalSection(&m_hCriticalSection);
	if ((iPos < m_iSize) && (iPos > -1))
	{
		pElem = m_ppElem[iPos];
	}
	LeaveCriticalSection(&m_hCriticalSection);
	return pElem;
}

BOOL CElemList::bSetAt(int iPos,CElemBase *pElem)
{
	BOOL bReturn = FALSE;

	EnterCriticalSection(&m_hCriticalSection);
	if ((iPos < m_iSize) && (iPos > -1))
	{
		m_ppElem[iPos] = pElem;
		bReturn = TRUE;
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	LeaveCriticalSection(&m_hCriticalSection);

	return bReturn;
}

CElemBase *CElemList::pAdd(CElemBase* pElem)
{
	EnterCriticalSection(&m_hCriticalSection);
	if (m_iSize < m_iSizeMax)
	{
		m_ppElem[m_iSize] = pElem;
		m_iSize++;
	}
	else pElem = NULL;
	LeaveCriticalSection(&m_hCriticalSection);
	return pElem;
}

BOOL CElemList::bAddAndRollText(LPCTSTR szText)
{
	int i;
	BOOL bReturn = TRUE;
	CElemBase *pElemMemo;

	EnterCriticalSection(&m_hCriticalSection);
	if (pElemMemo = pGetAt(m_iSize-1))
	{
		i = m_iSize-1;
		while ((i-- > 0) && bReturn)
		{
			bReturn = bSetAt(i+1,pGetAt(i));
		}
		if (bReturn)
		{
			bReturn = bSetAt(0,pElemMemo);
			if (bReturn) pElemMemo->SetLabel(szText);
		}
	}
	LeaveCriticalSection(&m_hCriticalSection);
	
	return (bReturn);
}

BOOL CElemList::bSerialize(CContext &Context)
{
	int i;
	BOOL bReturn = TRUE;
	
	EnterCriticalSection(&m_hCriticalSection);
	if (Context.m_bAllData)
	{
		bReturn = CElemBase::bSerialize(Context);
		if (bReturn) bReturn = bLoadSaveInt32(m_iSizeMax,Context);
		if (bReturn) bReturn = bLoadSaveInt32(m_iSize,Context);
	}
	for (i = 0; (bReturn) && (i < m_iSize); i++)
	{
		if (m_ppElem[i] == NULL)
		{
			if (m_ppElem[i] = new CElemBase()) m_ppElem[i]->SetAutoDelete(TRUE);
		}
		bReturn = (m_ppElem[i] != NULL);
		if (bReturn)
		{
			bReturn = m_ppElem[i]->bSerialize(Context);
		}
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	LeaveCriticalSection(&m_hCriticalSection);

	return bReturn;
}

int CElemList::iGetStreamSize(CContext &Context)
{
	int i;
	int iSize = 0;
	
	EnterCriticalSection(&m_hCriticalSection);
	if (Context.m_bAllData)
	{
		iSize = CElemBase::iGetStreamSize(Context);
		iSize += sizeof(m_iSizeMax);
		iSize += sizeof(m_iSize);
	}
	for (i = 0; i < m_iSize; i++)
	{
		if (m_ppElem[i])
		{
			iSize += m_ppElem[i]->iGetStreamSize(Context);
		}
	}
	LeaveCriticalSection(&m_hCriticalSection);
	return iSize;
}

BOOL CElemList::bSetConfig(LPTSTR pszText)
{
	BOOL bReturn = TRUE;
	TCHAR szSeps[]   = _T("|");
	TCHAR *pcToken;
	int i;
	CElemBase *pElem;

	// ID
	pcToken = _tcstok( pszText, szSeps ); 
	if (pcToken != NULL)
	{
		// on saute la mise à jour de ce champs (champs d'info uniquement)
		//_stscanf(pcToken,_T("%x"),&m_iType);
		pcToken = _tcstok( NULL, szSeps ); 
	}
	// label
	if (pcToken != NULL)
	{
		SetLabel(pcToken);
		pcToken = _tcstok( NULL, szSeps ); 
	}
	// les valeurs: il faut que les variables existent dans la liste
	i = 0;
	while (bReturn && (pcToken != NULL))
	{
		pElem = (CElemNbr*)pGetAt(i++);
		bReturn = (pElem != NULL);
		if (bReturn)
		{
			bReturn = pElem->bSetTextVal(pcToken);
			pcToken = _tcstok( NULL, szSeps ); 
		}
	}
	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

LPTSTR CElemList::szGetConfig(LPTSTR pszText, int iSizeMax)
{
	TCHAR szSeps[]   = _T("|");
	TCHAR szTemp[CONV_BUFFER_SIZE];
	int i;
	int iCount;
	CElemBase *pElem;

	// ID
	_stprintf(pszText,_T("0x%08x"),iGetType());
	lstrcat(pszText,szSeps);
	// label
	lstrcat(pszText,szGetLabel());
	lstrcat(pszText,szSeps);
	// les valeurs
	iCount = iGetCount();
	for (i = 0; i < iCount;i++)
	{
		pElem = (CElemNbr*)pGetAt(i);
		if (pElem)
		{
			pElem->GetVal(szTemp,CONV_BUFFER_SIZE);
			lstrcat(pszText,szTemp);
		}
		else lstrcat(pszText,_T("0"));
		if (i < iCount - 1) lstrcat(pszText,szSeps);
	}

	return pszText;
}


/*(@!*****************************************************************************************
* Nom     : CElemFieldBit8
* Role    : Collection de 8 bits
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemFieldBit8::CElemFieldBit8():CElemList(8)
{
	m_iType = MAKE_ID(0xFF,0xFF,eTYPE_BITFIELD8,0xFF);
	SetLabel(_T("CElemFieldBit8"));
}

CElemFieldBit8::~CElemFieldBit8()
{
}


BOOL CElemFieldBit8::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;
	stBitField8 BitField8;
	
	BitField8.value = 0;
	if (Context.m_bAllData)
	{
		bReturn = CElemList::bSerialize(Context);
	}
	else
	{
		if (Context.m_bSave)
		{
			BitField8.bitfield.bBit0 = m_ppElem[0] ? ((CElemInt8*)m_ppElem[0])->ucGetVal() : 0;
			BitField8.bitfield.bBit1 = m_ppElem[1] ? ((CElemInt8*)m_ppElem[1])->ucGetVal() : 0;
			BitField8.bitfield.bBit2 = m_ppElem[2] ? ((CElemInt8*)m_ppElem[2])->ucGetVal() : 0;
			BitField8.bitfield.bBit3 = m_ppElem[3] ? ((CElemInt8*)m_ppElem[3])->ucGetVal() : 0;
			BitField8.bitfield.bBit4 = m_ppElem[4] ? ((CElemInt8*)m_ppElem[4])->ucGetVal() : 0;
			BitField8.bitfield.bBit5 = m_ppElem[5] ? ((CElemInt8*)m_ppElem[5])->ucGetVal() : 0;
			BitField8.bitfield.bBit6 = m_ppElem[6] ? ((CElemInt8*)m_ppElem[6])->ucGetVal() : 0;
			BitField8.bitfield.bBit7 = m_ppElem[7] ? ((CElemInt8*)m_ppElem[7])->ucGetVal() : 0;
			bReturn = bLoadSaveInt8(BitField8.value,Context);
		}
		else
		{
			if (bReturn = bLoadSaveInt8(BitField8.value,Context))
			{
				if (m_ppElem[0]) ((CElemInt8*)m_ppElem[0])->bSetVal(BitField8.bitfield.bBit0);
				if (m_ppElem[1]) ((CElemInt8*)m_ppElem[1])->bSetVal(BitField8.bitfield.bBit1);
				if (m_ppElem[2]) ((CElemInt8*)m_ppElem[2])->bSetVal(BitField8.bitfield.bBit2);
				if (m_ppElem[3]) ((CElemInt8*)m_ppElem[3])->bSetVal(BitField8.bitfield.bBit3);
				if (m_ppElem[4]) ((CElemInt8*)m_ppElem[4])->bSetVal(BitField8.bitfield.bBit4);
				if (m_ppElem[5]) ((CElemInt8*)m_ppElem[5])->bSetVal(BitField8.bitfield.bBit5);
				if (m_ppElem[6]) ((CElemInt8*)m_ppElem[6])->bSetVal(BitField8.bitfield.bBit6);
				if (m_ppElem[7]) ((CElemInt8*)m_ppElem[7])->bSetVal(BitField8.bitfield.bBit7);
			}
		}
	}

	if (bReturn) TRACE_DEBUG(eInformation,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Info: %s, BitField8 = 0x%x "),szGetLabel(),BitField8.value);
	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}

int CElemFieldBit8::iGetStreamSize(CContext &Context)
{
	int iSize = 0;
	
	if (Context.m_bAllData)
	{
		iSize = CElemList::iGetStreamSize(Context);
	}
	else
	{
		iSize = sizeof(stBitField8);
	}
	return iSize;
}

BOOL CElemFieldBit8::bSetConfig(LPTSTR pszText,int &iCurrentPos,CListStream *pListStream)
{
	BOOL bReturn = FALSE;
	TCHAR szSeps[]   = _T("|");
	TCHAR *pcToken;
	int i;
	long lID = 0;
	CElemBase *pElem = NULL;

	pszText += iCurrentPos;
	//iCurrentPos = 0;

	pcToken = _tcstok(pszText, szSeps ); 
	if (pcToken)
	{
		bReturn = TRUE;
		iCurrentPos += (lstrlen(pcToken) + 1);
		SetAutoDelete(TRUE);
		for (i = 0; bReturn && (i < 8); i++)
		{
			if ((pcToken != NULL) && bReturn)
			{
				iCurrentPos += (lstrlen(pcToken) + 1);
				lID = 0;
				pElem = NULL;
				// valeur de ref à une variable interne
				if ((_tcsstr(pcToken,_T("0x")) != NULL) || (_tcsstr(pcToken,_T("0X")) != NULL))
				{
					_stscanf(pcToken,_T("%x"),&lID);
					if (bReturn = (NUM_TYPE(lID) == eTYPE_INT8))
					{
						pElem = pListStream->pFindElemFromID(lID);
						bReturn = (pElem != NULL);
					}
					else 
					{
						TRACE_DEBUG(eError,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),_T("les références doivent être du type eTYPE_INT8 dans une trame JBUS1_2"));
					}
				}
				if (pElem == NULL)
				{
					pElem = new CElemInt8();
					bReturn = (pElem != NULL);
					if (bReturn)
					{
						pElem->SetAutoDelete(TRUE);
						if (pcToken) bReturn = ((CElemInt8*)pElem)->bSetTextVal(pcToken);
						else bReturn = ((CElemInt8*)pElem)->bSetVal((BYTE)0);
					}
					TRACE_DEBUG(eInformation,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Info: %s"),_T("référence inconnu, creation d'une valeur par defaut"));
				}
				pcToken = _tcstok( NULL, szSeps ); 
			}
			else
			{
				pElem = new CElemInt8();
				bReturn = (pElem != NULL);
				if (bReturn)
				{
					pElem->SetAutoDelete(TRUE);
					if (pcToken) bReturn = ((CElemInt8*)pElem)->bSetTextVal(pcToken);
					else bReturn = ((CElemInt8*)pElem)->bSetVal((BYTE)0);
				}
			}
			if (bReturn)
			{
				pAdd(pElem);
			}
		}
	}

	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	}
	return bReturn;
}

LPTSTR CElemFieldBit8::szGetConfig(LPTSTR pszText, int iSizeMax)
{
	TCHAR szSeps[]   = _T("|");
	TCHAR szTemp[CONV_BUFFER_SIZE];
	int i;
	CElemInt8 *pElem = NULL;

	for (i = 0; (i < 8); i++)
	{
		pElem = (CElemInt8*)pGetAt(i);
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
			lstrcat(pszText,_T(" "));
		}
	}
	return pszText;
}


/*(@!*****************************************************************************************
* Nom     : CElemFieldBit16
* Role    : Collection de 16 bits
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemFieldBit16::CElemFieldBit16():CElemList(16)
{
	m_iType = MAKE_ID(0xFF,0xFF,eTYPE_BITFIELD16,0xFF);
	SetLabel(_T("CElemFieldBit16"));
}

CElemFieldBit16::~CElemFieldBit16()
{
}


BOOL CElemFieldBit16::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;
	stBitField16 BitField16;
	
	BitField16.value = 0;
	if (Context.m_bAllData)
	{
		bReturn = CElemList::bSerialize(Context);
	}
	else
	{
		if (Context.m_bSave)
		{
			BitField16.bitfield.bBit0 = m_ppElem[0] ? ((CElemInt8*)m_ppElem[0])->ucGetVal() : 0;
			BitField16.bitfield.bBit1 = m_ppElem[1] ? ((CElemInt8*)m_ppElem[1])->ucGetVal() : 0;
			BitField16.bitfield.bBit2 = m_ppElem[2] ? ((CElemInt8*)m_ppElem[2])->ucGetVal() : 0;
			BitField16.bitfield.bBit3 = m_ppElem[3] ? ((CElemInt8*)m_ppElem[3])->ucGetVal() : 0;
			BitField16.bitfield.bBit4 = m_ppElem[4] ? ((CElemInt8*)m_ppElem[4])->ucGetVal() : 0;
			BitField16.bitfield.bBit5 = m_ppElem[5] ? ((CElemInt8*)m_ppElem[5])->ucGetVal() : 0;
			BitField16.bitfield.bBit6 = m_ppElem[6] ? ((CElemInt8*)m_ppElem[6])->ucGetVal() : 0;
			BitField16.bitfield.bBit7 = m_ppElem[7] ? ((CElemInt8*)m_ppElem[7])->ucGetVal() : 0;
			BitField16.bitfield.bBit8 = m_ppElem[8] ? ((CElemInt8*)m_ppElem[8])->ucGetVal() : 0;
			BitField16.bitfield.bBit9 = m_ppElem[9] ? ((CElemInt8*)m_ppElem[9])->ucGetVal() : 0;
			BitField16.bitfield.bBit10 = m_ppElem[10] ? ((CElemInt8*)m_ppElem[10])->ucGetVal() : 0;
			BitField16.bitfield.bBit11 = m_ppElem[11] ? ((CElemInt8*)m_ppElem[11])->ucGetVal() : 0;
			BitField16.bitfield.bBit12 = m_ppElem[12] ? ((CElemInt8*)m_ppElem[12])->ucGetVal() : 0;
			BitField16.bitfield.bBit13 = m_ppElem[13] ? ((CElemInt8*)m_ppElem[13])->ucGetVal() : 0;
			BitField16.bitfield.bBit14 = m_ppElem[14] ? ((CElemInt8*)m_ppElem[14])->ucGetVal() : 0;
			BitField16.bitfield.bBit15 = m_ppElem[15] ? ((CElemInt8*)m_ppElem[15])->ucGetVal() : 0;
			bReturn = bLoadSaveUInt16(BitField16.value,Context);
		}
		else
		{
			if (bReturn = bLoadSaveUInt16(BitField16.value,Context))
			{
				if (m_ppElem[0]) ((CElemInt8*)m_ppElem[0])->bSetVal(BitField16.bitfield.bBit0);
				if (m_ppElem[1]) ((CElemInt8*)m_ppElem[1])->bSetVal(BitField16.bitfield.bBit1);
				if (m_ppElem[2]) ((CElemInt8*)m_ppElem[2])->bSetVal(BitField16.bitfield.bBit2);
				if (m_ppElem[3]) ((CElemInt8*)m_ppElem[3])->bSetVal(BitField16.bitfield.bBit3);
				if (m_ppElem[4]) ((CElemInt8*)m_ppElem[4])->bSetVal(BitField16.bitfield.bBit4);
				if (m_ppElem[5]) ((CElemInt8*)m_ppElem[5])->bSetVal(BitField16.bitfield.bBit5);
				if (m_ppElem[6]) ((CElemInt8*)m_ppElem[6])->bSetVal(BitField16.bitfield.bBit6);
				if (m_ppElem[7]) ((CElemInt8*)m_ppElem[7])->bSetVal(BitField16.bitfield.bBit7);
				if (m_ppElem[8]) ((CElemInt8*)m_ppElem[8])->bSetVal(BitField16.bitfield.bBit8);
				if (m_ppElem[9]) ((CElemInt8*)m_ppElem[9])->bSetVal(BitField16.bitfield.bBit9);
				if (m_ppElem[10]) ((CElemInt8*)m_ppElem[10])->bSetVal(BitField16.bitfield.bBit10);
				if (m_ppElem[11]) ((CElemInt8*)m_ppElem[11])->bSetVal(BitField16.bitfield.bBit11);
				if (m_ppElem[12]) ((CElemInt8*)m_ppElem[12])->bSetVal(BitField16.bitfield.bBit12);
				if (m_ppElem[13]) ((CElemInt8*)m_ppElem[13])->bSetVal(BitField16.bitfield.bBit13);
				if (m_ppElem[14]) ((CElemInt8*)m_ppElem[14])->bSetVal(BitField16.bitfield.bBit14);
				if (m_ppElem[15]) ((CElemInt8*)m_ppElem[15])->bSetVal(BitField16.bitfield.bBit15);
			}
		}
	}

	if (bReturn) TRACE_DEBUG(eInformation,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Info: %s, BitField16 = 0x%x "),szGetLabel(),BitField16.value);
	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());

	return bReturn;
}

int CElemFieldBit16::iGetStreamSize(CContext &Context)
{
	int iSize = 0;
	
	if (Context.m_bAllData)
	{
		iSize = CElemList::iGetStreamSize(Context);
	}
	else
	{
		iSize = sizeof(stBitField16);
	}
	return iSize;
}

/*(@!*****************************************************************************************
* Nom     : CElemNbr
* Role    : element de base de gestion des nombres
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemNbr::CElemNbr():CElemBase()
{
	m_szUnit.SetLabel(_T("V"));
	m_szFormat.SetLabel(_T("%08x"));
}

CElemNbr::~CElemNbr()
{
}


BOOL CElemNbr::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;

	if (Context.m_bAllData)
	{
		bReturn = CElemBase::bSerialize(Context);
		if (bReturn) bReturn = m_szUnit.bSerialize(Context);
		if (bReturn) bReturn = m_szFormat.bSerialize(Context);
	}
	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

int CElemNbr::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	if (Context.m_bAllData)
	{
		iSize = CElemBase::iGetStreamSize(Context);
		iSize += m_szUnit.iGetStreamSize(Context);
		iSize += m_szFormat.iGetStreamSize(Context);
	}
	return iSize;
}

BOOL CElemNbr::bSetConfig(LPTSTR pszText)
{
	BOOL bReturn = FALSE;
	TCHAR szSeps[]   = _T("|");
	TCHAR *pcToken;

	// ID
	
	pcToken = _tcstok( pszText, szSeps );
	
	if (pcToken != NULL)
	{
		// on saute la mise à jour de ce champs (champs d'info uniquement)
		//_stscanf(pcToken,_T("%x"),&m_iType);
		pcToken = _tcstok( NULL, szSeps ); 
	}
	// label
	if (pcToken != NULL)
	{
		SetLabel(pcToken);
		pcToken = _tcstok( NULL, szSeps ); 
	}
	// la valeur
	if (pcToken != NULL)
	{
		bReturn = bSetTextVal(pcToken);
		pcToken = _tcstok( NULL, szSeps ); 
	}
	// l'unité
	if (pcToken != NULL)
	{
		m_szUnit.SetLabel(pcToken);
		pcToken = _tcstok( NULL, szSeps ); 
	}
	// le format
	if (pcToken != NULL)
	{
		m_szFormat.SetLabel(pcToken);
		pcToken = _tcstok( NULL, szSeps ); 
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

LPTSTR CElemNbr::szGetConfig(LPTSTR pszText, int iSizeMax)
{
	TCHAR szSeps[]   = _T("|");
	TCHAR szTemp[CONV_BUFFER_SIZE];

	// ID
	_stprintf(pszText,_T("0x%08x"),iGetType());
	lstrcat(pszText,szSeps);
	// label
	lstrcat(pszText,szGetLabel());
	lstrcat(pszText,szSeps);
	// la valeur
	GetVal(szTemp,CONV_BUFFER_SIZE);
	lstrcat(pszText,szTemp);
	lstrcat(pszText,szSeps);
	// unité
	lstrcat(pszText,m_szUnit.szGetLabel());
	lstrcat(pszText,szSeps);
	// le format
	lstrcat(pszText,m_szFormat.szGetLabel());

	return pszText;
}

/*(@!*****************************************************************************************
* Nom     : CElemFloat
* Role    : element de la base de type float
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemFloat::CElemFloat():CElemNbr()
{
	m_fVal = 0;
	m_iType = MAKE_ID(0xFF,0xFF,eTYPE_FLOAT,0xFF);
	SetLabel(_T("FLOAT"));
	m_szFormat.SetLabel(_T("%7.3f"));
}

CElemFloat::~CElemFloat()
{
}


BOOL CElemFloat::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;

	bReturn = CElemNbr::bSerialize(Context);
	if (bReturn) bReturn = bLoadSaveFloat(m_fVal,Context);
	
	if (bReturn) TRACE_DEBUG(eInformation,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Info: %s, m_fVal = %f "),szGetLabel(),m_fVal);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

int CElemFloat::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	iSize = CElemNbr::iGetStreamSize(Context);
	if (Context.m_bModeInteger && Context.m_bForceByte) iSize += sizeof(BYTE);
	else if (Context.m_bForceWord && Context.m_bModeInteger) iSize += sizeof(short);
	else iSize += sizeof(m_fVal);
	return iSize;
}

//Surchage des opérateurs de calcul pour la classe CElemFloat
void CElemFloat::operator +=(CElemFloat argefOperande)
{
	this->m_fVal += argefOperande.fGetVal();
}
void CElemFloat::operator +=(float argfOperande)
{
	this->m_fVal += argfOperande;
}
void CElemFloat::operator =(CElemFloat argefOperande)
{
	this->m_fVal = argefOperande.fGetVal();
}
void CElemFloat::operator =(float argfOperande)
{
	this->m_fVal = argfOperande;
}


/*(@!*****************************************************************************************
* Nom     : CElemInt8
* Role    : element de la base de type int8
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemInt8::CElemInt8():CElemNbr()
{
	m_ucVal = 0;
	m_iType = MAKE_ID(0xFF,0xFF,eTYPE_INT8,0xFF);
	SetLabel(_T("INT8"));
	m_szFormat.SetLabel(_T("%d"));
}

CElemInt8::~CElemInt8()
{
}



BOOL CElemInt8::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;

	bReturn = CElemNbr::bSerialize(Context);
	if (bReturn) bReturn = bLoadSaveInt8(m_ucVal,Context);

	if (bReturn) TRACE_DEBUG(eInformation,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Info: %s, m_ucVal = %d "),szGetLabel(),m_ucVal);
	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

int CElemInt8::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	iSize = CElemNbr::iGetStreamSize(Context);
	if (/*Context.m_bModeInteger && */Context.m_bForceWord) iSize += sizeof(short);
	else iSize += sizeof(m_ucVal);
	return iSize;
}

/*(@!*****************************************************************************************
* Nom     : CElemInt16
* Role    : element de la base de type int16
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemInt16::CElemInt16():CElemNbr()
{
	m_nVal = 0;
	m_iType = MAKE_ID(0xFF,0xFF,eTYPE_INT16,0xFF);
	SetLabel(_T("INT16"));
	m_szFormat.SetLabel(_T("%d"));
}

CElemInt16::~CElemInt16()
{
}


BOOL CElemInt16::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;

	bReturn = CElemNbr::bSerialize(Context);
	if (bReturn) bReturn = bLoadSaveInt16(m_nVal,Context);

	if (bReturn) TRACE_DEBUG(eInformation,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Info: %s, m_nVal = %d "),szGetLabel(),m_nVal);
	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

int CElemInt16::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	iSize = CElemNbr::iGetStreamSize(Context);
	if (Context.m_bModeInteger && Context.m_bForceByte) iSize += sizeof(BYTE);
	else iSize += sizeof(m_nVal);
	return iSize;
}

/*(@!*****************************************************************************************
* Nom     : CElemInt32
* Role    : element de la base de type int32
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemInt32::CElemInt32():CElemNbr()
{
	m_lVal = 0;
	m_iType = MAKE_ID(0xFF,0xFF,eTYPE_INT32,0xFF);
	SetLabel(_T("INT32"));
	m_szFormat.SetLabel(_T("%d"));
}

CElemInt32::~CElemInt32()
{
}

BOOL CElemInt32::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;

	bReturn = CElemNbr::bSerialize(Context);
	if (bReturn) bReturn = bLoadSaveInt32(m_lVal,Context);

	if (bReturn) TRACE_DEBUG(eInformation,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Info: %s, m_lVal = %d "),szGetLabel(),m_lVal);
	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

int CElemInt32::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	iSize = CElemNbr::iGetStreamSize(Context);
	if (Context.m_bModeInteger && Context.m_bForceByte) iSize += sizeof(BYTE);
	else if (Context.m_bModeInteger && Context.m_bForceWord) iSize += sizeof(short);
	else iSize += sizeof(m_lVal);
	return iSize;
}


