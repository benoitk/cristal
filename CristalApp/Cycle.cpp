#include "stdafx.h"
#include "network.h"


#define NBR_RETRY_EXCHANGE		3  //le nbr de retry reellement réalisé est = NBR_RETRY_EXCHANGE + 1
#define DW_DELAI_INTER_TRAME	100  // delai entre 2 emissions de trame 
/*(@!*****************************************************************************************
* Nom     : CElemCycleStep
* Role    : definition du traitement sur un step du cycle
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemCycleStep::CElemCycleStep() : CElemBase(),m_ListExchangeBegin(NBR_EXCHANGE_JBUS_MAX),m_ListExchangeEnd(NBR_EXCHANGE_JBUS_MAX),m_ListExchangeRealTime(NBR_EXCHANGE_JBUS_MAX)
{
	m_iType = MAKE_ID(0xFF,0xFF,eTYPE_CYCLE_STEP,0xFF);
	SetLabel(_T("CElemCycleStep"));
	m_ListExchangeBegin.SetLabel(_T("CListExchangeBegin"));
	m_ListExchangeEnd.SetLabel(_T("CListExchangeEnd"));
	m_ListExchangeRealTime.SetLabel(_T("CListExchangeRealTime"));
}

CElemCycleStep::~CElemCycleStep()
{
	RemoveAll();
}

void CElemCycleStep::RemoveAll()
{
	m_Step.bSetVal((short)0);
	m_ListExchangeBegin.RemoveAll();
	m_ListExchangeEnd.RemoveAll();
	m_ListExchangeRealTime.RemoveAll();
}

BOOL CElemCycleStep::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;

	bReturn = CElemBase::bSerialize(Context);
	if (bReturn) bReturn = m_Step.bSerialize(Context);
	if (bReturn) bReturn = m_ListExchangeBegin.bSerialize(Context);
	if (bReturn) bReturn = m_ListExchangeEnd.bSerialize(Context);
	if (bReturn) bReturn = m_ListExchangeRealTime.bSerialize(Context);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

int CElemCycleStep::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	iSize = CElemBase::iGetStreamSize(Context);
	iSize += m_Step.iGetStreamSize(Context);
	iSize += m_ListExchangeBegin.iGetStreamSize(Context);
	iSize += m_ListExchangeEnd.iGetStreamSize(Context);
	iSize += m_ListExchangeRealTime.iGetStreamSize(Context);

	return iSize;
}

BOOL CElemCycleStep::bReadConfigExchangeJbus(LPTSTR pszRub, LPTSTR pszKeyRQ,LPTSTR pszKeyRP,LPCTSTR pszFileName,CElemList *pListExchange,CListStream *pListStream)
{
	BOOL bReturn = FALSE;
	TCHAR szText[MAX_PATH*2];
	CElemExchangeJbus *pExchangeJbus = NULL;
	int iCurrentPos;

	if (pExchangeJbus = new CElemExchangeJbus())
	{
		_stprintf(szText,_T("CElemCycleStep : (PAS=%s) -> %s - %s"),pszRub, pszKeyRQ,pszKeyRP);
		pExchangeJbus->SetLabel(szText);
		pExchangeJbus->SetAutoDelete(TRUE);

		if (dwGetPrivateProfileString(pszRub,pszKeyRQ,_T(""),szText,sizeof(szText)/sizeof(TCHAR),pszFileName) > 0)
		{
			// requete
			iCurrentPos = 0;
			if (bReturn = pExchangeJbus->bSetConfig(TRUE,szText,iCurrentPos,pListStream))
			{
				iCurrentPos = 0;
				// reponse
				if (dwGetPrivateProfileString(pszRub,pszKeyRP,_T(""),szText,sizeof(szText)/sizeof(TCHAR),pszFileName) > 0)
				{
					if (bReturn = pExchangeJbus->bSetConfig(FALSE,szText,iCurrentPos,pListStream))
					{
						bReturn = (pListExchange->pAdd(pExchangeJbus) != NULL);
						pExchangeJbus = NULL;
					}
				}
			}
		}
	}
	if (pExchangeJbus) delete pExchangeJbus;
	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	}

//	delete [] szText;
	return bReturn;
}


BOOL CElemCycleStep::bReadConfig(LPTSTR pszRub, LPCTSTR pszFileName,CListStream *pListStream)
{
	BOOL bReturn = TRUE;
	TCHAR szKeyRQ[MAX_PATH];
	TCHAR szKeyRP[MAX_PATH];
	TCHAR szText[MAX_PATH];
	int i;
	int iNbrTrameBegin = 0;
	int iNbrTrameEnd = 0;
	int iNbrTrameRealTime = 0;

	RemoveAll();
	// label
	dwGetPrivateProfileString(pszRub,_T("Label"),_T(""),szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (lstrlen(szText) == 0) _stprintf(szText,_T("CElemCycleStep : (PAS=%s)"),pszRub);
	SetLabel(szText);
	// nbr de trame begin
	iNbrTrameBegin = iGetPrivateProfileInt(pszRub,_T("NbrBegin"),0,pszFileName);
	for (i = 0;bReturn && (i < iNbrTrameBegin);i++)
	{
		_stprintf(szKeyRQ,_T("BeginRQ%d"),i+1);
		_stprintf(szKeyRP,_T("BeginRP%d"),i+1);
		bReturn = bReadConfigExchangeJbus(pszRub, szKeyRQ,szKeyRP,pszFileName,&m_ListExchangeBegin,pListStream);
	}
	// nbr de trame end
	iNbrTrameEnd = iGetPrivateProfileInt(pszRub,_T("NbrEnd"),0,pszFileName);
	for (i = 0;bReturn && (i < iNbrTrameEnd);i++)
	{
		_stprintf(szKeyRQ,_T("EndRQ%d"),i+1);
		_stprintf(szKeyRP,_T("EndRP%d"),i+1);
		bReturn = bReadConfigExchangeJbus(pszRub, szKeyRQ,szKeyRP,pszFileName,&m_ListExchangeEnd,pListStream);
	}
	// nbr de trame realtime
	iNbrTrameRealTime = iGetPrivateProfileInt(pszRub,_T("NbrRealTime"),0,pszFileName);
	for (i = 0;bReturn && (i < iNbrTrameRealTime);i++)
	{
		_stprintf(szKeyRQ,_T("RealTimeRQ%d"),i+1);
		_stprintf(szKeyRP,_T("RealTimeRP%d"),i+1);
		bReturn = bReadConfigExchangeJbus(pszRub, szKeyRQ,szKeyRP,pszFileName,&m_ListExchangeRealTime,pListStream);
	}
	if (bReturn) bReturn = m_Step.bSetTextVal(pszRub);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return (bReturn && (iNbrTrameRealTime>0 || iNbrTrameEnd>0 || iNbrTrameBegin>0));
}

BOOL CElemCycleStep::bWriteConfigExchangeJbus(LPTSTR pszRub, LPTSTR pszKeyRQ,LPTSTR pszKeyRP, int iPos ,LPCTSTR pszFileName,CElemList *pListExchange)
{
	BOOL bReturn = FALSE;
	TCHAR szKey[MAX_PATH];
	TCHAR szText[MAX_PATH*2];
	CElemExchangeJbus *pExchangeJbus = NULL;

	pExchangeJbus = (CElemExchangeJbus*)pListExchange->pGetAt(iPos);
	if (bReturn = (pExchangeJbus != NULL))
	{
		// RQ
		_stprintf(szKey,_T("%s%d"),pszKeyRQ,iPos+1);
		pExchangeJbus->m_pTrameJbusRQ->szGetConfig(szText,sizeof(szText)/sizeof(TCHAR));
		bReturn = bWritePrivateProfileString(pszRub,szKey,szText,pszFileName);
		// RP
		_stprintf(szKey,_T("%s%d"),pszKeyRP,iPos+1);
		pExchangeJbus->m_pTrameJbusRP->szGetConfig(szText,sizeof(szText)/sizeof(TCHAR));
		if (bReturn) bReturn = bWritePrivateProfileString(pszRub,szKey,szText,pszFileName);
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

BOOL CElemCycleStep::bWriteConfig(LPTSTR pszRub,LPCTSTR pszFileName)
{
	BOOL bReturn = FALSE;
	TCHAR szRub[MAX_PATH];
	int i;
	int iNbrTrame;


	if (pszRub == NULL) _stprintf(szRub,_T("%d"),m_Step.nGetVal());
	else lstrcpy(szRub,pszRub);
	// label
	bReturn = bWritePrivateProfileString(szRub,_T("Label"),szGetLabel(),pszFileName);
	// nbr de trame begin
	iNbrTrame = m_ListExchangeBegin.iGetCount();
	if (bReturn) bReturn = bWritePrivateProfileInt(szRub,_T("NbrBegin"),iNbrTrame,pszFileName);
	for (i = 0;bReturn && (i < iNbrTrame);i++)
	{
		bReturn = bWriteConfigExchangeJbus(szRub, _T("BeginRQ"),_T("BeginRP"),i ,pszFileName,&m_ListExchangeBegin);
	}
	// nbr de trame end
	iNbrTrame = m_ListExchangeEnd.iGetCount();
	if (bReturn) bReturn = bWritePrivateProfileInt(szRub,_T("NbrEnd"),iNbrTrame,pszFileName);
	for (i = 0;bReturn && (i < iNbrTrame);i++)
	{
		bReturn = bWriteConfigExchangeJbus(szRub, _T("EndRQ"),_T("EndRP"),i ,pszFileName,&m_ListExchangeEnd);
	}
	// nbr de trame realtime
	iNbrTrame = m_ListExchangeRealTime.iGetCount();
	if (bReturn) bReturn = bWritePrivateProfileInt(szRub,_T("NbrRealTime"),iNbrTrame,pszFileName);
	for (i = 0;bReturn && (i < iNbrTrame);i++)
	{
		bReturn = bWriteConfigExchangeJbus(szRub, _T("RealTimeRQ"),_T("RealTimeRP"),i ,pszFileName,&m_ListExchangeRealTime);
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

BOOL CElemCycleStep::bExecuteNumExchange(int iNum,CElemList *pListExchange, BOOL bCanRead, BOOL bCanWrite,CEnumInterface &EnumInterface)
{
	BOOL bReturn = TRUE;
	CElemExchangeJbus *pElem = NULL;
	BYTE aBuffer[10240];
	CContext Context;
	int iNbrTrame;
	long iSizeToWrite;
	long iSizeToRead;
	int iNbrRetry = NBR_RETRY_EXCHANGE;
	CThreadInterface *pInterface = NULL;

	iNbrTrame = pListExchange->iGetCount();

	if ((iNum < iNbrTrame) && (iNum > -1))
	{
		if (pElem = (CElemExchangeJbus*)pListExchange->pGetAt(iNum))
		{
			if (pElem->m_pTrameJbusRQ && pElem->m_pTrameJbusRP)
			{
				if (pElem->m_pTrameJbusRQ->bAccessAllowed(bCanRead,bCanWrite))
				{

					if (pInterface = EnumInterface.pGetSelectedInterface(pElem->m_pTrameJbusRQ->ucGetNumDest()))
					{
						iNbrRetry = NBR_RETRY_EXCHANGE;
						do
						{
							Context.Reset(TRUE,NULL,aBuffer,sizeof(aBuffer),pInterface->bGetModeInteger(),FALSE);
							iSizeToWrite = pElem->m_pTrameJbusRQ->iGetStreamSize(Context);
							if (iSizeToWrite < sizeof(aBuffer))
							{
								if (bReturn = pElem->m_pTrameJbusRQ->bSerialize(Context))
								{
									iSizeToWrite = Context.iGetCurrentSize();
									iSizeToRead = pElem->m_pTrameJbusRP->iGetStreamSize(Context);
									if (iSizeToRead < Context.m_iSize)
									{
										
										if (bReturn = pInterface->bWriteAndRead(iNum,Context.m_pBuffStart,iSizeToWrite,aBuffer,iSizeToRead,Context.m_iSize, &iSizeToRead,FALSE))
										{
											bReturn = pElem->m_pTrameJbusRP->bUpdateData(aBuffer,iSizeToRead,Context.m_bModeInteger);
											if (!bReturn) 
											{
												TRACE_DEBUG(eDebug,eCycle,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error bUpdateData: %s"),szGetLabel());
											}
											

										}
										Sleep(DW_DELAI_INTER_TRAME);// delai inter-trame
										
									}
									else
									{
										TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("taille buffer d'échange trop petit, taille buffer = %d, taille trame = %d"),Context.m_iSize,iSizeToRead);
									}
								}
							}
						}
						while (!bReturn && (iNbrRetry-- > 0));
					}
				}
			}

		}
	}
	else
		TRACE_LOG_MSG(_T("(iNum < iNbrTrame) && (iNum > -1)"));

	if (!bReturn) 
	{
		TRACE_DEBUG(eError,eCycle,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Erreur de com avec la carte n°%u"), (pElem)?pElem->m_pTrameJbusRQ->ucGetNumDest():99);
	}
	return bReturn;
}


BOOL CElemCycleStep::bExecuteListExchange(CElemList *pListExchange, BOOL bCanRead, BOOL bCanWrite,CEnumInterface &EnumInterface)
{
	BOOL bReturn = TRUE;
	CElemExchangeJbus *pElem = NULL;
	CContext Context;
	int iNbrTrame;
	int i;
	int iNbrRetry = NBR_RETRY_EXCHANGE;
	CThreadInterface *pInterface = NULL;

	iNbrTrame = pListExchange->iGetCount();

	for (i = 0; (i < iNbrTrame) && bReturn; i++)
	{
		bReturn = bExecuteNumExchange(i,pListExchange,bCanRead,bCanWrite,EnumInterface);
	}
	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eCycle,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	}
	return bReturn;
}

BOOL CElemCycleStep::bExecuteBegin(BOOL bCanRead, BOOL bCanWrite,CEnumInterface &EnumInterface)
{
	return bExecuteListExchange(&m_ListExchangeBegin, bCanRead, bCanWrite,EnumInterface);
}

BOOL CElemCycleStep::bExecuteEnd(BOOL bCanRead, BOOL bCanWrite,CEnumInterface &EnumInterface)
{
	return bExecuteListExchange(&m_ListExchangeEnd, bCanRead, bCanWrite,EnumInterface);
}

BOOL CElemCycleStep::bExecuteRealTime(BOOL bCanRead, BOOL bCanWrite,CEnumInterface &EnumInterface)
{
	return bExecuteListExchange(&m_ListExchangeRealTime, bCanRead, bCanWrite,EnumInterface);
}

BOOL CElemCycleStep::bFindRqAndExecuteFromIHM(long lExtraHeader,BOOL bCanRead, BOOL bCanWrite,BYTE *pBufferIn,long lSizeIn,BYTE *pBufferOut, long *plSizeOut,long lSizeOutMax,CEnumInterface &EnumInterface)
{
	BOOL bReturn = FALSE;
	CElemExchangeJbus *pElem = NULL;
	CContext Context;
	int iNbrTrame;
	int iNbrRetry = NBR_RETRY_EXCHANGE;
	CThreadInterface *pInterface = NULL;

	// recherche de l'interface de sortie
	pInterface = EnumInterface.pGetSelectedInterface(*pBufferIn);
	*plSizeOut = 0;

	if (pInterface)
	{
		// si c'est un message de l'IHM
		if (EnumInterface.bSelectedInterfaceIsSocketIHM(pInterface)) 
		{
			iNbrTrame = m_ListExchangeRealTime.iGetCount();
			if ((lExtraHeader > -1) && (lExtraHeader < iNbrTrame))
			{
				if (pElem = (CElemExchangeJbus*)m_ListExchangeRealTime.pGetAt(lExtraHeader))
				{
					if (pElem->m_pTrameJbusRQ && pElem->m_pTrameJbusRP)
					{
						if (pElem->m_pTrameJbusRQ->bAccessAllowed(bCanRead,bCanWrite))
						{
							// verif de la taille en retour
							Context.Reset(TRUE,NULL,pBufferOut,lSizeOutMax,pInterface->bGetModeInteger(),FALSE);
							if (pElem->m_pTrameJbusRP->iGetStreamSize(Context) <= lSizeOutMax)
							{
								// verif si c'est la bonne trame et mise à jour
								if (bReturn = pElem->m_pTrameJbusRQ->bUpdateData(pBufferIn,lSizeIn,Context.m_bModeInteger))
								{
									// recup de la reponse RP
									*plSizeOut = pElem->m_pTrameJbusRP->iGetStreamSize(Context);
									if (pElem->m_pTrameJbusRP->bSerialize(Context))
									{
										bReturn = TRUE;
									}
								}
							}
						}
					}
				}
			}
		}
		// trame pas pour cette interface
		else /// carte io ou mesure
		{
			do
			{
				// ecriture et lecture sur l'interface serie (IO ou mesure
				if (bReturn = pInterface->bWriteAndRead(-1,pBufferIn,lSizeIn,pBufferOut,lSizeOutMax,lSizeOutMax,plSizeOut,TRUE))
				{
					// recup de la taille du buffer de sortie a retransmettre vers IHM en l'état
				}
			}
			while (!bReturn && (iNbrRetry-- > 0));
		}
	}

	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eComSocket,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		TRACE_DEBUG_IHM(eError,eComSocket,eErrorFindRqAndExecuteFromIHM);
	}
	return bReturn;
}


BOOL CElemCycleStep::bExecute(CElemInt8 *pCmdRun,CElemInt16 *pStatusRealTime,CElemInt16 *pTimeCycle,CEnumInterface &EnumInterface)
{
	BOOL bReturn = TRUE;
	pStatusRealTime->bSetVal(0);
	bReturn = bExecuteBegin(TRUE, TRUE,EnumInterface);
	if (bReturn) 
	{
		if (m_ListExchangeRealTime.iGetCount() > 0)
		{
			do
			{
				pStatusRealTime->bSetVal(pStatusRealTime->nGetVal() | 0x0001);
				bReturn = bExecuteRealTime(TRUE,TRUE,EnumInterface);
				/*if ((pStatusRealTime->nGetVal() & 0x0001) != 0) 
				{
					Sleep(1000);
					pTimeCycle->bIncVal(1);
				}*/
				Sleep(250);
			}
			while (bReturn && (pCmdRun->ucGetVal() != 0) && ((pStatusRealTime->nGetVal() & 0x0001) != 0));
		}
	}

	if (bReturn) bReturn = bExecuteEnd(TRUE,TRUE,EnumInterface);



	if (!bReturn) TRACE_DEBUG(eDebug,eCycle,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

CElemCycleStep CElemCycle::m_CurrentStep;

/*(@!*****************************************************************************************
* Nom     : CElemCycle
* Role    : definition du traitement sur un cycle
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemCycle::CElemCycle() : CElemList(NBR_CYCLE_STEP_MAX)
{
	m_iType = MAKE_ID(0xFF,0xFF,eTYPE_CYCLE,0xFF);
	SetLabel(_T("CElemCycle"));
	//InitializeCriticalSection(&m_hCriticalSection);
	CElemCycle::m_CurrentStep.SetType(MAKE_ID(0xFF,0xFF,eTYPE_CYCLE_STEP,eID_STREAM_CURRENT_STEP));
}

CElemCycle::~CElemCycle()
{
	RemoveAll();
	//DeleteCriticalSection(&m_hCriticalSection);
}

void CElemCycle::RemoveAll()
{
	CElemList::RemoveAll();
	m_Duration.bSetVal((short)0);
	m_ElemCycleStepStop.RemoveAll();
}

BOOL CElemCycle::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;

	bReturn = CElemList::bSerialize(Context);
	if (bReturn) bReturn = m_Duration.bSerialize(Context);
	if (bReturn) bReturn = m_ElemCycleStepStop.bSerialize(Context);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

int CElemCycle::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	iSize = CElemList::iGetStreamSize(Context);
	iSize += m_Duration.iGetStreamSize(Context);
	iSize += m_ElemCycleStepStop.iGetStreamSize(Context);

	return iSize;
}

BOOL CElemCycle::bReadConfig(LPCTSTR pszFileName,CListStream *pListStream)
{
	BOOL bReturn = FALSE;
	TCHAR szRub[MAX_PATH];
	TCHAR szText[MAX_PATH];
	int i;
	int iLastStep;
	CElemCycleStep *pCycleStep = NULL;

	RemoveAll();
	// label
	dwGetPrivateProfileString(_T("Config"),_T("Label"),szGetLabel(),szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	SetLabel(szText);
	// duree max
	bReturn = m_Duration.bSetVal(iGetPrivateProfileInt(_T("Config"),_T("Duration"),0,pszFileName));
	// dernier num de pas
	iLastStep = iGetPrivateProfileInt(_T("Config"),_T("LastStepNum"),0,pszFileName);
	// trame d'arrêt
	m_ElemCycleStepStop.bReadConfig(_T("Stop"),pszFileName,pListStream);
	// les pas
	for (i = 0;bReturn && (i <= iLastStep); i++)
	{
		_stprintf(szRub,_T("%d"),i);
		if (pCycleStep == NULL) pCycleStep = new CElemCycleStep();
		if (bReturn = (pCycleStep != NULL))
		{
			pCycleStep->SetAutoDelete(TRUE);
			if (pCycleStep->bReadConfig(szRub,pszFileName,pListStream))
			{
				bReturn = (pAdd(pCycleStep) != NULL);
				pCycleStep = NULL;
			}
			else pCycleStep->RemoveAll();
		}
	}

	if (pCycleStep != NULL) delete pCycleStep;

	if (!bReturn)
	{
		TRACE_DEBUG(eDebug,eCycle,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		TRACE_DEBUG_IHM(eError,eCycle,eErrorCycleReadConfig);
	}

	return bReturn;
}

BOOL CElemCycle::bWriteConfig(LPCTSTR pszFileName)
{
	BOOL bReturn = FALSE;
	int i;
	int iSize;
	CElemCycleStep *pCycleStep = NULL;

	// label
	bReturn = bWritePrivateProfileString(_T("Config"),_T("Label"),szGetLabel(),pszFileName);
	// duree max
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("Config"),_T("Duration"),m_Duration.nGetVal(),pszFileName);
	// trame d'arrêt
	if (bReturn) bReturn = m_ElemCycleStepStop.bWriteConfig(_T("Stop"),pszFileName);


	iSize = iGetCount();
	for (i = 0;bReturn && (i < iSize); i++)
	{
		pCycleStep = (CElemCycleStep *)pGetAt(i);
		if (bReturn = (pCycleStep != NULL))
		{
			bReturn = pCycleStep->bWriteConfig(NULL,pszFileName);
		}
	}
	if (bReturn && (pCycleStep != NULL))
	{
		// dernier pas
		bReturn = bWritePrivateProfileInt(_T("Config"),_T("LastStepNum"),pCycleStep->m_Step.nGetVal(),pszFileName);
	}
	else bReturn = bWritePrivateProfileInt(_T("Config"),_T("LastStepNum"),0,pszFileName);

	if (!bReturn)
	{
		TRACE_DEBUG(eDebug,eCycle,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		TRACE_DEBUG_IHM(eError,eCycle,eErrorCycleWriteConfig);
	}
	return bReturn;
}

BOOL CElemCycle::bWaitForNextStep(short nNextTime, CElemInt8 *pCmdRun,CElemInt8 *pCmdPause,CElemInt16 *pCmdJumpStep,CElemInt16 *pTimeCycle)
{
	BOOL bReturn = TRUE;

	while (bReturn && (CElemCycle::m_CurrentStep.m_Step.nGetVal() < nNextTime) && (pCmdRun->ucGetVal() != 0) || pCmdPause->ucGetVal())
	{
		if (pCmdJumpStep->nGetVal() > nNextTime)
		{
			bReturn = FALSE;
		}
		else
		{
			Sleep(1000);
			if (pCmdPause->ucGetVal() == 0) 
			{
				pTimeCycle->bIncVal(1);
				CElemCycle::m_CurrentStep.m_Step.bIncVal(1);
			}
			bReturn = (pCmdRun->ucGetVal() != 0);
		}
	}
	if (!bReturn) TRACE_DEBUG(eDebug,eCycle,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

BOOL CElemCycle::bWaitForNextTime( short nNextTime,CElemInt8 *pCmdRun,CElemInt8 *pCmdPause,CElemInt16 *pCmdJumpStep,CElemInt16 *pTimeCycle)
{
	BOOL bReturn = TRUE;

	while (bReturn && (pTimeCycle->nGetVal() < nNextTime) && (pCmdRun->ucGetVal() != 0) || pCmdPause->ucGetVal())
	{
		if (pCmdJumpStep->nGetVal() > nNextTime)
		{
			bReturn = FALSE;
		}
		else
		{
			Sleep(1000);
			if (pCmdPause->ucGetVal() == 0) 
			{
				pTimeCycle->bIncVal(1);
				CElemCycle::m_CurrentStep.m_Step.bIncVal(1);
			}
			bReturn = (pCmdRun->ucGetVal() != 0);
		}
	}
	if (!bReturn) TRACE_DEBUG(eDebug,eCycle,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

CElemCycleStep *CElemCycle::pGetCurrentStep()
{
	CElemCycleStep *pStep = NULL;

	EnterCriticalSection(&m_hCriticalSection);
	pStep = &CElemCycle::m_CurrentStep;
	LeaveCriticalSection(&m_hCriticalSection);
	return pStep;
}

void CElemCycle::SetCurrentStep(CElemCycleStep *pStep)
{
	EnterCriticalSection(&m_hCriticalSection);
	if (pStep != NULL)
	{
		CElemCycle::m_CurrentStep.SetLabel(pStep->szGetLabel());
		CElemCycle::m_CurrentStep.m_Step.bSetVal(pStep->m_Step.nGetVal());
	}
	LeaveCriticalSection(&m_hCriticalSection);
}

BOOL CElemCycle::bExecute(CElemInt8 *pCmdRun,CElemInt8 *pCmdStopEndCycle,CElemInt8 *pCmdPause,CElemInt16 *pCmdJumpStep,CElemInt16 *pStatusRealTime,CElemInt16 *pTimeCycle,CEnumInterface &EnumInterface, CStream* argpStream, CElemInt8* argNumCurrentStream)
{
	BOOL bReturn = TRUE;
	CElemCycleStep *pStep = NULL;
	int i;
	int iSize;
		
	iSize = iGetCount();
	pTimeCycle->bSetVal((short)0);
	CElemCycle::m_CurrentStep.m_Step.bSetVal(0);
	CElemCycle::m_CurrentStep.SetLabel(_T(" "));

	for (i = 0;(pCmdRun->ucGetVal() != 0) && bReturn && (i < iSize) && (m_Duration.nGetVal()/**60*/ > pTimeCycle->nGetVal());i++)
	{
		//Entre qu'en cas de saut de pas
		if (pStep = (CElemCycleStep *)pGetAt(i)) 
		{
			if (pCmdJumpStep->nGetVal() > pStep->m_Step.nGetVal())
			{
				// recherche du pas le plus près inférieur
				for (i; (pCmdRun->ucGetVal() != 0) && bReturn && (i < iSize);i++)
				{
					if (pStep = (CElemCycleStep *)pGetAt(i))
					{
						pTimeCycle->bSetVal(pStep->m_Step.nGetVal());
						if (pCmdJumpStep->nGetVal() <= pStep->m_Step.nGetVal())
						{
							SetCurrentStep(pStep);
							break;
						}
						else pStep = NULL;
					}
				}
				// Arret de tous les organes
				if (!m_ElemCycleStepStop.bExecute(pCmdRun,pStatusRealTime,pTimeCycle,EnumInterface))
				{
					TRACE_DEBUG(eDebug,eCycle,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: m_ElemCycleStepStop"));
					bReturn = FALSE;
				}
			}
		}
		if (pStep)
		{
			if (bWaitForNextStep(pStep->m_Step.nGetVal(), pCmdRun,pCmdPause,pCmdJumpStep,pTimeCycle)) 
			{
				SetCurrentStep(pStep);
				bReturn = pStep->bExecute(pCmdRun,pStatusRealTime,pTimeCycle,EnumInterface);

				//Log en cas d'erreur sur un programme de la carte mesure
				for(int j=0; j<argpStream->iGetNbrMesure(); j++)
				{
					if(argpStream->pGetAt(j)->m_StatusFailure.ucGetVal() != 0)
					{
						TRACE_LOG_ERROR_PRG(argpStream, argNumCurrentStream, j, CElemCycle::m_CurrentStep.m_Step.nGetVal());
						argpStream->m_StatusFailure.bSetVal(1);	
						argpStream->pGetAt(j)->m_StatusFailure.bSetVal(0);
					}
				}
			}
		}
	}

	//Si le cmdRun est a 0 c'est qu'une fin de cycle IMMEDIATE a été demandé : executer le pas stop
 	if(!pCmdRun->ucGetVal())
	{
		//Ce pas ne peut être arrêté
		CElemInt8 m_CmdRunStopStep;
		m_CmdRunStopStep.bSetVal((BYTE)1);
		m_ElemCycleStepStop.bExecute(&m_CmdRunStopStep,pStatusRealTime,pTimeCycle,EnumInterface);
	}

	// attente durée max du cycle
	bWaitForNextTime(m_Duration.nGetVal(), pCmdRun,pCmdPause,pCmdJumpStep,pTimeCycle);
	
	//Aprés attante si il y a une arrêt fiin de cycle, on éxecute la pas stop
	if(pCmdStopEndCycle->ucGetVal())
	{
		//Ce pas ne peut être arrêté
		CElemInt8 m_CmdRunStopStep;
		m_CmdRunStopStep.bSetVal((BYTE)1);
		m_ElemCycleStepStop.bExecute(&m_CmdRunStopStep,pStatusRealTime,pTimeCycle,EnumInterface);
	}

	if (!bReturn)
	{
		TRACE_DEBUG(eDebug,eCycle,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		TRACE_DEBUG_IHM(eError,eCycle,eErrorCycleExecute);
	}
	return bReturn;
}


/*(@!*****************************************************************************************
* Nom     : CElemCycleZero
* Role    : definition du traitement d'un cycle de zero
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemCycleZero::CElemCycleZero() : CElemCycle()
{
	m_iType = MAKE_ID(0xFF,0xFF,eTYPE_CYCLE_ZERO,0xFF);
	SetLabel(_T("CElemCycleZero"));
}

CElemCycleZero::~CElemCycleZero()
{
}


BOOL CElemCycleZero::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;

	bReturn = CElemCycle::bSerialize(Context);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

int CElemCycleZero::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	iSize = CElemCycle::iGetStreamSize(Context);

	return iSize;
}

BOOL CElemCycleZero::bReadConfig(LPCTSTR pszFileName,CListStream *pListStream)
{
	BOOL bReturn = FALSE;

	if (bReturn = CElemCycle::bReadConfig(pszFileName,pListStream))
	{
		// lecture param complémentaire
	}

	if (!bReturn)
	{
		TRACE_DEBUG(eDebug,eCycleZero,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		TRACE_DEBUG_IHM(eError,eCycleZero,eErrorCycleZeroReadConfig);
	}
	return bReturn;
}

BOOL CElemCycleZero::bWriteConfig(LPCTSTR pszFileName)
{
	BOOL bReturn = FALSE;

	if (bReturn = CElemCycle::bWriteConfig(pszFileName))
	{
		// ecriture param complémentaire
	}

	if (!bReturn)
	{
		TRACE_DEBUG(eDebug,eCycleZero,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		TRACE_DEBUG_IHM(eError,eCycleZero,eErrorCycleZeroWriteConfig);
	}

	return bReturn;
}


BOOL CElemCycleZero::bExecute(CElemInt8 *pCmdRun ,CElemInt8 *pCmdStopEndCycle,CElemInt8 *pCmdPause,CElemInt16 *pCmdJumpStep,CElemInt16 *pStatusRealTime,CElemInt16 *pTimeCycle,CEnumInterface &EnumInterface, CStream* argpStream, CElemInt8* argNumCurrentStream)
{
	BOOL bReturn = FALSE;

	bReturn = CElemCycle::bExecute(pCmdRun,pCmdStopEndCycle,pCmdPause,pCmdJumpStep,pStatusRealTime,pTimeCycle,EnumInterface,argpStream,argNumCurrentStream);

	if (!bReturn)
	{
		TRACE_DEBUG(eDebug,eCycleZero,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		TRACE_DEBUG_IHM(eError,eCycleZero,eErrorCycleZeroExecute);
	}
	return bReturn;
}


/*(@!*****************************************************************************************
* Nom     : CElemCycleCalib
* Role    : definition du traitement d'un cycle de calibration
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemCycleCalib::CElemCycleCalib() : CElemCycleZero()
{
	m_iType = MAKE_ID(0xFF,0xFF,eTYPE_CYCLE_CALIB,0xFF);
	SetLabel(_T("CElemCycleCalib"));
}

CElemCycleCalib::~CElemCycleCalib()
{
}


BOOL CElemCycleCalib::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;

	bReturn = CElemCycleZero::bSerialize(Context);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

int CElemCycleCalib::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	iSize = CElemCycleZero::iGetStreamSize(Context);

	return iSize;
}

BOOL CElemCycleCalib::bReadConfig(LPCTSTR pszFileName,CListStream *pListStream)
{
	BOOL bReturn = FALSE;

	if (bReturn = CElemCycleZero::bReadConfig(pszFileName,pListStream))
	{
	}

	if (!bReturn)
	{
		TRACE_DEBUG(eDebug,eCycleCalib,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		TRACE_DEBUG_IHM(eError,eCycleCalib,eErrorCycleCalibReadConfig);
	}
	return bReturn;
}

BOOL CElemCycleCalib::bWriteConfig(LPCTSTR pszFileName)
{
	BOOL bReturn = FALSE;

	if (bReturn = CElemCycleZero::bWriteConfig(pszFileName))
	{
	}

	if (!bReturn)
	{
		TRACE_DEBUG(eDebug,eCycleCalib,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		TRACE_DEBUG_IHM(eError,eCycleCalib,eErrorCycleCalibWriteConfig);
	}
	return bReturn;
}



BOOL CElemCycleCalib::bExecute(CElemInt8 *pCmdRun,CElemInt8 *pCmdStopEndCycle,CElemInt8 *pCmdPause,CElemInt16 *pCmdJumpStep,CElemInt16 *pStatusRealTime,CElemInt16 *pTimeCycle,CEnumInterface &EnumInterface, CStream* argpStream, CElemInt8* argNumCurrentStream)
{
	BOOL bReturn = FALSE;

	bReturn = CElemCycle::bExecute(pCmdRun,pCmdStopEndCycle,pCmdPause,pCmdJumpStep,pStatusRealTime,pTimeCycle,EnumInterface,argpStream,argNumCurrentStream);
	
	if (!bReturn)
	{
		TRACE_DEBUG(eDebug,eCycleCalib,_T(__FILE__),_T(__FUNCTION__),__LINE__,szGetLabel());
		TRACE_DEBUG_IHM(eError,eCycleCalib,eErrorCycleCalibExecute);
	}

	return bReturn;
}

/*(@!*****************************************************************************************
* Nom     : CElemCycleCleanup
* Role    : definition du traitement d'un cycle de nettoyage
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemCycleCleanup::CElemCycleCleanup() : CElemCycle()
{
	m_iType = MAKE_ID(0xFF,0xFF,eTYPE_CYCLE_CLEANUP,0xFF);
	SetLabel(_T("CElemCycleCleanup"));
}

CElemCycleCleanup::~CElemCycleCleanup()
{
}


BOOL CElemCycleCleanup::bReadConfig(LPCTSTR pszFileName,CListStream *pListStream)
{
	BOOL bReturn = FALSE;

	if (bReturn = CElemCycle::bReadConfig(pszFileName,pListStream))
	{
	}

	if (!bReturn)
	{
		TRACE_DEBUG(eDebug,eCycleCleanup,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		TRACE_DEBUG_IHM(eError,eCycleCleanup,eErrorCycleCleanupReadConfig);
	}
	return bReturn;
}

BOOL CElemCycleCleanup::bWriteConfig(LPCTSTR pszFileName)
{
	BOOL bReturn = FALSE;

	if (bReturn = CElemCycle::bWriteConfig(pszFileName))
	{
	}

	if (!bReturn)
	{
		TRACE_DEBUG(eDebug,eCycleCleanup,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		TRACE_DEBUG_IHM(eError,eCycleCleanup,eErrorCycleCleanupWriteConfig);
	}

	return bReturn;
}

