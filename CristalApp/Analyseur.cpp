#include "stdafx.h"
#include "header.h"


#include "header_qt.h"

#include "CWinMaintenanceModel.h"

/////////////////////////////////////////////////////////////////////////////
// CAnalyseur
////////////////////////////////////////////////////////////////
/*@!************************************************************************
* NOM:                      CAnalyseur:CAnalyseur
* ROLE:                     Constructeur de la classe CAnalyseur
* ALGORITHME:
*    Point d'entree
*    Initialisation des membres de la classe
*    Point de sortie
***********************************************************************@!)*/

CAnalyseur::CAnalyseur():CListStream()
{
}


/*@!************************************************************************
* NOM:                      CAnalyseur::~CAnalyseur
* ROLE:                     Destructeur de la classe client
* ALGORITHME:
***********************************************************************@!)*/
CAnalyseur::~CAnalyseur()
{
}


// gestion des cycles
//DWORD CAnalyseur::RunThread()
void CAnalyseur::run()
{
#define BREAK_NBR		9999
	//int i;
//	int j;
	int iAtt = 0;
	BOOL bReturn = TRUE;
	CStream *pStream = NULL;
	//CStream *pStream2 = NULL;
	//int iElapse;
	m_bRun = TRUE;
	CElemInt8 *pNumVoie;
	CElemInt16 *pDuree;

	m_bStateCalib.bSetVal(0);
	m_bStateZero.bSetVal(0);
	m_bStateCleanup.bSetVal(0);
	m_bStatusFailure.bSetVal(0);
	m_bStatusRealTime.bSetVal(0);
	m_bStatusSupervision.bSetVal(0);
	m_CmdCycleCalib.bSetVal(0xFF);
	m_CmdCycleCalibInLine.bSetVal(0xFF);
	m_CmdCycleZero.bSetVal(0xFF);
	m_CmdCycleCleanup.bSetVal(0xFF);
	

	m_CmdSaveNumConfig.bSetVal(m_NumCurrentConfig.ucGetVal());
	m_CmdLoadNumConfig.bSetVal(m_NumCurrentConfig.ucGetVal());

	TCHAR szTrace[500];

	//bReadTempConfig(_T("\\Hard Disk2\\backup.ini"));

	m_bInRunThread = TRUE;
	while (m_bRun)
	{
		while (m_bRun && (!m_CmdRun.ucGetVal() || m_CmdPause.ucGetVal()))
		{
			// gestion des configs
			//TRACE_LOG_MSG(_T("En stop  \n"));
			GestionConfigFlash();
			if(!bAnalyseurStoped) bAnalyseurStoped = true;
			Sleep(1000);
		}
			bAnalyseurStoped = false;
			/*if (m_CmdStopEndCycle.ucGetVal())
				TRACE_LOG_MSG(_T("-- m_CmdStopEndCycle vrai\n"));
			else 
				TRACE_LOG_MSG(_T("-- m_CmdStopEndCycle Faux\n"));

			if (m_CmdCycleCalib.ucGetVal()!= 0xFF)
				TRACE_LOG_MSG(_T("-- m_CmdCycleCalib vrai\n"));
			else 
				TRACE_LOG_MSG(_T("-- m_CmdCycleCalib Faux\n"));
			if (m_CmdMaintenanceManuel.ucGetVal())
				TRACE_LOG_MSG(_T("-- m_CmdMaintenanceManuel vrai\n"));
			else 
				TRACE_LOG_MSG(_T("-- m_CmdMaintenanceManuel Faux\n"));*/
		for (m_indexSeqence = 0;m_bRun && m_CmdRun.ucGetVal() && (m_indexSeqence < NBR_SEQUENCE_CYCLE_MAX); ++m_indexSeqence)
		{
			// exec des cycles
			pNumVoie = (CElemInt8*)m_ListSequenceNum.pGetAt(m_indexSeqence);
			if(pNumVoie && pNumVoie->ucGetVal() == 99) //Si sur la voie attente
			{
				//TRACE_LOG_MSG(_T("Voie attente ...  \n"));
				m_NumCurrentStream.bSetVal(99);
				m_CmdJumpStep.bSetVal(0);
				pDuree = (CElemInt16*)m_ListSequenceDuree.pGetAt(m_indexSeqence);
				iAtt = pDuree->nGetVal()*60; //Pour avoir le temps en seconde
				while ( (iAtt -- > 0) 
						&& m_CmdRun.ucGetVal() 
						&& !m_CmdStopEndCycle.ucGetVal() 
						&&  m_CmdJumpStep.nGetVal() != BREAK_NBR)
				
				{	
					m_TimeRemaingUntilNextCycle.bSetVal(iAtt);
					Sleep(1000);}
				//TRACE_LOG_MSG(_T("Fin Voie attente ...  \n"));
			}
			else 
			{
				//TRACE_LOG_MSG(_T("Cycle normale en cours  \n"));
				pStream = (pNumVoie != NULL) ? pGetAt(pNumVoie->ucGetVal()) : NULL;
				pDuree = (CElemInt16*)m_ListSequenceDuree.pGetAt(m_indexSeqence);
				if (pStream && pDuree && (pNumVoie->ucGetVal() < m_iNbrStream))
				{
					m_NumCurrentStream.bSetVal(pNumVoie->ucGetVal());
					// init le compteur de cycle
					pStream->m_CounterCycle.bSetVal(0);
					m_CmdJumpStep.bSetVal(0);
					m_iTimeElapse = 0;

					//Pour ne pas faire de check sur les séquences inactive et si on est en maintenance manuel
					if(pDuree->nGetVal()>0 && !m_CmdMaintenanceManuel.ucGetVal())
					{
						_stprintf(szTrace,_T("Check Calib : sequence: %d , voie : %d, duree : %d \n")
								, m_indexSeqence
								, pNumVoie->ucGetVal()
								, pDuree->nGetVal());

						//TRACE_LOG_MSG(szTrace);


						//Gestion des cycles periodique de la voie
						
						pStream->bCheckAndCmdPeriodic( pStream->m_iCalibCheckedDays, pStream->m_iCalibCheckedHours
											, &pStream->m_ListPeriodicHourCycleCalib, &pStream->m_ListPeriodicDayCycleCalib
											, &pStream->m_PeriodicCycleCalib, pStream->m_iNbCycleCalib
											, &m_CmdCycleCalib, &m_NumCurrentStream);
						//TRACE_LOG_MSG(_T("Check CalibInLine ...  \n"));
						pStream->bCheckAndCmdPeriodic( pStream->m_iCalibInLineCheckedDays, pStream->m_iCalibInLineCheckedHours
											, &pStream->m_ListPeriodicHourCycleCalibInLine, &pStream->m_ListPeriodicDayCycleCalibInLine
											, &pStream->m_PeriodicCycleCalibInLine, pStream->m_iNbCycleCalibInLine
											, &m_CmdCycleCalibInLine, &m_NumCurrentStream);
						//TRACE_LOG_MSG(_T("Check Zero ...  \n"));
						pStream->bCheckAndCmdPeriodic( pStream->m_iZeroCheckedDays, pStream->m_iZeroCheckedHours
											, &pStream->m_ListPeriodicHourCycleZero, &pStream->m_ListPeriodicDayCycleZero
											, &pStream->m_PeriodicCycleZero, pStream->m_iNbCycleZero
											, &m_CmdCycleZero, &m_NumCurrentStream);
						//TRACE_LOG_MSG(_T("Check Cleanup ...  \n"));
						pStream->bCheckAndCmdPeriodic( pStream->m_iCleanupCheckedDays, pStream->m_iCleanupCheckedHours
											, &pStream->m_ListPeriodicHourCycleCleanup, &pStream->m_ListPeriodicDayCycleCleanup
											, &pStream->m_PeriodicCycleCleanup, pStream->m_iNbCycleCleanup
											, &m_CmdCycleCleanup, &m_NumCurrentStream);

						_stprintf(szTrace,_T("Valeur de la boucle : cmdRun: %d , m_CmdJumpStep : %d, m_CounterCycle : %d , m_iTimeElapse : %d, duree : %d \n")
								, m_CmdRun.ucGetVal() 
								, m_CmdJumpStep.nGetVal()
								, pStream->m_CounterCycle.nGetVal()
								, m_iTimeElapse
								, pDuree->nGetVal());

						//TRACE_LOG_MSG(szTrace);
					}

					while (    m_CmdRun.ucGetVal() 
							&& ((m_CmdJumpStep.nGetVal() != BREAK_NBR) || (pStream->m_CounterCycle.nGetVal() != BREAK_NBR)) 
							&& (m_iTimeElapse /*+ pStream->m_ElemCycle.m_Duration.nGetVal())*/ < pDuree->nGetVal()))//*60))
					{
						//TRACE_LOG_MSG(_T("CMD RUN ON  \n"));
						qDebug() <<"CHECK MAINTENANCE";
						if (m_CmdStopEndCycle.ucGetVal())
						{
							qDebug() <<"CHECK MAINTENANCE m_CmdStopEndCycle";

							//TRACE_LOG_MSG(_T("CMD STOP AND CYCLE ON  \n"));
							while (m_CmdStopEndCycle.ucGetVal() && m_CmdRun.ucGetVal())
							{
							//TRACE_LOG_MSG(_T("EN PERIODIQUE \n"));
								qDebug() <<"CHECK MAINTENANCE m_CmdRun";
								qDebug() <<"CHECK MAINTENANCE m_CmdCycleZero" << m_CmdCycleZero.ucGetVal();
								qDebug() <<"CHECK MAINTENANCE m_CmdCycleCleanup"<< m_CmdCycleCleanup.ucGetVal();
								qDebug() <<"CHECK MAINTENANCE m_CmdCycleCalib"<< m_CmdCycleCalib.ucGetVal();
								qDebug() <<"CHECK MAINTENANCE m_CmdCycleCalibInLine"<< m_CmdCycleCalibInLine.ucGetVal();
								
								// action périodique
								if (m_CmdCycleZero.ucGetVal() != 0xFF)
								{
								qDebug() <<"CHECK MAINTENANCE m_CmdCycleZero ON";
									
									pStream->m_StatusWaterFailure.bSetVal(0);
									ExecuteZero();
									m_CmdCycleZero.bSetVal(0xFF);
								}
								if (m_CmdCycleCleanup.ucGetVal() != 0xFF)
								{
								qDebug() <<"CHECK MAINTENANCE m_CmdCycleCleanup ON";
									pStream->m_StatusWaterFailure.bSetVal(0);
									ExecuteCleanup();
									m_CmdCycleCleanup.bSetVal(0xFF);
								}
								if (m_CmdCycleCalib.ucGetVal() != 0xFF)
								{
								qDebug() <<"CHECK MAINTENANCE m_CmdCycleCalib ON";
									//TRACE_LOG_MSG(_T("CALIB ON  \n"));
									pStream->m_StatusWaterFailure.bSetVal(0);
									ExecuteCalib();
									m_CmdCycleCalib.bSetVal(0xFF);
									//TRACE_LOG_MSG(_T("CALIB OFF  \n"));
								}
								if (m_CmdCycleCalibInLine.ucGetVal() != 0xFF)
								{
								qDebug() <<"CHECK MAINTENANCE m_CmdCycleCalibInLine ON";
									pStream->m_StatusWaterFailure.bSetVal(0);
									ExecuteCalibInLine();
									m_CmdCycleCalibInLine.bSetVal(0xFF);
								}
								
								Sleep(1000);
							}
						}
						else
						{
							qDebug() <<"CHECK MAINTENANCE";

							//TRACE_LOG_MSG(_T("CMD STOP AND CYCLE OFF  \n"));
							//A factoriser
							// action périodique
							//TRACE_LOG_MSG(_T("Check des Cmd ...  \n"));
							if (m_CmdCycleZero.ucGetVal() != 0xFF)
							{
								m_CmdJumpStep.bSetVal(0);
								CElemCycle::m_CurrentStep.m_Step.bSetVal(0);
								//TRACE_LOG_MSG(_T("Cmd de zero ...  \n"));
								pStream->m_StatusWaterFailure.bSetVal(0);
								ExecuteZero();
								m_CmdCycleZero.bSetVal(0xFF);
							}
							if (m_CmdCycleCalib.ucGetVal() != 0xFF)
							{
								m_CmdJumpStep.bSetVal(0);
								CElemCycle::m_CurrentStep.m_Step.bSetVal(0);
								//TRACE_LOG_MSG(_T("Cmd de calib ...  \n"));
								pStream->m_StatusWaterFailure.bSetVal(0);
								ExecuteCalib();
								m_CmdCycleCalib.bSetVal(0xFF);
							}
							if (m_CmdCycleCalibInLine.ucGetVal() != 0xFF)
							{
								m_CmdJumpStep.bSetVal(0);
								CElemCycle::m_CurrentStep.m_Step.bSetVal(0);
								//TRACE_LOG_MSG(_T("Cmd de calib inline...  \n"));
								pStream->m_StatusWaterFailure.bSetVal(0);
								ExecuteCalibInLine();
								m_CmdCycleCalibInLine.bSetVal(0xFF);
							}
							if (m_CmdCycleCleanup.ucGetVal() != 0xFF)
							{
								m_CmdJumpStep.bSetVal(0);
								CElemCycle::m_CurrentStep.m_Step.bSetVal(0);
								//TRACE_LOG_MSG(_T("Cmd de cleanup ...  \n"));
								pStream->m_StatusWaterFailure.bSetVal(0);
								ExecuteCleanup();
								m_CmdCycleCleanup.bSetVal(0xFF);
							}
						}


						if(m_CmdRun.ucGetVal())
						{
							//TRACE_LOG_MSG(_T("DEMARRAGE CYCLE  \n"));
							// cycle mesure
							// reset du temps passé dans le cycle
							m_CurrentTimeCycle.bSetVal(0);
							m_CmdJumpStep.bSetVal(0);
							CElemCycle::m_CurrentStep.m_Step.bSetVal(0);
							
							//Exécute le traitement pour vérfier les seuils des mesures de la voie
							//TRACE_LOG_MSG(_T("DEBT mesure"));
                            qDebug() << "m_bStatusFailure " << QString::number(m_bStatusFailure.ucGetVal());
                            qDebug() << "m_StatusWaterFailure " << QString::number(pStream->m_StatusWaterFailure.ucGetVal());
							
							bReturn = pStream->bExecute( &m_CmdRun,&m_CmdStopEndCycle,&m_CmdPause
													   , &m_CmdJumpStep,&m_bStatusRealTime,&m_CurrentTimeCycle
													   , m_ExternalInterface,&m_NumCurrentStream
													   , &m_CmdCycleCalib, &m_CmdCycleCalibInLine
													   , &m_CmdCycleCleanup, &m_CmdCycleZero, &m_CmdRemoteControl
													   , m_bNeedConditioning);
							//TRACE_LOG_MSG(_T("FIN mesure"));
							//Fait remonter le défaut d'eau sur le status analyseur
                            
                            m_bStatusFailure.bSetVal(m_bStatusFailure.ucGetVal()|pStream->m_StatusWaterFailure.ucGetVal());
                                                       
                            qDebug() << "m_bStatusFailure " << QString::number(m_bStatusFailure.ucGetVal());
                            qDebug() << "m_StatusWaterFailure " << QString::number(pStream->m_StatusWaterFailure.ucGetVal());
                            if (!bReturn)
							{
								TRACE_DEBUG_IHM(eError,eCycle,eErrorAppRunThread);
								m_bStatusFailure.bSetVal(1);
							}
							
							//Si le cycle a été arrété, ne pas faire de trace de mesure ou qu'un cycle est en défaut (eau, température, etc ...)
							if(m_CmdRun.ucGetVal() && (m_CmdJumpStep.nGetVal()!=9999) )
							{				
								//Trace des moyennes de mesures
								TRACE_LOG_MESURE(pStream, &m_NumCurrentStream, m_Average.ucGetVal());					
							}

							//Si une demande d'ârret fin de cycle a été commandé, mettre le cmdRun à 0 à la fin du cycle
							if(m_CmdStopEndCycle.ucGetVal())
							{
								m_CmdRun.bSetVal(0);
								m_CmdStopEndCycle.bSetVal(0);
							}

							// incremente le compteur de cycle et de temps
							if ((m_CmdJumpStep.nGetVal() != BREAK_NBR) && (pStream->m_CounterCycle.nGetVal() > BREAK_NBR))
							{
								pStream->m_CounterCycle.bSetVal(0);
							}
							//m_iTimeElapse += m_CurrentTimeCycle.nGetVal();
							m_iTimeElapse ++;
							m_CurrentTimeCycle.bSetVal(0);
							
							// si pas actif, un seul passage puis cycle suivant
							if (!pStream->m_Active.ucGetVal())
							{
								m_CmdJumpStep.bSetVal(BREAK_NBR);
								pStream->m_CounterCycle.bSetVal(BREAK_NBR);
							}
						}
							///TRACE_LOG_MSG(_T("FIN Boucle"));

					}
					/*if (pStream->m_Active.ucGetVal() && ((m_CmdJumpStep.nGetVal() != BREAK_NBR) || (pStream->m_CounterCycle.nGetVal() != BREAK_NBR)))
					{
						// temps restant en ms
						j = pDuree->nGetVal()*60 - m_iTimeElapse;
						// temps restant en s
						while ((j-- > 0) && m_CmdRun.ucGetVal() && !m_CmdStopEndCycle.ucGetVal()) Sleep(1000);
					}*/
				}
			}
		}
	}

//	return 0;
}
