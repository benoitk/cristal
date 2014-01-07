#include "CWinMainModel.h"
#include "CSupervision.h"
#include "CWinMainView.h"
#include "CStreamModel.h"
#include "CCmdJBusRunnable.h"

#include "header_qt.h"


#define SZ_CONFIG_ANALYSEUR_FILE _T("ConfigAnalyseur.ini")
#define NB_FILES_LOG 60

CWinMainModel::CWinMainModel(CSupervision* argoSupervision, CWinMainView* argoView)
{
    m_threadPool = new QThreadPool(this);
    m_mutex = new QMutex();

    qDebug() << "#### CWinMainModel::CWinMainModel" << endl;
    m_iModeSaved = CSupervision::eREMOTE_DEFAULT;
    //	CStreamModel* pStreamModel;
    //	QVector<CMesureModel*>* vectorMesure;
    //	CMesureModel* pMesureModel;

    m_pSupervision = argoSupervision;
    m_bFlagEndCycle = false;
    m_iPreviousStep = 0;
		

	if(m_bRun && !m_bPause)
		m_sEtatAnalyseur = tr("CYCLE EN COURS");
	else if(m_bPause)
		m_sEtatAnalyseur = tr("EN PAUSE");
	else
		m_sEtatAnalyseur = tr("EN ARRET");

	m_pView = argoView;
	
	//Initialisation pour données sur carte mesure
	TCHAR szRQ[5000];
	TCHAR szRP[5000];
	m_pSupervision->addKeyOnMapRQTComJBUSMesure("fTemperatureCuve");
	_stprintf(szRQ,_T("10|3|0x0420|2"));
	_stprintf(szRP,_T("10|3|4|0|0|0|0"));
	m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
					
	m_pSupervision->addKeyOnMapRQTComJBUSMesure("fPressionEau");
	_stprintf(szRQ,_T("10|3|0x0444|2"));
	_stprintf(szRP,_T("10|3|4|0|0|0|0"));
	m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
#ifdef SONDE	
    m_pSupervision->addKeyOnMapRQTComJBUSMesure("fMesureElectrode");
	_stprintf(szRQ,_T("10|3|0x0448|2"));
	_stprintf(szRP,_T("10|3|4|0|0|0|0"));
	m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
#else
	m_pSupervision->addKeyOnMapRQTComJBUSMesure("fMesureOptique");
	_stprintf(szRQ,_T("10|3|0x0440|2"));
	_stprintf(szRP,_T("10|3|4|0|0|0|0"));
	m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
#endif	
    
	getDataFromSupervision();
	getDataFromMeasureCard(); 
	

	m_logErrorPrgFileDir = new QDir(QString::fromUtf16(( const ushort *)_szLogErrorPrgFileDir));
	m_logFileDir = new QDir(QString::fromUtf16(( const ushort *)_szLogFileDir));
	m_logUserFileDir = new QDir(QString::fromUtf16(( const ushort *)_szUserLogFileDir));

	TCHAR szText[250];
	TCHAR szText2[250];
	dwGetPrivateProfileString(_T("Config"), _T("NbrDayLog"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), szGetFullPathName(SZ_CONFIG_ANALYSEUR_FILE,szText2));
	QString sConfigNbrDayLog = QString::fromUtf16 ((const ushort *)szText);//.split("|")[2];
	if(sConfigNbrDayLog.count() > 3 ) //Si la ligne de conf est pas foireuse
	{
		m_nbrDayRetentionLog = sConfigNbrDayLog.split("|")[2].toInt();
		m_nbrDayRetentionErrorLog = m_nbrDayRetentionLog;
	}
	else
	{
		m_nbrDayRetentionLog = NB_FILES_LOG;
	}
	dwGetPrivateProfileString(_T("Config"), _T("NbrDayMeasurement"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), szGetFullPathName(SZ_CONFIG_ANALYSEUR_FILE,szText2));
	sConfigNbrDayLog = QString::fromUtf16 ((const ushort *)szText);//.split("|")[2];
	if(sConfigNbrDayLog.count() > 3 ) //Si la ligne de conf est pas foireuse
	{
		m_nbrDayRetentionUserLog = sConfigNbrDayLog.split("|")[2].toInt();
	}
	else
	{
		m_nbrDayRetentionLog = NB_FILES_LOG;
	}
	

	/*m_nbrDayRetentionLog;
	m_nbrDayRetentionErrorLog;
	m_nbrDayRetentionUserLog*/
	m_iCptPurgeLog = 0;
	setConnexion();
	qDebug() << "#### FIN CWinMainModel::CWinMainModel" << endl;
	
}

//Méthode appelé par les thread de m_threadPool
void CWinMainModel::sendCmdJBus(const int& arg_numRQT, CElemList* arg_elemList, CEnumInterface& arg_interface)
{
    QMutexLocker locker(m_mutex);
    //qDebug() << "CWinMainModel::sendCmdJBus : " << arg_numRQT;
    m_cycleStep.bExecuteNumExchange(arg_numRQT, arg_elemList, TRUE, TRUE, arg_interface);
}

QString CWinMainModel::getTotalStep() const
{
    int tmp;
    if(this->nGetCurrentStream() == 99)
        return QString("");
   
    tmp =  m_pSupervision->getAnalyseur()->pGetAt(m_pSupervision->getAnalyseur()->m_NumCurrentStream.ucGetVal())->m_CycleTimeMax.nGetVal();
    return QString::number(tmp);
    
}
QString CWinMainModel::getCurrentStep()const
{
    int tmp;
    if(this->nGetCurrentStream() == 99)
        tmp = m_pSupervision->getAnalyseur()->m_TimeRemaingUntilNextCycle.nGetVal();
    else
        tmp = CElemCycle::m_CurrentStep.m_Step.nGetVal();
    return QString::number(tmp);
}
QString CWinMainModel::getOpticalMeasurementValue()const
{
    float tmp = m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalMeasurement.fGetVal();
    return QString::number(tmp, 'f', 2);
}
QString CWinMainModel::getOpticalMeasurementUnit()const
{
    return QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalMeasurement.m_szUnit.szGetLabel());;
}
QString CWinMainModel::getOpticalMeasurementLbl()const
{
    return QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalMeasurement.szGetLabel());
}
QString CWinMainModel::getAbsorbanceValueValue()const
{
    float tmp = m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_AbsorbanceValue.fGetVal();
    return QString::number(tmp, 'f', 5);
}
QString CWinMainModel::getAbsorbanceValueUnit()const
{
    return QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_AbsorbanceValue.m_szUnit.szGetLabel());;
}
QString CWinMainModel::getAbsorbanceValueLbl()const
{
    return QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_AbsorbanceValue.szGetLabel());
}
QString CWinMainModel::getZeroOpticalMeasurementUnit()const
{
    return QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ZeroOpticalMeasurement.m_szUnit.szGetLabel());
}
QString CWinMainModel::getZeroOpticalMeasurementLbl()const
{
    return QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ZeroOpticalMeasurement.szGetLabel());
}
QString CWinMainModel::getZeroOpticalMeasurementValue()const
{
    float tmp = m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ZeroOpticalMeasurement.fGetVal();
    return QString::number(tmp, 'f', 2);
}
QString CWinMainModel::getOpticalGainUnit()const
{
    return QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalGain.m_szUnit.szGetLabel());
}
QString CWinMainModel::getOpticalGainLbl()const
{
    return QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalGain.szGetLabel());
}
QString CWinMainModel::getOpticalGainValue()const
{
    float tmp = m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalGain.nGetVal();
    return QString::number(tmp, 'f', 2);
}
QString CWinMainModel::getMesureOptique()
{
    CElemExchangeJbus *pElem;
	TCHAR szText[5000];
#ifdef SONDE
    m_threadPool->start(new CCmdJBusRunnable( this
                                            , m_pSupervision->getNumRQTComJBUSMesure("fMesureElectrode")
                                            , m_pSupervision->getCarteMesure()->getListExchange()
                                            , m_pSupervision->getAnalyseur()->m_ExternalInterface));
	pElem =(CElemExchangeJbus*)m_pSupervision->getCarteMesure()->getListExchange()->pGetAt(m_pSupervision->getNumRQTComJBUSMesure("fMesureElectrode"));
    
#else
    m_threadPool->start(new CCmdJBusRunnable( this
                                            , m_pSupervision->getNumRQTComJBUSMesure("fMesureOptique")
                                            , m_pSupervision->getCarteMesure()->getListExchange()
                                            , m_pSupervision->getAnalyseur()->m_ExternalInterface));
	pElem =(CElemExchangeJbus*)m_pSupervision->getCarteMesure()->getListExchange()->pGetAt(m_pSupervision->getNumRQTComJBUSMesure("fMesureOptique"));

#endif	
    /*m_cycleStep.bExecuteNumExchange(m_pSupervision->getNumRQTComJBUSMesure("fMesureOptique")
							,m_pSupervision->getCarteMesure()->getListExchange()
						    ,TRUE,TRUE , m_pSupervision->getAnalyseur()->m_ExternalInterface);*/
	QString sRQT = QString::fromUtf16((const ushort*)pElem->m_pTrameJbusRP->szGetConfig(szText, 5000));
	QString sTemp1 = sRQT.split("|").at(sRQT.split("|").count()-1);
	QString sTemp2 = sRQT.split("|").at(sRQT.split("|").count()-2);
	//qDebug() << sTemp1 << "  " << sTemp2;
	QByteArray byteArray = QByteArray::number(sTemp1.toLongLong(), 16);
	int nPos=2;
	if(byteArray.count() > 4) nPos = byteArray.count()-2;
	else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	QByteArray byteArrayHex = byteArray.mid(nPos, 2);
	byteArrayHex.append(byteArray.mid(nPos-2,2));
	byteArray = QByteArray::number(sTemp2.toLongLong(), 16);
	nPos=2;
	if(byteArray.count() > 4) nPos = byteArray.count()-2;
	else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	byteArrayHex.append(byteArray.mid(nPos, 2));
	byteArrayHex.append(byteArray.mid(nPos-2,2));
	
    float tmp = CSupervision::getFloatFromQByteArrayHex(byteArrayHex);
    return QString::number( tmp, 'f', 2);
    
}
QString CWinMainModel::getPressionEau()
{
    CElemExchangeJbus *pElem;
	TCHAR szText[5000];
     m_threadPool->start(new CCmdJBusRunnable( this
                                            , m_pSupervision->getNumRQTComJBUSMesure("fPressionEau")
                                            , m_pSupervision->getCarteMesure()->getListExchange()
                                            , m_pSupervision->getAnalyseur()->m_ExternalInterface));
	/*m_cycleStep.bExecuteNumExchange(m_pSupervision->getNumRQTComJBUSMesure("fPressionEau")
							,m_pSupervision->getCarteMesure()->getListExchange()
						    ,TRUE,TRUE , m_pSupervision->getAnalyseur()->m_ExternalInterface);*/
	pElem =(CElemExchangeJbus*)m_pSupervision->getCarteMesure()->getListExchange()->pGetAt(m_pSupervision->getNumRQTComJBUSMesure("fPressionEau"));
	QString sRQT = QString::fromUtf16((const ushort*)pElem->m_pTrameJbusRP->szGetConfig(szText, 5000));
	QString sTemp1 = sRQT.split("|").at(sRQT.split("|").count()-1);
	QString sTemp2 = sRQT.split("|").at(sRQT.split("|").count()-2);
	QByteArray byteArray = QByteArray::number(sTemp1.toLongLong(), 16);
	int nPos=2;
	if(byteArray.count() > 4) nPos = byteArray.count()-2;
	else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	QByteArray byteArrayHex = byteArray.mid(nPos, 2);
	byteArrayHex.append(byteArray.mid(nPos-2,2));
	byteArray = QByteArray::number(sTemp2.toLongLong(), 16);	
	nPos=2;
	if(byteArray.count() > 4) nPos = byteArray.count()-2;
	else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	byteArrayHex.append(byteArray.mid(nPos, 2));
	byteArrayHex.append(byteArray.mid(nPos-2,2));
	float tmp = CSupervision::getFloatFromQByteArrayHex(byteArrayHex);
    return QString::number( tmp, 'f', 2);
    
}
QString CWinMainModel::getTemperatureCuve()
{
    CElemExchangeJbus *pElem;
	TCHAR szText[5000];
    m_threadPool->start(new CCmdJBusRunnable( this
                                            , m_pSupervision->getNumRQTComJBUSMesure("fTemperatureCuve")
                                            , m_pSupervision->getCarteMesure()->getListExchange()
                                            , m_pSupervision->getAnalyseur()->m_ExternalInterface));
	/*m_cycleStep.bExecuteNumExchange(m_pSupervision->getNumRQTComJBUSMesure("fTemperatureCuve")
							,m_pSupervision->getCarteMesure()->getListExchange()
						    ,TRUE,TRUE , m_pSupervision->getAnalyseur()->m_ExternalInterface);*/
	pElem =(CElemExchangeJbus*)m_pSupervision->getCarteMesure()->getListExchange()->pGetAt(m_pSupervision->getNumRQTComJBUSMesure("fTemperatureCuve"));
	QString sRQT = QString::fromUtf16((const ushort*)pElem->m_pTrameJbusRP->szGetConfig(szText, 5000));
	QString sTemp1 = sRQT.split("|").at(sRQT.split("|").count()-1);
	QString sTemp2 = sRQT.split("|").at(sRQT.split("|").count()-2);
	QByteArray byteArray = QByteArray::number(sTemp1.toLongLong(), 16);
	qDebug() << sTemp1 << "  " << byteArray;
	int nPos=2;
	if(byteArray.count() > 4) nPos = byteArray.count()-2;
	else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	qDebug() << sTemp1<< " bis " << byteArray;
	QByteArray byteArrayHex = byteArray.mid(nPos, 2);
	byteArrayHex.append(byteArray.mid(nPos-2,2));
	byteArray = QByteArray::number(sTemp2.toLongLong(), 16);
	qDebug() << sTemp2 << "  " << byteArray;
	nPos=2;
	if(byteArray.count() > 4) nPos = byteArray.count()-2;
	else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	qDebug() << sTemp1<< " bis " << byteArray;
	byteArrayHex.append(byteArray.mid(nPos, 2));
	byteArrayHex.append(byteArray.mid(nPos-2,2));
	float tmp = CSupervision::getFloatFromQByteArrayHex(byteArrayHex);
	qDebug() << "fTemperatureCuve= "<< QString::number( tmp,'f', 5 );
    return QString::number( tmp, 'f', 2);
}
QString CWinMainModel::getNameStep()const
{
   return QString::fromUtf16(( const ushort *)CElemCycle::m_CurrentStep.szGetLabel()
										    , CElemCycle::m_CurrentStep.lGetLabelLength());
}
QString CWinMainModel::getCurrentStream()const
{
    return QString::number(m_pSupervision->getAnalyseur()->m_NumCurrentStream.ucGetVal()+1);
}
int CWinMainModel::nGetCurrentStream()const
{
	
    return m_pSupervision->getAnalyseur()->m_NumCurrentStream.ucGetVal();
}
int CWinMainModel::nGetPreviousStream()const{
	int j=0;
	int iTimeElapse = m_pSupervision->getAnalyseur()->getTimeElapse();
	CElemInt8* pNumVoie = 0;
	CElemInt8* pNumDuree = 0;
	//Si mono voie ne même pas se poser la question
	//OU Si supérieur à 0 -> toujours sur la même voie
	if(this->getNbStream()<2)
		return 0;
	else if(iTimeElapse>0 && this->nGetCurrentStream()!= 99){
		return this->nGetCurrentStream();
	}
	int i = m_pSupervision->getAnalyseur()->getIndexSeq()-1;
	for(j=0; j<NBR_SEQUENCE_CYCLE_MAX; ++j){
		if(i < 0 ){
			i = NBR_SEQUENCE_CYCLE_MAX - 1;
		}
		pNumDuree = (CElemInt8*)m_pSupervision->getAnalyseur()->m_ListSequenceDuree.pGetAt(i);
		pNumVoie = (CElemInt8*)m_pSupervision->getAnalyseur()->m_ListSequenceNum.pGetAt(i);
		
		if(pNumDuree->ucGetVal() == 0 || pNumVoie->ucGetVal() == 99){ //Si pas de voie à cette séquence
			--i;
		}
		else if(!this->getVoieActive(pNumVoie->ucGetVal())) //Si voie de cette séquence est inactive
			--i;
		else{
			j = NBR_SEQUENCE_CYCLE_MAX;
		}
		
//	qDebug() << "<><><><><><><><><> " <<i << "  "<< j;
		
	}

	if(pNumDuree->ucGetVal() == 0 || !this->getVoieActive(pNumVoie->ucGetVal())){ //Si pas de voie à cette séquence retour à la même voie
		pNumVoie = (CElemInt8*)m_pSupervision->getAnalyseur()->m_ListSequenceNum.pGetAt(m_pSupervision->getAnalyseur()->getIndexSeq());
	}
	return pNumVoie->ucGetVal();
}
int CWinMainModel::nGetNombreMesure()const
{
    return m_pSupervision->getAnalyseur()->pGetAt(0)->iGetNbrMesure();
}
QString CWinMainModel::getEtatAnalyseur()const
{
    
    QString sEtatAnalyseur;
    bool bPause = getPause();
    bool bRun = getRun();
    if(bPause)
		sEtatAnalyseur = tr("EN PAUSE");
    else if(this->nGetCurrentStream() == 99)
        sEtatAnalyseur = tr("EN ATTENTE");
    else if(bRun && m_pSupervision->getAnalyseur()->pGetAt(this->nGetCurrentStream())->m_Active.ucGetVal()==0)
		sEtatAnalyseur = tr("CYCLE EN COURS \n(VOIE INHIBE)");
	else if(   bRun && m_pSupervision->getAnalyseur()->m_CmdStopEndCycle.ucGetVal()==0 
			&& m_pSupervision->getAnalyseur()->m_CmdCycleZero.ucGetVal() != 0xFF)
		sEtatAnalyseur = tr("ZERO EN COURS");
	else if(bRun && m_pSupervision->getAnalyseur()->m_CmdStopEndCycle.ucGetVal()==0)
		sEtatAnalyseur = tr("CYCLE EN COURS");
	else if(bRun && m_pSupervision->getAnalyseur()->m_CmdStopEndCycle.ucGetVal()!=0)
		sEtatAnalyseur = tr("CYCLE EN COURS \n(ARRET EN FIN DE CYCLE)");    
	else 
		sEtatAnalyseur = tr("EN ARRET");
    return sEtatAnalyseur;
}


bool CWinMainModel::getRun()const
{
    return m_pSupervision->getAnalyseur()->m_CmdRun.ucGetVal();
}
bool CWinMainModel::getStop()const
{
    return !m_pSupervision->getAnalyseur()->m_CmdRun.ucGetVal();
}
bool CWinMainModel::getPause()const
{
    return m_pSupervision->getAnalyseur()->m_CmdPause.ucGetVal();
}
bool CWinMainModel::getEnAlarm()const
{
    return m_pSupervision->getAnalyseur()->m_bStatusFailure.ucGetVal();
}

//SLOT utilisé avec timer
void CWinMainModel::getDataFromSupervision()
{
	
	//m_iTotalStep = m_pSupervision->getAnalyseur()->pGetAt(m_pSupervision->getAnalyseur()->m_NumCurrentStream.ucGetVal())->m_CycleTimeMax.nGetVal();

	//m_sEtatAnalyseur =
	//m_sCurrentStream = QString::number(m_pSupervision->getAnalyseur()->m_NumCurrentStream.ucGetVal()+1);
	/*m_sNameStep = QString::fromUtf16(( const ushort *)CElemCycle::m_CurrentStep.szGetLabel()
												    , CElemCycle::m_CurrentStep.lGetLabelLength());*/
	//m_iCurrentStep=CElemCycle::m_CurrentStep.m_Step.nGetVal();

	//m_bRun=m_pSupervision->getAnalyseur()->m_CmdRun.ucGetVal();
	//m_bStop = !m_bRun;
	//m_bPause = m_pSupervision->getAnalyseur()->m_CmdPause.ucGetVal();
	//m_bEnAlarm = m_pSupervision->getAnalyseur()->m_bStatusFailure.ucGetVal();
	/*qDebug() << "m_bEnAlarm" << m_bEnAlarm;
	qDebug() << "m_pSupervision->getAnalyseur()->m_bStatusFailure.ucGetVal()" << m_pSupervision->getAnalyseur()->m_bStatusFailure.ucGetVal();
	*/
//	m_iTest--;
	/*if(m_bPause)
		m_sEtatAnalyseur = tr("EN PAUSE");
    else if(m_bRun && m_pSupervision->getAnalyseur()->pGetAt(0)->m_Active.ucGetVal()==0)
		m_sEtatAnalyseur = tr("CYCLE IN PROGRESS \n(STREAM INHIBITED)");
	else if(   m_bRun && m_pSupervision->getAnalyseur()->m_CmdStopEndCycle.ucGetVal()==0 
			&& m_pSupervision->getAnalyseur()->m_CmdCycleZero.ucGetVal() != 0xFF)
		m_sEtatAnalyseur = tr("ZERO EN COURS");
	else if(m_bRun && m_pSupervision->getAnalyseur()->m_CmdStopEndCycle.ucGetVal()==0)
		m_sEtatAnalyseur = tr("CYCLE EN COURS");
	else if(m_bRun && m_pSupervision->getAnalyseur()->m_CmdStopEndCycle.ucGetVal()!=0)
		m_sEtatAnalyseur = tr("CYCLE EN COURS \n(ARRET EN FIN DE CYCLE)");    
	else 
		m_sEtatAnalyseur = tr("EN ARRET");*/
 
	//Pour le flag de fin de cycle qui permet au graph de savoir si une mesure est finit
	/*if(m_iCurrentStep < m_iPreviousStep)
		m_bFlagEndCycle = true;
	m_iPreviousStep = m_iCurrentStep;*/

	//qDebug() << "#### FIN CWinMainModel::getDataFromSupervision" ;
	checkAgeLog();
	
}
QString CWinMainModel::getNbCycleAvantBlanc()
{
	int nbCptCycle = m_pSupervision->getAnalyseur()->pGetAt(0)->m_iNbCycleZero;
	int nbCycleAFaire = m_pSupervision->getAnalyseur()->pGetAt(0)->m_PeriodicCycleZero.ucGetVal();
	nbCptCycle = nbCycleAFaire - nbCptCycle +1;
	if(nbCptCycle<1) nbCptCycle = 1;
	return QString::number(nbCptCycle);
}
//SLOT utilisé par le deuxième timer_diag
void CWinMainModel::getDataFromMeasureCard()
{
	//qDebug() << "#### CWinMainModel::getDataFromMeasureCard" ;

	//CElemExchangeJbus *pElem;
	//TCHAR szText[5000];
    m_threadPool->start(new CCmdJBusRunnable( this
                                            , m_pSupervision->getNumRQTComJBUSMesure("fTemperatureCuve")
                                            , m_pSupervision->getCarteMesure()->getListExchange()
                                            , m_pSupervision->getAnalyseur()->m_ExternalInterface));
	///*m_cycleStep.bExecuteNumExchange(m_pSupervision->getNumRQTComJBUSMesure("fTemperatureCuve")
	//						,m_pSupervision->getCarteMesure()->getListExchange()
	//					    ,TRUE,TRUE , m_pSupervision->getAnalyseur()->m_ExternalInterface);*/
	//pElem =(CElemExchangeJbus*)m_pSupervision->getCarteMesure()->getListExchange()->pGetAt(m_pSupervision->getNumRQTComJBUSMesure("fTemperatureCuve"));
	//QString sRQT = QString::fromUtf16((const ushort*)pElem->m_pTrameJbusRP->szGetConfig(szText, 5000));
	//QString sTemp1 = sRQT.split("|").at(sRQT.split("|").count()-1);
	//QString sTemp2 = sRQT.split("|").at(sRQT.split("|").count()-2);
	//QByteArray byteArray = QByteArray::number(sTemp1.toLongLong(), 16);
	//qDebug() << sTemp1 << "  " << byteArray;
	//int nPos=2;
	//if(byteArray.count() > 4) nPos = byteArray.count()-2;
	//else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	//qDebug() << sTemp1<< " bis " << byteArray;
	//QByteArray byteArrayHex = byteArray.mid(nPos, 2);
	//byteArrayHex.append(byteArray.mid(nPos-2,2));
	//byteArray = QByteArray::number(sTemp2.toLongLong(), 16);
	//qDebug() << sTemp2 << "  " << byteArray;
	//nPos=2;
	//if(byteArray.count() > 4) nPos = byteArray.count()-2;
	//else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	//qDebug() << sTemp1<< " bis " << byteArray;
	//byteArrayHex.append(byteArray.mid(nPos, 2));
	//byteArrayHex.append(byteArray.mid(nPos-2,2));
	//fTemperatureCuve = CSupervision::getFloatFromQByteArrayHex(byteArrayHex);
	//qDebug() << "fTemperatureCuve= "<< QString::number( fTemperatureCuve,'f', 5 );

 //   m_threadPool->start(new CCmdJBusRunnable( this
 //                                           , m_pSupervision->getNumRQTComJBUSMesure("fPressionEau")
 //                                           , m_pSupervision->getCarteMesure()->getListExchange()
 //                                           , m_pSupervision->getAnalyseur()->m_ExternalInterface));
	///*m_cycleStep.bExecuteNumExchange(m_pSupervision->getNumRQTComJBUSMesure("fPressionEau")
	//						,m_pSupervision->getCarteMesure()->getListExchange()
	//					    ,TRUE,TRUE , m_pSupervision->getAnalyseur()->m_ExternalInterface);*/
	//pElem =(CElemExchangeJbus*)m_pSupervision->getCarteMesure()->getListExchange()->pGetAt(m_pSupervision->getNumRQTComJBUSMesure("fPressionEau"));
	//sRQT = QString::fromUtf16((const ushort*)pElem->m_pTrameJbusRP->szGetConfig(szText, 5000));
	//sTemp1 = sRQT.split("|").at(sRQT.split("|").count()-1);
	//sTemp2 = sRQT.split("|").at(sRQT.split("|").count()-2);
	//byteArray = QByteArray::number(sTemp1.toLongLong(), 16);
	//nPos=2;
	//if(byteArray.count() > 4) nPos = byteArray.count()-2;
	//else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	//byteArrayHex = byteArray.mid(nPos, 2);
	//byteArrayHex.append(byteArray.mid(nPos-2,2));
	//byteArray = QByteArray::number(sTemp2.toLongLong(), 16);	
	//nPos=2;
	//if(byteArray.count() > 4) nPos = byteArray.count()-2;
	//else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	//byteArrayHex.append(byteArray.mid(nPos, 2));
	//byteArrayHex.append(byteArray.mid(nPos-2,2));
	//fPressionEau = CSupervision::getFloatFromQByteArrayHex(byteArrayHex);
	//qDebug() << "fPressionEau= "<< QString::number( fPressionEau,'f', 5 );

 //   m_threadPool->start(new CCmdJBusRunnable( this
 //                                           , m_pSupervision->getNumRQTComJBUSMesure("fMesureOptique")
 //                                           , m_pSupervision->getCarteMesure()->getListExchange()
 //                                           , m_pSupervision->getAnalyseur()->m_ExternalInterface));
	///*m_cycleStep.bExecuteNumExchange(m_pSupervision->getNumRQTComJBUSMesure("fMesureOptique")
	//						,m_pSupervision->getCarteMesure()->getListExchange()
	//					    ,TRUE,TRUE , m_pSupervision->getAnalyseur()->m_ExternalInterface);*/
	//pElem =(CElemExchangeJbus*)m_pSupervision->getCarteMesure()->getListExchange()->pGetAt(m_pSupervision->getNumRQTComJBUSMesure("fMesureOptique"));
	//sRQT = QString::fromUtf16((const ushort*)pElem->m_pTrameJbusRP->szGetConfig(szText, 5000));
	//sTemp1 = sRQT.split("|").at(sRQT.split("|").count()-1);
	//sTemp2 = sRQT.split("|").at(sRQT.split("|").count()-2);
	////qDebug() << sTemp1 << "  " << sTemp2;
	//byteArray = QByteArray::number(sTemp1.toLongLong(), 16);
	//nPos=2;
	//if(byteArray.count() > 4) nPos = byteArray.count()-2;
	//else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	//byteArrayHex = byteArray.mid(nPos, 2);
	//byteArrayHex.append(byteArray.mid(nPos-2,2));
	//byteArray = QByteArray::number(sTemp2.toLongLong(), 16);
	//nPos=2;
	//if(byteArray.count() > 4) nPos = byteArray.count()-2;
	//else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	//byteArrayHex.append(byteArray.mid(nPos, 2));
	//byteArrayHex.append(byteArray.mid(nPos-2,2));
	//fMesureOptique = CSupervision::getFloatFromQByteArrayHex(byteArrayHex);
	//qDebug() << "fMesureOptique= "<< QString::number( fMesureOptique,'f', 5 );

	//m_sOpticalGainLbl = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalGain.szGetLabel());
	//m_nOpticalGainValue = m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalGain.nGetVal();
	//m_sOpticalGainUnit = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalGain.m_szUnit.szGetLabel());
	
	//m_sOpticalMeasurementLbl = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalMeasurement.szGetLabel());
	//m_nOpticalMeasurementValue = m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalMeasurement.fGetVal();
	//m_sOpticalMeasurementUnit = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalMeasurement.m_szUnit.szGetLabel());
	//
	//m_sZeroOpticalMeasurementLbl = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ZeroOpticalMeasurement.szGetLabel());
	//m_nZeroOpticalMeasurementValue = m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ZeroOpticalMeasurement.fGetVal();
	//m_sZeroOpticalMeasurementUnit = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ZeroOpticalMeasurement.m_szUnit.szGetLabel());
	
	//qDebug() << "#### FIN CWinMainModel::getDataFromMeasureCard" ;
	
	
}

void CWinMainModel::setRun()
{
	m_pSupervision->getAnalyseur()->m_CmdRun.bSetVal(1);
	m_bRun=m_pSupervision->getAnalyseur()->m_CmdRun.ucGetVal();
	m_bStop = !m_bRun;
	m_sEtatAnalyseur = tr("CYCLE EN COURS");
	//pour pas qu'une nouvelle bar se mette dans le graph quand on rappuit sur play
	CElemCycle::m_CurrentStep.m_Step.bSetVal(0);
	m_iPreviousStep = 0; 
	m_iCurrentStep =0;
	
}

bool CWinMainModel::getStatusWaterFailure(int arg_numStream)const
{
    if(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream))
	    return m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->m_StatusWaterFailure.ucGetVal();
    else
        return false;
}
bool CWinMainModel::getStreamStatus(int arg_numStream)const
{
    if(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream))
        return m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->m_StatusFailure.ucGetVal();
    else
        return false;
}
bool CWinMainModel::getStatusSeuil(int arg_numStream)const
{
    if(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream))
	    return m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(0)->m_StatusThreshold1.ucGetVal();
    else
        return false;
}
bool CWinMainModel::getVoieActive(int arg_numStream)const
{
    if(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream))
        return m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->m_Active.ucGetVal();
    else
        return false;
}
bool CWinMainModel::getStatusPeriodic(int arg_numStream)const
{
	if(     m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)
        &&  m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->m_PeriodicCycleZero.ucGetVal() > 0)
		return true;
	else
		return false;
}
bool CWinMainModel::getEnPeriodic()const
{
	if(m_pSupervision->getAnalyseur()->m_CmdCycleZero.ucGetVal() != 0xFF)
		return true;
	else
		return false;
}
void CWinMainModel::setStop()
{
	m_pSupervision->getAnalyseur()->m_CmdRun.bSetVal(0);
	//m_pSupervision->getAnalyseur()->m_CmdRemoteControl
	m_bRun=m_pSupervision->getAnalyseur()->m_CmdRun.ucGetVal();
	m_bStop = !m_bRun;
	m_sEtatAnalyseur = tr("EN ARRET");

	////pour pas qu'une nouvelle bar se mette dans le graph quand on rappuit sur play
	//CElemCycle::m_CurrentStep.m_Step.bSetVal(0);
	//m_iPreviousStep = 0; 
	//m_iCurrentStep =0;

}

void CWinMainModel::setStopEndCycle()
{
	m_pSupervision->getAnalyseur()->m_CmdStopEndCycle.bSetVal(1);
	m_sEtatAnalyseur = tr("CYCLE EN COURS \n(ARRET EN FIN DE CYCLE)");
	
}
void CWinMainModel::setPause()
{
	m_pSupervision->getAnalyseur()->m_CmdPause.bSetVal(1);
	m_bPause = m_pSupervision->getAnalyseur()->m_CmdPause.ucGetVal();
	m_sEtatAnalyseur = tr("EN PAUSE");
}

void CWinMainModel::setUnpause()
{
	m_pSupervision->getAnalyseur()->m_CmdPause.bSetVal(0);
	m_bPause = m_pSupervision->getAnalyseur()->m_CmdPause.ucGetVal();
	m_sEtatAnalyseur = tr("CYCLE EN COURS");
}

void CWinMainModel::setNext()
{
	m_pSupervision->getAnalyseur()->m_CmdJumpStep.bSetVal(9999);
}
void CWinMainModel::setModeMaintenance(bool arg_bEnMaintenance)
{
    if(arg_bEnMaintenance && m_pSupervision->getAnalyseur()->m_CmdRemoteControl.ucGetVal() != CSupervision::eREMOTE_SAV)
	{
		qDebug() << "MISE EN SAV";
		m_iModeSaved = m_pSupervision->getAnalyseur()->m_CmdRemoteControl.ucGetVal();
        m_pSupervision->getAnalyseur()->m_CmdRemoteControl.bSetVal(CSupervision::eREMOTE_SAV);
		m_pSupervision->getAnalyseur()->SetRemoteControl();
        m_pSupervision->getAnalyseur()->m_CmdMaintenanceManuel.bSetVal(1);
	}
	else if(m_pSupervision->getAnalyseur()->m_CmdRemoteControl.ucGetVal() == CSupervision::eREMOTE_SAV && m_iModeSaved!=CSupervision::eREMOTE_SAV ) 
	{
		qDebug() << "RETOUR DE SAV";
		m_pSupervision->getAnalyseur()->m_CmdRemoteControl.bSetVal(m_iModeSaved);
		m_pSupervision->getAnalyseur()->SetRemoteControl();
        m_pSupervision->getAnalyseur()->m_CmdMaintenanceManuel.bSetVal(0);
	}	
}
void CWinMainModel::setConnexion()
{

	//PAr trigger ou timer ?
	m_timerCycle = new QTimer(this);
	connect(m_timerCycle, SIGNAL(timeout()), this, SLOT(getDataFromSupervision()));
	//Signal de mise à jour à la vue
	connect(m_timerCycle, SIGNAL(timeout()), m_pView, SLOT(dataUpdate())); 
	
	m_timerDiag = new QTimer(this);
	connect(m_timerDiag, SIGNAL(timeout()), this, SLOT(getDataFromMeasureCard()));
	connect(m_timerDiag, SIGNAL(timeout()), m_pView, SLOT(dataUpdate())); 
	
	m_timerCycle->setInterval(1000);
	m_timerCycle->start();
	m_timerDiag->setInterval(1000);
}

//Appelé lors de getDataFromSupervision
void CWinMainModel::checkAgeLog()
{
	//une vérfie toute les heures pendant la mesure
	if(++m_iCptPurgeLog>3600)
	{
		QStringList listErrorPrgFiles = m_logErrorPrgFileDir->entryList(QDir::Files, QDir::Time);
		int nbFilesToDelete = m_logErrorPrgFileDir->count()-m_nbrDayRetentionErrorLog;
		if(nbFilesToDelete>0)
		{
			for(; nbFilesToDelete<0; --nbFilesToDelete)
			{
				qDebug() << listErrorPrgFiles.last();
				m_logErrorPrgFileDir->remove(listErrorPrgFiles.takeLast());
			}
		}
		QStringList listFiles = m_logFileDir->entryList(QDir::Files, QDir::Time);
		nbFilesToDelete = m_logFileDir->count()-m_nbrDayRetentionLog;
		if(nbFilesToDelete>0)
		{
			for(; nbFilesToDelete<0; --nbFilesToDelete)
			{
				qDebug() << listFiles.last();
				m_logFileDir->remove(listFiles.takeLast());
			}
		}
		QStringList listUserFiles = m_logUserFileDir->entryList(QDir::Files, QDir::Time);
		nbFilesToDelete = m_logUserFileDir->count()-m_nbrDayRetentionUserLog;
		if(nbFilesToDelete>0)
		{
			for(; nbFilesToDelete<0; --nbFilesToDelete)
			{
				qDebug() << listUserFiles.last();
				m_logUserFileDir->remove(listUserFiles.takeLast());
			}
		}
		m_iCptPurgeLog = 0;
	}
}

bool CWinMainModel::getFlagEndCycle()
{
    int iCurrentStep =  CElemCycle::m_CurrentStep.m_Step.nGetVal();
    bool bResult = false;
    if(iCurrentStep < m_iPreviousStep)
		bResult = true;
	m_iPreviousStep = iCurrentStep;
    return bResult;
}

float CWinMainModel::getBoutPlageMax(int arg_iStream, int arg_iMeasure)
{
    if(m_pSupervision->getAnalyseur()->pGetAt(arg_iStream))
	    return m_pSupervision->getAnalyseur()->pGetAt(arg_iStream)->pGetAt(arg_iMeasure)->m_AnalogPlage.fGetVal();
    else
        return 0;
}
float CWinMainModel::getBoutPlageMin(int arg_iStream, int arg_iMeasure)
{
    if(m_pSupervision->getAnalyseur()->pGetAt(arg_iStream))
	    return m_pSupervision->getAnalyseur()->pGetAt(arg_iStream)->pGetAt(arg_iMeasure)->m_AnalogZero.fGetVal();
    else
        return 0;
}

int CWinMainModel::getNbStream()const
{
	return m_pSupervision->getAnalyseur()->iGetNbrStream();
}

int CWinMainModel::getNbMeasure(int numStream)const
{
	if(m_pSupervision->getAnalyseur()->pGetAt(numStream))
		return m_pSupervision->getAnalyseur()->pGetAt(numStream)->iGetNbrMesure();
	else
		return 0;
}

QString CWinMainModel::getMesureValue(int numStream, int numMeasure)const
{
	if(    m_pSupervision->getAnalyseur()->pGetAt(numStream) 
		&& m_pSupervision->getAnalyseur()->pGetAt(numStream)->pGetAt(numMeasure))
        return QString::number(m_pSupervision->getAnalyseur()->pGetAt(numStream)->pGetAt(numMeasure)->m_Val.fGetVal(), 'f', 2);
	else
		return "NaN";
}

QString CWinMainModel::getMesureValueUnit(int numStream, int numMeasure)const
{
	if(    m_pSupervision->getAnalyseur()->pGetAt(numStream) 
		&& m_pSupervision->getAnalyseur()->pGetAt(numStream)->pGetAt(numMeasure))
		return QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(numStream)->pGetAt(numMeasure)->m_Val.m_szUnit.szGetLabel());
	else
		return "NaN";
}
QString CWinMainModel::getMesureValueLbl(int numStream, int numMeasure)const
{
	if(    m_pSupervision->getAnalyseur()->pGetAt(numStream) 
		&& m_pSupervision->getAnalyseur()->pGetAt(numStream)->pGetAt(numMeasure))
		return QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(numStream)->pGetAt(numMeasure)->m_Val.szGetLabel());
	else
		return "NaN";
}