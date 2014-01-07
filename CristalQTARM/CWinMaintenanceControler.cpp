#include "CWinMaintenanceControler.h"
#include "CWinMaintenanceModel.h"
#include "CWinMaintenanceView.h"
#include "CSupervision.h"
#include "CWinMainControler.h"
#include "CDialogValEtalon.h"
#include "CDialogResultatEtalon.h"
#include "CUserSession.h"

CWinMaintenanceControler* CWinMaintenanceControler::singletonControler = 0;

CWinMaintenanceControler::CWinMaintenanceControler(CWinMainControler* argpWinMainControler)
{
	m_pWinMainControler = argpWinMainControler;
	m_pSupervision = argpWinMainControler->getpSupervision();
	m_pView  = new CWinMaintenanceView(this);
	m_pModel = new CWinMaintenanceModel(m_pSupervision, m_pView);
	m_pView->setModel(m_pModel);

	//Attention, état de la visu et pas du la suppervision (ie m_CmdCycleCalib, les deux données ne sont pas redondante)
	m_bCycleCalibEnCours = false; 
	m_bCycleCalibInLineEnCours = false;
	m_bCycleZeroEnCours = false;
	m_bCycleCleanupEnCours = false;

	m_numTabIndex = 0;
	m_numStream = 0;
}
//SLOT
void CWinMaintenanceControler::btBackPressed()
{
	CUserSession::getInstance()->poke();
	CUserSession::getInstance()->objectUnregister(this);
	m_pModel->retourAnalyseurDeMaintenance();
	m_pView->close();
	m_pWinMainControler->execControler();
}
//SLOT 
void CWinMaintenanceControler::btStopPressed()
{
	m_pView->setPressedBtExecuteCalib(false, m_numStream);
	m_pView->setPressedBtExecuteCalibInLine(false, m_numStream);
	m_pView->setPressedBtExecuteCleanup(false, m_numStream);
	m_pView->setPressedBtExecuteZero(false, m_numStream);
	m_pView->setEnabledBtBack(true);
	m_pView->setEnabledBtExecuteCalib(true, m_numStream);
	m_pView->setEnabledBtExecuteCalibInLine(true, m_numStream);
	m_pView->setEnabledBtExecuteCleanup(true, m_numStream);
	m_pView->setEnabledBtExecuteZero(true, m_numStream);

	m_pView->setEnabledLblCalib(true, m_numStream);
	m_pView->setEnabledLblCalibInLine(true, m_numStream);
	m_pView->setEnabledLblCleanup(true, m_numStream);
	m_pView->setEnabledLblZero(true, m_numStream);
	m_pView->razlblCurrentStep(m_numStream);
	m_pView->razlblNameStep(m_numStream);
	m_pModel->setStop();
	
}
//SLOT
void CWinMaintenanceControler::btExecuteCalibPressed()
{
    qDebug()<< "CWinMaintenanceControler::btExecuteCalibPressed()" << m_numStream;
#ifdef CALIBRATIONS_INDEPENDANTE
	m_numStream = m_numTabIndex;
#endif
	if(m_pView->getEnabledLblCalib(m_numStream))
	{
		m_pDialogValEtalon = CDialogValEtalon::getInstance();
		connect(m_pDialogValEtalon, SIGNAL(accepted()), this, SLOT(executeCalibAccepted()));
		//connect(m_pDialogValEtalon, SIGNAL(rejected()), this, SLOT(hexecuteCalibRejected()));
		m_pDialogValEtalon->setTittle(tr("VALEUR ETALON"));
		m_pDialogValEtalon->setLine(m_pModel->sGetEtalonRefLbl(m_numStream, 0), m_pModel->sGetEtalonRefVal(m_numStream, 0));
#if defined(MULTI_MEASURE)&& !defined(CHROME) && !defined(MAGNESIUM) 
		m_pDialogValEtalon->setLine2(m_pModel->sGetEtalonRefLbl(m_numStream, 1), m_pModel->sGetEtalonRefVal(m_numStream, 1));
#endif
		m_pDialogValEtalon->exec();
	}
	else if(m_pModel->getEnPause())
	{
		m_pModel->setEnPause(false);
		m_pView->setPressedBtExecuteCalib(true, m_numStream);
	}
	else
		m_pView->setPressedBtExecuteCalib(true, m_numStream);
    qDebug()<< "FIN CWinMaintenanceControler::btExecuteCalibPressed()";

}

//SLOT
void CWinMaintenanceControler::executeCalibRejected()
{

}
//SLOT
void CWinMaintenanceControler::btExecuteCalibInLinePressed()
{
#ifdef CALIBRATIONS_INDEPENDANTE
	m_numStream = m_numTabIndex;
#endif
	if(m_pView->getEnabledLblCalibInLine(m_numStream))
	{
		m_pDialogValEtalon = CDialogValEtalon::getInstance();
#if !defined(COULEUR) && !defined(SONDE)
		connect(m_pDialogValEtalon, SIGNAL(accepted()), this, SLOT(executeCalibInLineAccepted()));
		//connect(m_pDialogValEtalon, SIGNAL(rejected()), this, SLOT(executeCalibRejected()));
		m_pDialogValEtalon->setTittle(tr("VALEUR ETALON"));
		m_pDialogValEtalon->setLine(m_pModel->sGetEtalonRefLbl(m_numStream,0), m_pModel->sGetEtalonRefVal(m_numStream,0));
#ifdef MULTI_MEASURE
		m_pDialogValEtalon->setLine2(m_pModel->sGetEtalonRefLbl(m_numStream,1), m_pModel->sGetEtalonRefVal(m_numStream,1));
#endif
		m_pDialogValEtalon->exec();
#else
        executeCalibInLineAccepted();
#endif
	}
	else if(m_pModel->getEnPause())
	{
		m_pModel->setEnPause(false);
		m_pView->setPressedBtExecuteCalibInLine(true, m_numStream);
	}
	else
		m_pView->setPressedBtExecuteCalibInLine(true, m_numStream);
}
//SLOT
void CWinMaintenanceControler::btExecuteCleanupPressed()
{
#ifdef CALIBRATIONS_INDEPENDANTE
	m_numStream = m_numTabIndex;
#endif
	if(m_pView->getEnabledLblCleanup(m_numStream))
	{
		m_pDialogValEtalon = CDialogValEtalon::getInstance();
		//connect(m_pDialogValEtalon, SIGNAL(accepted()), this, SLOT(executeCleanupAccepted()));
		////connect(m_pDialogValEtalon, SIGNAL(rejected()), this, SLOT(executeCalibRejected()));
		//m_pDialogValEtalon->setTittle(tr("VALEUR ETALON"));
		//m_pDialogValEtalon->setLine(m_pModel->sGetEtalonRefLbl(), m_pModel->sGetEtalonRefVal());
		//m_pDialogValEtalon->exec();
		executeCleanupAccepted();
	}
	else if(m_pModel->getEnPause())
	{
		m_pModel->setEnPause(false);
		m_pView->setPressedBtExecuteCleanup(true, m_numStream);
	}
	else
		m_pView->setPressedBtExecuteCleanup(true, m_numStream);
}
//SLOT
void CWinMaintenanceControler::btExecuteZeroPressed()
{
#ifdef CALIBRATIONS_INDEPENDANTE
	m_numStream = m_numTabIndex;
#endif
	if(m_pView->getEnabledLblZero(m_numStream))
	{
		m_pDialogValEtalon = CDialogValEtalon::getInstance();
        //connect(m_pDialogValEtalon, SIGNAL(accepted()), this, SLOT(executeZeroAccepted()));
		////connect(m_pDialogValEtalon, SIGNAL(rejected()), this, SLOT(executeCalibRejected()));
		//m_pDialogValEtalon->setTittle(tr("VALEUR OFFSET"));
		//m_pDialogValEtalon->setLine(m_pModel->sGetOffsetActuelLbl(), m_pModel->sGetOffsetActuelVal());
//#ifdef COULEUR
//        m_pDialogValEtalon->setTittle(tr("VALEUR ETALON"));
//		m_pDialogValEtalon->setLine(m_pModel->sGetEtalonEauRefLbl(), m_pModel->sGetEtalonEauRefVal());
//		if(m_pDialogValEtalon->exec())	
//#endif
		executeZeroAccepted();

	}
	else if(m_pModel->getEnPause())
	{
		m_pModel->setEnPause(false);
		m_pView->setPressedBtExecuteZero(true, m_numStream);
	}
	else
		m_pView->setPressedBtExecuteZero(true, m_numStream);
}
//SLOT
void CWinMaintenanceControler::executeCalibAccepted()
{
    qDebug()<< "CWinMaintenanceControler::executeCalibAccepted()" << m_numStream;

	//Modifier la valeur étalon
	m_pView->setEnabledLblCalib(false, m_numStream);
	qDebug()<< "GA" ;
	
	m_pView->setEnabledBtBack(false);
	qDebug()<< "GA" ;
	m_pView->setPressedBtExecuteCalib(true, m_numStream);
	m_pView->setEnabledBtExecuteCalibInLine(false, m_numStream);
	m_pView->setEnabledBtExecuteCleanup(false, m_numStream);
	m_pView->setEnabledBtExecuteZero(false, m_numStream);
	qDebug()<< "GA" ;

	m_pModel->setEtalonRefVal(m_pDialogValEtalon->getReturnValue(),m_numStream, 0);
	m_sAncienCoefActuel = m_pModel->sGetCoefActuelVal(m_numStream, 0);
#if defined(MULTI_MEASURE) && !defined(CHROME) && !defined(MAGNESIUM)
	qDebug()<< "GA" ;

	m_pModel->setEtalonRefVal(m_pDialogValEtalon->getReturnValue2(),m_numStream ,1);
	m_sAncienCoefActuel2 = m_pModel->sGetCoefActuelVal(m_numStream, 1);
#elif defined(MULTI_MEASURE) && (defined(CHROME)||defined(MAGNESIUM))
	m_pModel->setEtalonRefVal(m_pDialogValEtalon->getReturnValue(),m_numStream ,1);
	m_sAncienCoefActuel2 = m_pModel->sGetCoefActuelVal(m_numStream, 1);
#endif
	//Exécuter le cycle de maintenance
	m_bCycleCalibEnCours = true;
	qDebug()<< "GA" ;

	m_pModel->executeCalib(m_numStream);
    qDebug()<< "FIN CWinMaintenanceControler::executeCalibAccepted()";

}
//SLOT
void CWinMaintenanceControler::executeCalibInLineAccepted()
{
	//Modifier la valeur étalon
	m_pView->setEnabledLblCalibInLine(false, m_numStream);
	m_pView->setEnabledBtBack(false);
	m_pView->setEnabledBtExecuteCalib(false, m_numStream);
	m_pView->setPressedBtExecuteCalibInLine(true, m_numStream);
	m_pView->setEnabledBtExecuteCleanup(false, m_numStream);
	m_pView->setEnabledBtExecuteZero(false, m_numStream);
	m_pModel->setEtalonRefVal(m_pDialogValEtalon->getReturnValue(), m_numStream,0);

	m_sAncienOffsetActuel = m_pModel->sGetOffsetActuelVal(m_numStream);
	m_sAncienCoefActuel = m_pModel->sGetCoefActuelVal(m_numStream, 0);
#ifdef MULTI_MEASURE
	m_pModel->setEtalonRefVal(m_pDialogValEtalon->getReturnValue2(), m_numStream,1);
	m_sAncienCoefActuel2 = m_pModel->sGetCoefActuelVal(m_numStream, 1);
#endif
	//Exécuter le cycle de maintenance
	m_bCycleCalibInLineEnCours = true;
	m_pModel->executeCalibInLine(m_numStream);

}
//SLOT
void CWinMaintenanceControler::executeCleanupAccepted()
{
	//Modifier la valeur étalon
	m_pView->setEnabledLblCleanup(false, m_numStream);
	m_pView->setEnabledBtBack(false);
	m_pView->setEnabledBtExecuteCalib(false, m_numStream);
	m_pView->setEnabledBtExecuteCalibInLine(false, m_numStream);
	m_pView->setPressedBtExecuteCleanup(true, m_numStream);
	m_pView->setEnabledBtExecuteZero(false, m_numStream);
	//m_pModel->setEtalonRefVal(m_pDialogValEtalon->getReturnValue());

	m_sAncienMesureManuelle = m_pModel->sGetMesureManuelleVal(m_numStream, 0);
	//Exécuter le cycle de maintenance
	m_bCycleCleanupEnCours = true;
	m_pModel->executeCleanup(m_numStream);

}
//SLOT
void CWinMaintenanceControler::executeZeroAccepted()
{
	//Modifier la valeur étalon
	m_pView->setEnabledLblZero(false, m_numStream);
	m_pView->setEnabledBtExecuteCalib(false, m_numStream);
	m_pView->setEnabledBtExecuteCalibInLine(false, m_numStream);
	m_pView->setEnabledBtExecuteCleanup(false, m_numStream);
	m_pView->setPressedBtExecuteZero(true, m_numStream);
	m_pView->setEnabledBtBack(false);
	m_pModel->setEtalonRefVal(m_pDialogValEtalon->getReturnValue(),m_numStream,0);

	m_sAncienOffsetActuel = m_pModel->sGetOffsetActuelVal(m_numStream);
	//Exécuter le cycle de maintenance
	m_bCycleZeroEnCours = true;
	m_pModel->executeZero(m_numStream);

}
//SLOT
void CWinMaintenanceControler::cycleMaintenanceFinished()
{
	qDebug() << "CWinMaintenanceControler::cycleMaintenanceFinished()" << m_pView->getPressedBtExecuteCalib(m_numStream);
	m_pView->setTabIndex(m_numStream); //remet sur la tab maintenance si était sur diag ou sur la mauvaise voie
	btStopPressed();
	
	m_pDialogResultatEtalon = CDialogResultatEtalon::getInstance();
	/*connect(m_pDialogResultatEtalon, SIGNAL(accepted()), this, SLOT(cycleCalibFinishedAccepted()));
	connect(m_pDialogResultatEtalon, SIGNAL(rejected()), this, SLOT(cycleCalibFinishedRejected()));*/
	if(m_bCycleCalibEnCours)//m_pView->getPressedBtExecuteCalib()) //isDown irémédiablement en faux si sur onglet diag d'ou l'ajout de m_bCycleCalibEnCours
	{
		m_bCycleCalibEnCours=false;
		m_pDialogResultatEtalon->setTittle(tr("RESULTATS ETALONNAGE"));
		//m_pDialogResultatEtalon->setLine(m_pModel->sGetEtalonRefLbl(), m_pModel->sGetEtalonRefVal());
		m_pDialogResultatEtalon->setLine(m_pModel->sGetCoefActuelLbl(m_numStream, 0), m_sAncienCoefActuel);
		m_pDialogResultatEtalon->setLine2(m_pModel->sGetCoefCalculeLbl(m_numStream, 0), m_pModel->sGetCoefCalculeVal(m_numStream, 0));
#if defined(SILICE) && !defined(MULTI_MEASURE)
		float fMesureAvantEtalon = 
				(m_pModel->sGetEtalonRefVal(m_numStream, 0).toFloat() * 
				m_sAncienCoefActuel.toFloat()) / m_pModel->sGetCoefCalculeVal(m_numStream, 0).toFloat();
		m_pDialogResultatEtalon->setLine3(tr("Mesure avant étalonnage"), QString::number(fMesureAvantEtalon, 'f', 2));
		m_pDialogResultatEtalon->setLine4(tr("Mesure après étalonnage"), m_pModel->sGetEtalonRefVal(m_numStream,0));
#endif
#ifdef MULTI_MEASURE
        m_pDialogResultatEtalon->setLine3(m_pModel->sGetCoefActuelLbl(m_numStream, 1), m_sAncienCoefActuel2);
		m_pDialogResultatEtalon->setLine4(m_pModel->sGetCoefCalculeLbl(m_numStream, 1), m_pModel->sGetCoefCalculeVal(m_numStream, 1));

        //Erreur d'étalonnage si écart entre ancien et nouveau > à 50%
		if( m_pModel->bGetCoefStatus(m_numStream, 0) && m_pModel->bGetCoefStatus(m_numStream, 1))
		{
			m_pDialogResultatEtalon->setLblMessageErreur(tr("Erreur étalonnage mesure 1 et 2"));
			if(!CUserSession::getInstance()->amIAdmin())
				m_pDialogResultatEtalon->disabledBtApply();
		}
        else if(m_pModel->bGetCoefStatus(m_numStream, 0))
        {
            m_pDialogResultatEtalon->setLblMessageErreur(tr("Erreur étalonnage mesure 1"));
			if(!CUserSession::getInstance()->amIAdmin())
				m_pDialogResultatEtalon->disabledBtApply();
        }
        else if(m_pModel->bGetCoefStatus(m_numStream, 1))
        {
            m_pDialogResultatEtalon->setLblMessageErreur(tr("Erreur étalonnage mesure 2"));
			if(!CUserSession::getInstance()->amIAdmin())
				m_pDialogResultatEtalon->disabledBtApply();
        }
        if(m_pModel->bGetCoefStatus(m_numStream, 0) || m_pModel->bGetCoefStatus(m_numStream, 1))
        {
            m_pModel->setCoefActuelVal(m_sAncienCoefActuel, m_numStream, 0);
			m_pModel->setCoefCalculeVal(m_sAncienCoefActuel, m_numStream,0);
            m_pModel->setCoefActuelVal(m_sAncienCoefActuel2, m_numStream,1);
			m_pModel->setCoefCalculeVal(m_sAncienCoefActuel2, m_numStream,1);
        }
#else
		//Erreur d'étalonnage si écart entre ancien et nouveau > à 50%
		if( m_pModel->bGetCoefStatus(m_numStream, 0) )
		{
			m_pDialogResultatEtalon->setLblMessageErreur(tr("Erreur étalonnage"));
            m_pModel->setCoefActuelVal(m_sAncienCoefActuel ,m_numStream, 0);
			m_pModel->setCoefCalculeVal(m_sAncienCoefActuel ,m_numStream, 0);
			if(!CUserSession::getInstance()->amIAdmin())
				m_pDialogResultatEtalon->disabledBtApply();
		}

#endif
		if(m_pDialogResultatEtalon->exec())
		{
			//m_pModel->setEtalonRefVal(m_pDialogResultatEtalon->getReturnValue());
			m_pModel->setCoefActuelVal(m_pDialogResultatEtalon->getReturnValue2(),m_numStream, 0);
			m_pModel->setCoefCalculeVal(m_pDialogResultatEtalon->getReturnValue2(),m_numStream, 0);
#ifdef MULTI_MEASURE
            m_pModel->setCoefActuelVal(m_pDialogResultatEtalon->getReturnValue4(),m_numStream, 1);
			m_pModel->setCoefCalculeVal(m_pDialogResultatEtalon->getReturnValue4(),m_numStream, 1);
#endif
		}
		else
		{
			m_pModel->setCoefActuelVal(m_sAncienCoefActuel,m_numStream,0);
#ifdef MULTI_MEASURE
			m_pModel->setCoefActuelVal(m_sAncienCoefActuel2,m_numStream,1);
#endif
		}

	}
	else if (m_bCycleCalibInLineEnCours) //m_pView->getPressedBtExecuteCalibInLine())
	{
		m_bCycleCalibInLineEnCours=false;
#ifdef COULEUR
        m_pDialogResultatEtalon->setTittle(tr("RESULTATS ZERO EAU-AIR"));
		m_pDialogResultatEtalon->setLine(m_pModel->sGetIndicateurEauAirLbl(), m_pModel->sGetIndicateurEauAirVal());	
		if( m_pModel->bGetOffsetStatus(m_numStream) )
		{
			m_pDialogResultatEtalon->setLblMessageErreur(tr("Erreur zéro eau-air"));
			if(!CUserSession::getInstance()->amIAdmin())
				m_pDialogResultatEtalon->disabledBtApply();
		}
		if(m_pDialogResultatEtalon->exec())
		{	
			m_pModel->setIndicateurEauAirVal(m_pDialogResultatEtalon->getReturnValue());	
		}
#elif defined(SONDE)
        m_pDialogResultatEtalon->setTittle(tr("RESULTATS ETALONNAGE SONDE"));
		//m_pDialogResultatEtalon->setLine(m_pModel->sGetEtalonRefLbl(), m_pModel->sGetEtalonRefVal());
		m_pDialogResultatEtalon->setLine(m_pModel->sGetOffsetActuelLbl(m_numStream),m_sAncienOffsetActuel);
		m_pDialogResultatEtalon->setLine2(m_pModel->sGetOffsetCalculeLbl(m_numStream),m_pModel->sGetOffsetCalculeVal(m_numStream));
		if( m_pModel->bGetCoefStatus(m_numStream,0) )
		{
			m_pDialogResultatEtalon->setLblMessageErreur(tr("Erreur étalonnage"));
			if(!CUserSession::getInstance()->amIAdmin())
				m_pDialogResultatEtalon->disabledBtApply();
		}
		if(m_pDialogResultatEtalon->exec())
		{
			//m_pModel->setEtalonRefVal(m_pDialogResultatEtalon->getReturnValue());
			m_pModel->setOffsetActuelVal(m_pDialogResultatEtalon->getReturnValue2(), m_numStream);
			m_pModel->setOffsetCalculeVal(m_pDialogResultatEtalon->getReturnValue2(), m_numStream);
		}
		else
		{
			m_pModel->setOffsetActuelVal(m_sAncienOffsetActuel, m_numStream);
		}
#else       
		m_pDialogResultatEtalon->setTittle(tr("RESULTATS ETALONNAGE EN LIGNE"));
		//m_pDialogResultatEtalon->setLine(m_pModel->sGetEtalonRefLbl(), m_pModel->sGetEtalonRefVal());
       // qDebug() << "m_sAncienCoefActuel" << m_sAncienCoefActuel;
		m_pDialogResultatEtalon->setLine(m_pModel->sGetCoefActuelLbl(m_numStream, 0), m_sAncienCoefActuel);
		m_pDialogResultatEtalon->setLine2(m_pModel->sGetCoefCalculeLbl(m_numStream, 0), m_pModel->sGetCoefCalculeVal(m_numStream,0));
#ifdef MULTI_MEASURE
        m_pDialogResultatEtalon->setLine3(m_pModel->sGetCoefActuelLbl(m_numStream, 1), m_sAncienCoefActuel2);
		m_pDialogResultatEtalon->setLine4(m_pModel->sGetCoefCalculeLbl(m_numStream, 1), m_pModel->sGetCoefCalculeVal(m_numStream,1));

        //Erreur d'étalonnage si écart entre ancien et nouveau > à 50%
		if( m_pModel->bGetCoefStatus(m_numStream, 0) && m_pModel->bGetCoefStatus(m_numStream, 1))
		{
			m_pDialogResultatEtalon->setLblMessageErreur(tr("Erreur étalonnage mesure 1 et 2"));
			if(!CUserSession::getInstance()->amIAdmin())
				m_pDialogResultatEtalon->disabledBtApply();
		}
        else if(m_pModel->bGetCoefStatus(m_numStream, 0))
        {
            m_pDialogResultatEtalon->setLblMessageErreur(tr("Erreur étalonnage mesure 1"));
			if(!CUserSession::getInstance()->amIAdmin())
				m_pDialogResultatEtalon->disabledBtApply();
        }
        else if(m_pModel->bGetCoefStatus(m_numStream, 1))
        {
            m_pDialogResultatEtalon->setLblMessageErreur(tr("Erreur étalonnage mesure 2"));
			if(!CUserSession::getInstance()->amIAdmin())
				m_pDialogResultatEtalon->disabledBtApply();
        }
        if(m_pModel->bGetCoefStatus(m_numStream, 0) || m_pModel->bGetCoefStatus(m_numStream, 1))
        {
            m_pModel->setCoefActuelVal(m_sAncienCoefActuel,m_numStream, 0);
			m_pModel->setCoefCalculeVal(m_sAncienCoefActuel,m_numStream, 0);
            m_pModel->setCoefActuelVal(m_sAncienCoefActuel2,m_numStream, 1);
			m_pModel->setCoefCalculeVal(m_sAncienCoefActuel2,m_numStream, 1);
        }
		if(m_pDialogResultatEtalon->exec())
		{
			//m_pModel->setEtalonRefVal(m_pDialogResultatEtalon->getReturnValue());
			m_pModel->setCoefActuelVal(m_pDialogResultatEtalon->getReturnValue2(),m_numStream, 0);
			m_pModel->setCoefCalculeVal(m_pDialogResultatEtalon->getReturnValue2(),m_numStream, 0);
			m_pModel->setCoefActuelVal(m_pDialogResultatEtalon->getReturnValue4(),m_numStream, 1);
			m_pModel->setCoefCalculeVal(m_pDialogResultatEtalon->getReturnValue4(),m_numStream, 1);
		}
		else
		{
			m_pModel->setCoefActuelVal(m_sAncienCoefActuel,m_numStream, 0);
			m_pModel->setCoefActuelVal(m_sAncienCoefActuel2,m_numStream, 1);
		}
#else
		if( m_pModel->bGetCoefStatus(0,m_numStream) )
		{
			m_pDialogResultatEtalon->setLblMessageErreur(tr("Erreur étalonnage"));
			if(!CUserSession::getInstance()->amIAdmin())
				m_pDialogResultatEtalon->disabledBtApply();
		}
		if(m_pDialogResultatEtalon->exec())
		{
			//m_pModel->setEtalonRefVal(m_pDialogResultatEtalon->getReturnValue());
			m_pModel->setCoefActuelVal(m_pDialogResultatEtalon->getReturnValue2(),m_numStream,0);
			m_pModel->setCoefCalculeVal(m_pDialogResultatEtalon->getReturnValue2(),m_numStream,0);
		}
		else
		{
			m_pModel->setCoefActuelVal(m_sAncienCoefActuel,m_numStream,0);
		}
#endif
#endif
	}
	else if (m_bCycleZeroEnCours)//m_pView->getPressedBtExecuteZero())
	{
#ifdef KMNO4
        //MODIF KMnO4
		m_bCycleZeroEnCours=false;
		m_pDialogResultatEtalon->setTittle(tr("RESULTATS DU BLANC"));
		m_pDialogResultatEtalon->setLine(m_pModel->sGetV0Lbl(), m_pModel->sGetV0Val());
		m_pDialogResultatEtalon->setLine2(m_pModel->sGetV2Lbl(), m_pModel->sGetV2Val());
		if( m_pModel->bGetOffsetStatus(m_numStream) )
		{
			m_pDialogResultatEtalon->setLblMessageErreur(tr("Erreur étalonnage"));
			if(!CUserSession::getInstance()->amIAdmin())
				m_pDialogResultatEtalon->disabledBtApply();
		}
		if(m_pDialogResultatEtalon->exec())
		{
			m_pModel->setV0Val(m_pDialogResultatEtalon->getReturnValue());
			m_pModel->setV2Val(m_pDialogResultatEtalon->getReturnValue2());

		}
		else
		{
			m_pModel->setOffsetActuelVal(m_sAncienOffsetActuel, m_numStream);
		}

		//FIN MODIF KMnO4
#elif defined(PH)
        m_bCycleZeroEnCours=false;
		m_pDialogResultatEtalon->setTittle(tr("RESULTATS MESURE PH"));
		m_pDialogResultatEtalon->setLine(m_pModel->sGetMesurePHLbl(), m_pModel->sGetMesurePHVal());
		m_pDialogResultatEtalon->exec();

		
#else
		m_bCycleZeroEnCours=false;
		m_pDialogResultatEtalon->setTittle(tr("RESULTATS ETALONNAGE ZERO"));
		m_pDialogResultatEtalon->setLine(m_pModel->sGetOffsetActuelLbl(m_numStream), m_sAncienOffsetActuel);
		m_pDialogResultatEtalon->setLine2(m_pModel->sGetOffsetCalculeLbl(m_numStream), m_pModel->sGetOffsetCalculeVal(m_numStream));
		if( m_pModel->bGetOffsetStatus(m_numStream) )
		{
			m_pDialogResultatEtalon->setLblMessageErreur(tr("Erreur étalonnage"));
			if(!CUserSession::getInstance()->amIAdmin())
				m_pDialogResultatEtalon->disabledBtApply();
		}
#ifndef COULEUR //cycle simple de nétoyage, ne rien retourner
		if(m_pDialogResultatEtalon->exec())
		{
			m_pModel->setOffsetActuelVal(m_pDialogResultatEtalon->getReturnValue2(), m_numStream);
			m_pModel->setOffsetCalculeVal(m_pDialogResultatEtalon->getReturnValue2(), m_numStream);

		}
		else
		{
			m_pModel->setOffsetActuelVal(m_sAncienOffsetActuel, m_numStream);
		} 
#endif
#endif	
	}
	else if (m_bCycleCleanupEnCours) // m_pView->getPressedBtExecuteCleanup())
	{
		m_bCycleCleanupEnCours=false;
		m_pDialogResultatEtalon->setTittle(tr("RESULTATS MESURE MANUELLE"));
#if defined(MULTI_MEASURE)
        m_pDialogResultatEtalon->setLine(m_pModel->sGetMesureManuelleLbl(m_numStream, 0), m_pModel->sGetMesureManuelleVal(m_numStream, 0));
#ifndef MAGNESIUM
		m_pDialogResultatEtalon->setLine2(m_pModel->sGetMesureManuelleLbl(m_numStream,1), m_pModel->sGetMesureManuelleVal(m_numStream,1));
#endif
		if(m_pDialogResultatEtalon->exec())
		{
			m_pModel->setMesureManuelleVal(m_pDialogResultatEtalon->getReturnValue(), m_numStream,0);
#ifndef MAGNESIUM
			m_pModel->setMesureManuelleVal(m_pDialogResultatEtalon->getReturnValue2(), m_numStream,1);
#endif
		}
#else
		m_pDialogResultatEtalon->setLine(m_pModel->sGetMesureManuelleLbl(m_numStream,0)+ tr(" (Av)"), m_sAncienMesureManuelle);
		m_pDialogResultatEtalon->setLine2(m_pModel->sGetMesureManuelleLbl(m_numStream,0), m_pModel->sGetMesureManuelleVal(m_numStream,0));
		if(m_pDialogResultatEtalon->exec())
		{
			m_pModel->setMesureManuelleVal(m_pDialogResultatEtalon->getReturnValue2(), m_numStream,0);
		}
#endif
	}
	
}
//SLOT
void CWinMaintenanceControler::cycleCalibFinishedAccepted()
{
	/*m_pModel->setEtalonRefVal(m_pDialogResultatEtalon->getReturnValue());
	m_pModel->setCoefActuelVal(m_pDialogResultatEtalon->getReturnValue2());
	m_pModel->setCoefCalculeVal(m_pDialogResultatEtalon->getReturnValue3());*/
}
//SLOT
void CWinMaintenanceControler::cycleCalibFinishedRejected()
{

}
//SLOT
void CWinMaintenanceControler::tabChanged(int index)
{
	qDebug() << "###### tab num " << index << endl;
	m_numTabIndex = index;
	switch(index)
	{
		
		//Tab Maintenance
		case 0 :
			//m_pModel->setStartTimerCycle();
			m_pModel->setStopTimerDiag();
			break;
		//tab diag
#ifdef CERIUM
		case 3:
#else
		case 1:
#endif
			//m_pModel->setStopTimerCycle();
			m_pModel->setStartTimerDiag();

			break;
		//autre
		default:
			//m_pModel->setStopTimerCycle();
			m_pModel->setStopTimerDiag();	
			break;
	}
}
//SLOT
void CWinMaintenanceControler::userSessionClosed()
{
	qDebug() << "##### CWinMaintenanceControler::userSessionClosed()" << endl;
	CUserSession::getInstance()->loginAsLastUser(true);
}
void CWinMaintenanceControler::execControler()
{
	//Passage en mode SAV
	m_pModel->passerAnalyseurEnMaintenance();
	//m_pView->setEnabledBtExecuteCalibInLine(false);
	//m_pView->setEnabledBtExecuteZero(false);
	//m_pView->setEnabledBtExecuteCleanup(false);
	m_pView->razlblCurrentStep(m_numStream);
	m_pView->razlblNameStep(m_numStream);
	m_pView->showFullScreen();
	
	CUserSession::getInstance()->objectRegister(this);
}

CWinMaintenanceControler* CWinMaintenanceControler::getInstance(CWinMainControler* argpWinMainControler)
{
		if(!singletonControler)
			singletonControler = new CWinMaintenanceControler(argpWinMainControler);

		return singletonControler;
}
