#include "CWinElecTestControler.h"
#include "CWinEVPompeModel.h"
#include "CWinExternalCardModel.h"
#include "CWinMeasureCardModel.h"
#include "CWinStreamSelectorModel.h"
#include "CWinElecTestView.h"
#include "CSupervision.h"
#include "CWinMainControler.h"
#include "CUserSession.h"
#include "CDialogPaveNum.h"
#include "header_qt.h"



CWinElecTestControler *CWinElecTestControler::singletonControler = 0;

CWinElecTestControler::CWinElecTestControler(CWinMainControler* argpWinMainControler)
{
	qDebug() << "#### CWinMainControler::CWinEVPompeControler" << endl;

	m_pWinMainControler = argpWinMainControler;
	m_pSupervision = argpWinMainControler->getpSupervision();
	m_pView  = new CWinElecTestView(this);
	m_pModelEVPompe = new CWinEVPompeModel(m_pSupervision);
	m_pModelStreamSelector = new CWinStreamSelectorModel(m_pSupervision);
	m_pModelExternalCard = new CWinExternalCardModel(m_pSupervision, m_pView);
    m_nombrePagesRelais = m_pModelExternalCard->getNbDigitOut()/NB_RELAIS_MAX;
    if(m_nombrePagesRelais ==0)  m_nombrePagesRelais = 1;
    m_numPageRelais = 0;
    m_nombrePagesEntree = m_pModelExternalCard->getNbDigitIn()/NB_RELAIS_MAX;
    m_numPageEntree = 0;
    m_nombrePagesSortieAna= m_pModelExternalCard->getNbAnalogOut();
    m_numPageSortieAna = 0;
    for(int i=0; i < m_pModelExternalCard->getNbDigitOut(); ++i) m_listEtatRelais.append(false); 
	m_pModelMeasureCard = new CWinMeasureCardModel(m_pSupervision);
	m_pView->setModel(m_pModelEVPompe, m_pModelExternalCard, m_pModelMeasureCard, m_pModelStreamSelector, argpWinMainControler->getMainModel());

    m_timerArretPompes = new QTimer();
    m_timerArretPompes->setInterval(180000);
    connect(m_timerArretPompes, SIGNAL(timeout()), this, SLOT(slotArretPompes()));

    m_timerTemperature = new QTimer();
    m_timerTemperature->setInterval(1000);
    connect(m_timerTemperature, SIGNAL(timeout()), m_pView, SLOT(slotTemperatureUpdated()));
    

	qDebug() << "#### FIN CWinMainControler::CWinEVPompeControler" << endl;
	
}

//SLOT
void CWinElecTestControler::btBackPressed()
{
	
	CUserSession::getInstance()->poke();
	CUserSession::getInstance()->objectUnregister(this);
	
    slotArretPompes();

	CPushButton* btTmp;
    int tmpNumPage = m_numPageRelais;
    for(int i=0; i<m_nombrePagesRelais; ++i)
    {
        m_numPageRelais = i;
	    foreach(btTmp, m_pView->getListBtOnRelais())
	    {
		    if(!btTmp->isEnabled())
			    btOffRelaisPressed(btTmp->getId());

	    }
    }
    m_numPageRelais = tmpNumPage;

	foreach(btTmp, m_pView->getListBtOnLocal())
	{
		if(!btTmp->isEnabled())
			btOffLocalPressed(btTmp->getId());

	}
#ifndef COULEUR
	btOffEVPressed(0);
#endif

	m_pView->close();
	m_pWinMainControler->execControler();
}

//SLOT
void CWinElecTestControler::slotArretPompes()
{
    m_timerArretPompes->stop();
    CPushButton* btTmp;
	foreach(btTmp, m_pView->getListBtOnPompe())
	{
		if(!btTmp->isEnabled())
			btOffPompePressed(btTmp->getId());

	}
}

void CWinElecTestControler::execControler()
{
	CUserSession::getInstance()->objectRegister(this);
	m_pModelEVPompe->cmdConfigPompes();
	//m_pModelEVPompe->setStartTimer();
	m_pView->showFullScreen();
}


CWinElecTestControler* CWinElecTestControler::getInstance(CWinMainControler* argpWinMainControler)
{
		if(!singletonControler)
			singletonControler = new CWinElecTestControler(argpWinMainControler);

		return singletonControler;
}
//SLOT
void CWinElecTestControler::btOffChauffe()
{
    qDebug() << "CWinElecTestControler::btOffChauffe" ;
    for(int i=0; i< m_pModelMeasureCard->getVectorLocalSecuriteOn().count(); ++i)
    {
        if(m_pModelMeasureCard->getVectorLocalSecuriteOn().at(i))
            btOffLocalPressed(i);
    }
}
//SLOT
void CWinElecTestControler::btOnEVPressed(int arg_numEV)
{
    qDebug() << "CWinElecTestControler::btOnEVPressed "  <<arg_numEV;
	CUserSession::getInstance()->poke();
	//m_pView->setEnabledBtOnEV1(false);
	//m_pView->setEnabledBtOffEV1(true);
	m_pView->setEnabledBtOnEV(false, arg_numEV);
	m_pView->setEnabledBtOffEV(true, arg_numEV);
	m_pModelEVPompe->cmdEv(arg_numEV, true);
}
//SLOT
void CWinElecTestControler::btOffEVPressed(int arg_numEV)
{
    qDebug() << "CWinElecTestControler::btOffEVPressed " <<arg_numEV;
	CUserSession::getInstance()->poke();
	//m_pView->setEnabledBtOnEV1(true);
	//m_pView->setEnabledBtOffEV1(false);
	m_pView->setEnabledBtOnEV(true, arg_numEV);
	m_pView->setEnabledBtOffEV(false, arg_numEV);
	m_pModelEVPompe->cmdEv(arg_numEV, false);
}
//SLOT
void CWinElecTestControler::btOnPompePressed(int arg_numPompe)
{
    m_timerArretPompes->start(); // Démarre ou redémare le timer d'arrêt
	CUserSession::getInstance()->poke();
#ifdef KMNO4
	this->btOnLocalPressed(3);
#endif
	m_pView->setEnabledBtOnPompe(false, arg_numPompe);
	m_pView->setEnabledBtOffPompe(true, arg_numPompe);
	m_pModelEVPompe->cmdPompe(arg_numPompe, true);
}
//SLOT
void CWinElecTestControler::btOffPompePressed(int arg_numPompe)
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnPompe(true, arg_numPompe);
	m_pView->setEnabledBtOffPompe(false, arg_numPompe);
	m_pModelEVPompe->cmdPompe(arg_numPompe, false);
}
//SLOT
void CWinElecTestControler::btOnLocalPressed(int arg_numLocal)
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnLocal(false, arg_numLocal);
	m_pView->setEnabledBtOffLocal(true, arg_numLocal);
	m_pModelMeasureCard->cmdOrganne(arg_numLocal, true);
	if(m_pModelMeasureCard->getVectorLocalSecuriteOn().at(arg_numLocal)){
    	QTimer::singleShot(20000, this, SLOT(btOffChauffe()));
    }
}
//SLOT
void CWinElecTestControler::btOffLocalPressed(int arg_numLocal)
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnLocal(true, arg_numLocal);
	m_pView->setEnabledBtOffLocal(false, arg_numLocal);
	m_pModelMeasureCard->cmdOrganne(arg_numLocal, false);
}
//SLOT
void CWinElecTestControler::btOnRelaisPressed(int numRelais)
{
	qDebug() << "btOnRelaisPressed(int numRelais) " << numRelais;
    int numRelaisVirtuel = numRelais+(m_numPageRelais*NB_RELAIS_MAX);
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnRelais(numRelais, false);
	m_pView->setEnabledBtOffRelais(numRelais,true);
	m_pModelExternalCard->cmdRelais(numRelaisVirtuel, true);
    m_listEtatRelais[numRelaisVirtuel] = true;
    qDebug() << "On numRelaisVirtuel " << numRelaisVirtuel;
}
//SLOT
void CWinElecTestControler::btOffRelaisPressed(int numRelais)
{
	qDebug() << "btOffRelaisPressed(int numRelais) " << numRelais;
    int numRelaisVirtuel = numRelais+(m_numPageRelais*NB_RELAIS_MAX);
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnRelais(numRelais,true);
	m_pView->setEnabledBtOffRelais(numRelais,false);
	m_pModelExternalCard->cmdRelais(numRelaisVirtuel, false);
    m_listEtatRelais[numRelaisVirtuel] = false;
    qDebug() << "Off numRelaisVirtuel " << numRelaisVirtuel;

}
//SLOT
void CWinElecTestControler::btOnStreamSelectorPressed(int numVoie)
{
	qDebug() << "btOnStreamSelectorPressed(int numVoie) " << numVoie;
    CUserSession::getInstance()->poke();
    for(int i=0; i<m_pModelStreamSelector->getNbStream(); ++i)
    {
        if(i == numVoie)
        {
	        m_pView->setEnabledBtOnStreamSelector(i, false);
	        m_pView->setEnabledBtOffStreamSelector(i,true);

        }
        else
        {
	        m_pView->setEnabledBtOnStreamSelector(i, true);  
	        m_pView->setEnabledBtOffStreamSelector(i,false);
        }

    }
	m_pModelStreamSelector->cmdSelectionVoie(numVoie);
    
    
}
//SLOT
void CWinElecTestControler::btOffStreamSelector(int numVoie)
{
	
}
//SLOT
void CWinElecTestControler::btNextPageRelaisPressed()
{
    qDebug() << "btNextPageRelaisPressed m_numPage " << m_numPageRelais << " m_nombrePages" << m_nombrePagesRelais;
	if(m_numPageRelais<m_nombrePagesRelais-1)
	{	
		m_pView->setEnabledBtPrevPageRelais(true);
		m_pView->loadPageExternalCard(++m_numPageRelais);
	}
	if(m_numPageRelais<m_nombrePagesRelais-1)
		m_pView->setEnabledBtNextPageRelais(true);
	else
		m_pView->setEnabledBtNextPageRelais(false);
	//m_pView->setLblPaginationTxt(m_numPage, m_nombrePages);
}
//SLOT
void CWinElecTestControler::btPrevPageRelaisPressed()
{
    qDebug() << "btPrevPageRelaisPressed m_numPage " << m_numPageRelais << " m_nombrePages"<< m_nombrePagesRelais;

	if(m_numPageRelais>0)
	{
		m_pView->setEnabledBtNextPageRelais(true);
		m_pView->loadPageExternalCard(--m_numPageRelais);
	}
	if(m_numPageRelais>0)
		m_pView->setEnabledBtPrevPageRelais(true);
	else
		m_pView->setEnabledBtPrevPageRelais(false);
	//m_pView->setLblPaginationTxt(m_numPage, m_nombrePages);
}
//SLOT
void CWinElecTestControler::btNextPageSortieAnaPressed()
{
    qDebug() << "btNextPageRelaisPressed m_numPage " << m_numPageRelais << " m_nombrePages" << m_nombrePagesRelais;
	if(m_numPageSortieAna<m_nombrePagesSortieAna-1)
	{	
		m_pView->setEnabledBtPrevPageSortieAna(true);
		m_pView->loadPageSortieAna(++m_numPageSortieAna);
	}
	if(m_numPageSortieAna<m_nombrePagesSortieAna-1)
		m_pView->setEnabledBtNextPageSortieAna(true);
	else
		m_pView->setEnabledBtNextPageSortieAna(false);
	//m_pView->setLblPaginationTxt(m_numPage, m_nombrePages);
}
//SLOT
void CWinElecTestControler::btPrevPageSortieAnaPressed()
{
    qDebug() << "btPrevPageRelaisPressed m_numPage " << m_numPageRelais << " m_nombrePages"<< m_nombrePagesRelais;

	if(m_numPageSortieAna>0)
	{
		m_pView->setEnabledBtNextPageSortieAna(true);
		m_pView->loadPageSortieAna(--m_numPageSortieAna);
	}
	if(m_numPageSortieAna>0)
		m_pView->setEnabledBtPrevPageSortieAna(true);
	else
		m_pView->setEnabledBtPrevPageSortieAna(false);
	//m_pView->setLblPaginationTxt(m_numPage, m_nombrePages);
}
void CWinElecTestControler::btValMaxConvertisseurPressed()
{
	CDialogPaveNum* pave = CDialogPaveNum::getInstance();
	pave->setValue(m_pModelExternalCard->getValueValMaxConvertisseur(m_numPageSortieAna));
	pave->setValueName(m_pModelExternalCard->getLblValMaxConvertisseur());
	if(pave->exec())
	{
		m_pView->setValMaxConvertisseur(pave->getValue());
		m_pModelExternalCard->setValMaxConvertisseur(m_numPageSortieAna, pave->getValue());
	}
}
void CWinElecTestControler::btValMinConvertisseurPressed()
{
	CDialogPaveNum* pave = CDialogPaveNum::getInstance();
	pave->setValue(m_pModelExternalCard->getValueValMinConvertisseur(m_numPageSortieAna));
	pave->setValueName(m_pModelExternalCard->getLblValMinConvertisseur());
	if(pave->exec())
	{
		m_pView->setValMinConvertisseur(pave->getValue());
		m_pModelExternalCard->setValMinConvertisseur(m_numPageSortieAna, pave->getValue());
	}
}
//SLOT
void CWinElecTestControler::btRadioTest4mAPressed()
{
	CUserSession::getInstance()->poke();
	m_pModelExternalCard->cmdSortieAnalogique(m_numPageSortieAna , 4);
}
//SLOT
void CWinElecTestControler::btRadioTest12mAPressed()
{
	CUserSession::getInstance()->poke();
	m_pModelExternalCard->cmdSortieAnalogique(m_numPageSortieAna,12);
}
//SLOT
void CWinElecTestControler::btRadioTest20mAPressed()
{
	CUserSession::getInstance()->poke();
	m_pModelExternalCard->cmdSortieAnalogique(m_numPageSortieAna,20);
}
//SLOT
void CWinElecTestControler::tabChanged(int index)
{
	CUserSession::getInstance()->poke();
	qDebug() << "###### tab num " << index << endl;
	switch(index)
	{
	//	
	//	//Tab Pompe
	//	case 0 :
	//		m_pModelEVPompe->setStartTimer();
	//		break;
	//	//Tab Relais
	//	case 1:
	//		m_pModelEVPompe->setStopTimer();
	//		break;
	//	//Tab carte mesure (actionneur)
		case 2:
	//		m_pModelEVPompe->setStopTimer();
            m_timerTemperature->start();
			break;
	//	//Tab EV
	//	case 3:
	//		m_pModelEVPompe->setStartTimer();
	//		break;
		//Tab ENtree
#ifdef COULEUR
		case 3:
#else
		case 4:
#endif
			m_pModelExternalCard->setStartTimerCmdEntree();
			break;
	//	//autre
		default:
			m_pModelExternalCard->setStopTimerCmdEntree();	
            m_timerTemperature->stop();
			break;

	}
}

//SLOT
void CWinElecTestControler::userSessionClosed()
{
	qDebug() << "##### CWinElecTestControler::userSessionClosed()" << endl;
	if(!CUserSession::getInstance()->loginAsLastUser())
		btBackPressed();
}
