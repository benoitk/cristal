#include "CWinEVPompeControler.h"
#include "CWinEVPompeModel.h"
#include "CWinEVPompeView.h"
#include "CWinMainControler.h"
#include "CSupervision.h"
#include "CUserSession.h"


CWinEVPompeControler *CWinEVPompeControler::singletonControler = 0;

CWinEVPompeControler::CWinEVPompeControler(CWinMainControler* argpWinMainControler)
{
	qDebug() << "#### CWinMainControler::CWinEVPompeControler" << endl;

	m_pWinMainControler = argpWinMainControler;
	m_pSupervision = argpWinMainControler->getpSupervision();
	m_pView  = new CWinEVPompeView(this);
	m_pModel = new CWinEVPompeModel(m_pSupervision);//, m_pView);
	m_pView->setModel(m_pModel);
	qDebug() << "#### FIN CWinMainControler::CWinEVPompeControler" << endl;
	
}

//SLOT
void CWinEVPompeControler::btBackPressed()
{
	CUserSession::getInstance()->poke();
	CUserSession::getInstance()->objectUnregister(this);
//	m_pModel->setStopTimer();
	m_pView->close();
	m_pWinMainControler->execControler();
}

void CWinEVPompeControler::execControler()
{
	CUserSession::getInstance()->objectRegister(this);
	m_pModel->cmdConfigPompes();
//	m_pModel->setStartTimer();
	m_pView->showFullScreen();
}

CWinEVPompeControler* CWinEVPompeControler::getInstance(CWinMainControler* argpWinMainControler)
{
		if(!singletonControler)
			singletonControler = new CWinEVPompeControler(argpWinMainControler);

		return singletonControler;
}

//SLOT
void CWinEVPompeControler::btOnEV1Pressed()
{
	CUserSession::getInstance()->poke();
//	m_pView->setEnabledBtOnEV1(false);
//	m_pView->setEnabledBtOffEV1(true);
	m_pModel->cmdEv(1, true);
}
//SLOT
void CWinEVPompeControler::btOffEV1Pressed()
{
	CUserSession::getInstance()->poke();
//	m_pView->setEnabledBtOnEV1(true);
//	m_pView->setEnabledBtOffEV1(false);
	m_pModel->cmdEv(1, false);
}
//SLOT
void CWinEVPompeControler::btOnPompe1Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnPompe1(false);
	m_pView->setEnabledBtOffPompe1(true);
	m_pModel->cmdPompe(1, true);
}
//SLOT
void CWinEVPompeControler::btOffPompe1Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnPompe1(true);
	m_pView->setEnabledBtOffPompe1(false);
	m_pModel->cmdPompe(1, false);
}
//SLOT
void CWinEVPompeControler::btOnPompe2Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnPompe2(false);
	m_pView->setEnabledBtOffPompe2(true);
	m_pModel->cmdPompe(2, true);
}
//SLOT
void CWinEVPompeControler::btOffPompe2Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnPompe2(true);
	m_pView->setEnabledBtOffPompe2(false);
	m_pModel->cmdPompe(2, false);
}

//SLOT
void CWinEVPompeControler::btOnPompe3Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnPompe3(false);
	m_pView->setEnabledBtOffPompe3(true);
	m_pModel->cmdPompe(3, true);
}
//SLOT
void CWinEVPompeControler::btOffPompe3Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnPompe3(true);
	m_pView->setEnabledBtOffPompe3(false);
	m_pModel->cmdPompe(3, false);
}
//SLOT
void CWinEVPompeControler::btOnPompe4Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnPompe4(false);
	m_pView->setEnabledBtOffPompe4(true);
	m_pModel->cmdPompe(4, true);
}
//SLOT
void CWinEVPompeControler::btOffPompe4Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnPompe4(true);
	m_pView->setEnabledBtOffPompe4(false);
	m_pModel->cmdPompe(4, false);
}
//SLOT
void CWinEVPompeControler::btOnPompe5Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnPompe5(false);
	m_pView->setEnabledBtOffPompe5(true);
	m_pModel->cmdPompe(5, true);
}
//SLOT
void CWinEVPompeControler::btOffPompe5Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnPompe5(true);
	m_pView->setEnabledBtOffPompe5(false);
	m_pModel->cmdPompe(5, false);
}
//SLOT
void CWinEVPompeControler::btOnPompe6Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnPompe6(false);
	m_pView->setEnabledBtOffPompe6(true);
	m_pModel->cmdPompe(6, true);
}
//SLOT
void CWinEVPompeControler::btOffPompe6Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnPompe6(true);
	m_pView->setEnabledBtOffPompe6(false);
	m_pModel->cmdPompe(6, false);
}
//SLOT
void CWinEVPompeControler::tabChanged(int index)
{
	CUserSession::getInstance()->poke();
	//qDebug() << "###### tab num " << index << endl;
	//switch(index)
	//{
	//	
	//	//Tab Maintenance
	//	case 0 :
	//	//	m_pModel->setStartTimer();
	//		break;
	//	//tab diag
	//	case 1:
	//	//	m_pModel->setStartTimer();

	//		break;
	//	//autre
	//	default:
	//		m_pModel->setStopTimer();	
	//		break;
	//}
}

//SLOT
void CWinEVPompeControler::userSessionClosed()
{
	qDebug() << "##### CWinMeasureCardControler::userSessionClosed()" << endl;
	if(!CUserSession::getInstance()->loginAsLastUser())
		btBackPressed();
}
