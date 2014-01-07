#include "CWinMeasureCardControler.h"
#include "CWinMeasureCardModel.h"
#include "CWinMeasureCardView.h"
#include "CWinMainControler.h"
#include "CUserSession.h"

CWinMeasureCardControler *CWinMeasureCardControler::singletonControler = 0;

CWinMeasureCardControler::CWinMeasureCardControler(CWinMainControler* argpWinMainControler)
{
	m_pWinMainControler = argpWinMainControler;
	m_pSupervision = argpWinMainControler->getpSupervision();
	m_pView  = new CWinMeasureCardView(this);
	m_pModel = new CWinMeasureCardModel(m_pSupervision);//, m_pView);
	m_pView->setModel(m_pModel);
}
CWinMeasureCardControler::~CWinMeasureCardControler()
{
	delete m_pModel;
	delete m_pView;
	qDebug() << "PIM :CWinMeasureCardControler" << endl;
	//TRACE_LOG_MSG(_T("PIM :CWinMeasureCardControler"));
}


//SLOT fermeture de la fenêtre
void CWinMeasureCardControler::btBackPressed()
{
	CUserSession::getInstance()->poke();
	CUserSession::getInstance()->objectUnregister(this);
	m_pView->close();
	//delete m_pModel;
	//delete m_pView;
	m_pWinMainControler->execControler();
	QPixmapCache::clear();
}

void CWinMeasureCardControler::execControler()
{
	/*m_pView  = new CWinMeasureCardView(this);
	m_pModel = new CWinMeasureCardModel(m_pSupervision, m_pView);
	m_pView->setModel(m_pModel);*/
	//m_pView->showFullScreen();
	m_pView->showFullScreen();
	CUserSession::getInstance()->objectRegister(this);

}

CWinMeasureCardControler* CWinMeasureCardControler::getInstance(CWinMainControler* argpWinMainControler)
{
		if(!singletonControler)
			singletonControler = new CWinMeasureCardControler(argpWinMainControler);

		return singletonControler;
}
//SLOT
void CWinMeasureCardControler::btOnLocal1Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnLocal1(false);
	m_pView->setEnabledBtOffLocal1(true);
	m_pModel->cmdOrganne(1, true);
	if(m_pModel->getVectorLocalSecuriteOn().at(0))
		QTimer::singleShot(20000, this, SLOT(btOffLocal1Pressed()));
}
//SLOT
void CWinMeasureCardControler::btOffLocal1Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnLocal1(true);
	m_pView->setEnabledBtOffLocal1(false);
	m_pModel->cmdOrganne(1, false);
}
//SLOT
void CWinMeasureCardControler::btOnLocal2Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnLocal2(false);
	m_pView->setEnabledBtOffLocal2(true);
	m_pModel->cmdOrganne(2, true);
	if(m_pModel->getVectorLocalSecuriteOn().at(1))
		QTimer::singleShot(20000, this, SLOT(btOffLocal2Pressed()));
}
//SLOT
void CWinMeasureCardControler::btOffLocal2Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnLocal2(true);
	m_pView->setEnabledBtOffLocal2(false);
	m_pModel->cmdOrganne(2, false);
}
//SLOT
void CWinMeasureCardControler::btOnLocal3Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnLocal3(false);
	m_pView->setEnabledBtOffLocal3(true);
	m_pModel->cmdOrganne(3, true);
	if(m_pModel->getVectorLocalSecuriteOn().at(2))
		QTimer::singleShot(20000, this, SLOT(btOffLocal3Pressed()));
}
//SLOT
void CWinMeasureCardControler::btOffLocal3Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnLocal3(true);
	m_pView->setEnabledBtOffLocal3(false);
	m_pModel->cmdOrganne(3, false);
}
//SLOT
void CWinMeasureCardControler::btOnLocal4Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnLocal4(false);
	m_pView->setEnabledBtOffLocal4(true);
	m_pModel->cmdOrganne(4, true);
	if(m_pModel->getVectorLocalSecuriteOn().at(3))
		QTimer::singleShot(20000, this, SLOT(btOffLocal4Pressed()));
}
//SLOT
void CWinMeasureCardControler::btOffLocal4Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnLocal4(true);
	m_pView->setEnabledBtOffLocal4(false);
	m_pModel->cmdOrganne(4, false);
}
//SLOT
void CWinMeasureCardControler::btOnLocal5Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnLocal5(false);
	m_pView->setEnabledBtOffLocal5(true);
	m_pModel->cmdOrganne(5, true);
	if(m_pModel->getVectorLocalSecuriteOn().at(4))
		QTimer::singleShot(20000, this, SLOT(btOffLocal5Pressed()));
}
//SLOT
void CWinMeasureCardControler::btOffLocal5Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnLocal5(true);
	m_pView->setEnabledBtOffLocal5(false);
	m_pModel->cmdOrganne(5, false);
}
//SLOT
void CWinMeasureCardControler::btOnLocal6Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnLocal6(false);
	m_pView->setEnabledBtOffLocal6(true);
	m_pModel->cmdOrganne(6, true);
	if(m_pModel->getVectorLocalSecuriteOn().at(5))
		QTimer::singleShot(20000, this, SLOT(btOffLocal6Pressed()));
}
//SLOT
void CWinMeasureCardControler::btOffLocal6Pressed()
{
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnLocal6(true);
	m_pView->setEnabledBtOffLocal6(false);
	m_pModel->cmdOrganne(6, false);
}

//SLOT
void CWinMeasureCardControler::userSessionClosed()
{
	qDebug() << "##### CWinMeasureCardControler::userSessionClosed()" << endl;
	if(!CUserSession::getInstance()->loginAsLastUser())
		btBackPressed();
}



