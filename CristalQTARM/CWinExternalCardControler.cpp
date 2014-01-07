#include "CWinExternalCardControler.h"
#include "CWinExternalCardView.h"
#include "CWinExternalCardModel.h"
#include "CWinMainControler.h"
#include "CUserSession.h"
#include "CDialogPaveNum.h"
CWinExternalCardControler *CWinExternalCardControler::singletonControler = 0;

CWinExternalCardControler::CWinExternalCardControler(CWinMainControler* argpWinMainControler)
{
	m_pWinMainControler = argpWinMainControler;
	m_pSupervision = argpWinMainControler->getpSupervision();
	qDebug() << "### CWinExternalCardView";
	m_pView  = new CWinExternalCardView(this);
	qDebug() << "### CWinExternalCardModel";
	//m_pModel = new CWinExternalCardModel(m_pSupervision);//, m_pView);
	qDebug() << "### FinCWinExternalCardModel";

	m_pView->setModel(m_pModel);
}

//SLOT
void CWinExternalCardControler::btBackPressed()
{
	CUserSession::getInstance()->poke();
	CUserSession::getInstance()->objectUnregister(this);
	m_pView->close();
	m_pWinMainControler->execControler();
}

//SLOT
void CWinExternalCardControler::btOnRelaisPressed(int numRelais)
{
	//qDebug() << "btOnRelaisPressed(int numRelais) " << numRelais;
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnRelais(numRelais, false);
	m_pView->setEnabledBtOffRelais(numRelais,true);
	m_pModel->cmdRelais(numRelais, true);
}
//SLOT
void CWinExternalCardControler::btOffRelaisPressed(int numRelais)
{
	//qDebug() << "btOffRelaisPressed(int numRelais) " << numRelais;
	CUserSession::getInstance()->poke();
	m_pView->setEnabledBtOnRelais(numRelais,true);
	m_pView->setEnabledBtOffRelais(numRelais,false);
	m_pModel->cmdRelais(numRelais, false);
}

void CWinExternalCardControler::btValMaxConvertisseurPressed()
{
	CDialogPaveNum* pave = CDialogPaveNum::getInstance();
	pave->setValue(m_pModel->getValueValMaxConvertisseur(0));
	pave->setValueName(m_pModel->getLblValMaxConvertisseur());
	if(pave->exec())
	{
		m_pView->setValMaxConvertisseur(pave->getValue());
		m_pModel->setValMaxConvertisseur(0,pave->getValue());
	}
}
void CWinExternalCardControler::btValMinConvertisseurPressed()
{
	CDialogPaveNum* pave = CDialogPaveNum::getInstance();
	pave->setValue(m_pModel->getValueValMinConvertisseur(0));
	pave->setValueName(m_pModel->getLblValMinConvertisseur());
	if(pave->exec())
	{
		m_pView->setValMinConvertisseur(pave->getValue());
		m_pModel->setValMinConvertisseur(0,pave->getValue());
	}
}
//SLOT
void CWinExternalCardControler::btRadioTest4mAPressed()
{
	CUserSession::getInstance()->poke();
	m_pModel->cmdSortieAnalogique(0,4);
}
//SLOT
void CWinExternalCardControler::btRadioTest12mAPressed()
{
	CUserSession::getInstance()->poke();
	m_pModel->cmdSortieAnalogique(0,12);
}
//SLOT
void CWinExternalCardControler::btRadioTest20mAPressed()
{
	CUserSession::getInstance()->poke();
	m_pModel->cmdSortieAnalogique(0,20);
}


void CWinExternalCardControler::execControler()
{
	CUserSession::getInstance()->objectRegister(this);
	m_pView->showFullScreen();
}

CWinExternalCardControler* CWinExternalCardControler::getInstance(CWinMainControler* argpWinMainControler)
{
		if(!singletonControler)
			singletonControler = new CWinExternalCardControler(argpWinMainControler);
				
		return singletonControler;
}

//SLOT
void CWinExternalCardControler::userSessionClosed()
{
	qDebug() << "##### CWinMeasureCardControler::userSessionClosed()" << endl;
	if(!CUserSession::getInstance()->loginAsLastUser())
		btBackPressed();
}


