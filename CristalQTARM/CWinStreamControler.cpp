#include "CWinStreamControler.h"
#include "CWinStreamView.h"
#include "CWinStreamModel.h"
#include "CWinMainControler.h"
#include "CUserSession.h"
#include "CDialogPaveNum.h"

CWinStreamControler *CWinStreamControler::singletonControler = 0;

CWinStreamControler::CWinStreamControler(CWinMainControler* argWinMainControler)
{
	m_pControler = argWinMainControler;
	m_pSupervision = argWinMainControler->getpSupervision();
	m_pView  = new CWinStreamView(this);
	m_pModel = new CWinStreamModel(m_pSupervision, m_pView);
	m_pView->setModel(m_pModel);

    for(int i=0; i<m_pModel->getNbMeasure(); ++i)
    {
	    m_listNumPage.append(0);
    }
    m_numCurrentMeasure = 0;
	m_nombrePages = m_pModel->getNombreValues(0,0)/NOMBRE_VALUE_PAR_PAGE;
	if((m_pModel->getNombreValues(0,0)%NOMBRE_VALUE_PAR_PAGE) == 0)--m_nombrePages;

//	m_pView->setLblPaginationTxt(m_numPage, m_nombrePages);
	qDebug() << "m_nombrePages " << m_nombrePages;
}
//SLOT
void CWinStreamControler::btBackPressed()
{
	//m_pControler->execControler();
#if defined(SILICE) || defined(COULEUR)// || defined(COLO)
    m_pModel->updateOffsetMesure(m_numCurrentStream,0);
#endif
	m_pView->close();
	m_pControler->execControler();
}
//SLOT
void CWinStreamControler::btNextPagePressed(int arg_numMesure)
{
	qDebug() << "btNextPagePressed m_numPage " << m_listNumPage.at(arg_numMesure) << " m_nombrePages";
	if(m_listNumPage.at(arg_numMesure)<m_nombrePages)
	{	
		m_pView->setEnabledBtPreviousPage(true, arg_numMesure);
		m_pView->loadPage(m_numCurrentStream, arg_numMesure, ++m_listNumPage[arg_numMesure]);
	}
	if(m_listNumPage.at(arg_numMesure)<m_nombrePages)
		m_pView->setEnabledBtNextPage(true, arg_numMesure);
	else
		m_pView->setEnabledBtNextPage(false, arg_numMesure);
	//m_pView->setLblPaginationTxt(m_numPage, m_nombrePages);
	
}

//SLOT
void CWinStreamControler::btPreviousPagePressed(int arg_numMesure)
{
	qDebug() << "btPreviousPagePressed m_numPage " << m_listNumPage.at(arg_numMesure) << " m_nombrePages";

	if(m_listNumPage.at(arg_numMesure)>0)
	{
		m_pView->setEnabledBtNextPage(true, arg_numMesure);
		m_pView->loadPage(m_numCurrentStream, arg_numMesure, --m_listNumPage[arg_numMesure]);
	}
	if(m_listNumPage.at(arg_numMesure)>0)
		m_pView->setEnabledBtPreviousPage(true, arg_numMesure);
	else
		m_pView->setEnabledBtPreviousPage(false, arg_numMesure);
	//m_pView->setLblPaginationTxt(m_numPage, m_nombrePages);

}
//SLOT
void CWinStreamControler::btOnVoieActivePressed()
{ 
    m_pModel->setVoieActive(m_numCurrentStream, true);
	m_pView->setDownBtOnVoieActive(true);
	m_pView->setDownBtOffVoieActive(false);
}
//SLOT
void CWinStreamControler::btOffVoieActivePressed()
{
    m_pModel->setVoieActive(m_numCurrentStream, false);
	m_pView->setDownBtOnVoieActive(false);
	m_pView->setDownBtOffVoieActive(true);
}
//SLOT
void CWinStreamControler::slotTabChanged(int arg_numTab)
{
    switch(arg_numTab)
    {
        //voie
    case VOIE:
        break;

        //mesure 1
    case MEASURE_1:
        m_numCurrentMeasure = 0;
        m_pView->loadPage(m_numCurrentStream, m_numCurrentMeasure, m_listNumPage.at(m_numCurrentMeasure));
        break;

        //mesure 2
    case MEASURE_2:
        m_numCurrentMeasure = 1;
        m_pView->loadPage(m_numCurrentStream, m_numCurrentMeasure, m_listNumPage.at(m_numCurrentMeasure));
        break;

        //mesure 3
    case MEASURE_3:
        m_numCurrentMeasure = 2;
        m_pView->loadPage(m_numCurrentStream, m_numCurrentMeasure, m_listNumPage.at(m_numCurrentMeasure));
        break;

        //mesure 4
    case MEASURE_4:
        m_numCurrentMeasure = 3;
        m_pView->loadPage(m_numCurrentStream, m_numCurrentMeasure, m_listNumPage.at(m_numCurrentMeasure));
        break;
    default:
        break;
    }

}
//SLOT
void CWinStreamControler::btEditPressed(int arg_index)
{
	if(CUserSession::getInstance()->loginUser())
	{
		CDialogPaveNum* pPaveNum = CDialogPaveNum::getInstance();
        int tmp = arg_index+(NOMBRE_VALUE_PAR_PAGE*m_listNumPage.at(m_numCurrentMeasure));
		pPaveNum->setValue(m_pModel->getValue(m_numCurrentStream, m_numCurrentMeasure, tmp));
		pPaveNum->setValueName(m_pModel->getValueLbl(m_numCurrentStream, m_numCurrentMeasure, tmp));
		//pPaveNum->showFullScreen();
		if(pPaveNum->exec())
        {
			m_pView->setEditText(m_numCurrentStream, m_numCurrentMeasure, arg_index, m_listNumPage.at(m_numCurrentMeasure), pPaveNum->getValue());
	        m_pView->loadPage(m_numCurrentStream, m_numCurrentMeasure, m_listNumPage.at(m_numCurrentMeasure));
        }
    }

}

////SLOT
//void CWinStreamControler::btEdit1Pressed()
//{
//	if(CUserSession::getInstance()->loginUser())
//	{
//		CDialogPaveNum* pPaveNum = CDialogPaveNum::getInstance();
//		pPaveNum->setValue(m_pView->getEditText(1));
//		pPaveNum->setValueName(m_pView->getEditTextLbl(1));
//		//pPaveNum->setValueName(m_pView->getgetEditText());
//		//pPaveNum->showFullScreen();
//		if(pPaveNum->exec())
//			m_pView->setEditText(1, m_numPage, pPaveNum->getValue());
//	}
//}
////SLOT
//void CWinStreamControler::btEdit2Pressed()
//{
//	if(CUserSession::getInstance()->loginUser())
//	{
//		CDialogPaveNum* pPaveNum = CDialogPaveNum::getInstance();
//		pPaveNum->setValue(m_pView->getEditText(2));
//		pPaveNum->setValueName(m_pView->getEditTextLbl(2));
//		//pPaveNum->setValueName(m_pView->getgetEditText());
//		//pPaveNum->showFullScreen();
//		if(pPaveNum->exec())
//			m_pView->setEditText(2, m_numPage, pPaveNum->getValue());
//	}
//}
////SLOT
//void CWinStreamControler::btEdit3Pressed()
//{
//	if(CUserSession::getInstance()->loginUser())
//	{
//		CDialogPaveNum* pPaveNum = CDialogPaveNum::getInstance();
//		pPaveNum->setValue(m_pView->getEditText(3));
//		pPaveNum->setValueName(m_pView->getEditTextLbl(3));
//		//pPaveNum->setValueName(m_pView->getgetEditText());
//		//pPaveNum->showFullScreen();
//		if(pPaveNum->exec())
//			m_pView->setEditText(3, m_numPage, pPaveNum->getValue());
//	}
//}
////SLOT
//void CWinStreamControler::btEdit4Pressed()
//{
//	if(CUserSession::getInstance()->loginUser())
//	{
//		CDialogPaveNum* pPaveNum = CDialogPaveNum::getInstance();
//		pPaveNum->setValue(m_pView->getEditText(4));
//		pPaveNum->setValueName(m_pView->getEditTextLbl(4));
//		//pPaveNum->setValueName(m_pView->getgetEditText());
//		//pPaveNum->showFullScreen();
//		if(pPaveNum->exec())
//			m_pView->setEditText(4, m_numPage, pPaveNum->getValue());
//	}
//}
void CWinStreamControler::execControler(int arg_numStream)
{
    m_numCurrentStream = arg_numStream;
 
	m_pModel->updateDataFromSupervision();
	m_pView->setDownBtOnVoieActive(true);
	m_pView->setDownBtOffVoieActive(false);
	m_pView->showFullScreen();
	m_pView->loadPage(arg_numStream, m_numCurrentMeasure, m_listNumPage.at(m_numCurrentMeasure));
}

CWinStreamControler* CWinStreamControler::getInstance(CWinMainControler* argWinMainControler)
{
		if(!singletonControler)
			singletonControler = new CWinStreamControler(argWinMainControler);

		return singletonControler;
}




