#include "CMeasureCardModel.h"

#include "header_qt.h"


CMeasureCardModel::CMeasureCardModel(CCarteMesure *argpCarteMesure, CAnalyseur* argpAnalyseur)
{
	//m_pAnalyseur = argpAnalyseur;
	//m_pCarteMesure = argpCarteMesure;

	//TCHAR szRQ[]   = _T("10|4|0x0420|2");
	//TCHAR szRP[]   = _T("10|4|0x0420|2");
	//m_pCarteMesure->bAddExchangeJbus(szRQ,szRP,argpAnalyseur);
	////_stprintf(szRQ,_T("1|15|0x0071|7|1|0|0|0|0|0|0|0"));
	////_stprintf(szRP, _T("1|15|0x0071|7"));
	////m_pCarteMesure->bAddExchangeJbus(szRQ,szRP,argpAnalyseur);
}


void CMeasureCardModel::setConnexion()
{
	//PAr trigger ou timer ?
	m_timer = new QTimer(this);
	m_timer->setInterval(1000);
	connect(m_timer, SIGNAL(timeout()), this, SLOT(getDataFromSupervision()));
	
	m_timer->start();
}

//SLOT
void CMeasureCardModel::getDataFromMeasureCard()
{

}