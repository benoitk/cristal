#include "CDialogStopCycle.h"
#include "CWinMainModel.h"
#include "header_qt.h"


CDialogStopCycle* CDialogStopCycle::singleton = 0;
CDialogStopCycle::CDialogStopCycle()
{
	//m_winMainModel = arg_WinMainModel;

	m_btApply = new QPushButton();
	m_btApply->setObjectName("btApply");
	m_btBack = new QPushButton();
	m_btBack->setObjectName("btCancel");

	QTabWidget* tabWidget = new QTabWidget();

	QWidget* widgetDialog = new QWidget();
	tabWidget->addTab(widgetDialog, tr("ATTENTION"));
	
	QVBoxLayout* layoutMenu = new QVBoxLayout();
	layoutMenu->addStretch();
	layoutMenu->addWidget(m_btApply);
	layoutMenu->addWidget(m_btBack);



	//assemblage du menu et du layoutGauche
	QHBoxLayout* layoutMain = new QHBoxLayout();
	layoutMain->addWidget(new QLabel(tr("Pour accéder aux outils, \nles cycles doivent être arrêtés. \nVoulez vous arrêter les cyles ?")));
	layoutMain->addLayout(layoutMenu);
	widgetDialog->setLayout(layoutMain);
	
	
	QHBoxLayout* layout = new QHBoxLayout();
	layout->addWidget(tabWidget);

	setLayout(layout);

	this->setObjectName("dialogModal");
	this->setWindowFlags(Qt::FramelessWindowHint);

	setConnexion();
}

bool CDialogStopCycle::cycleStoped()
{
	/*if(m_winMainModel->getStop())
		return true;
	else
		return this->exec();*/
    return true;
}
//SLOT
void CDialogStopCycle::stopCycle()
{
	/*m_winMainModel->setStop();
	this->accept();*/
}
void CDialogStopCycle::setConnexion()
{
	connect(m_btApply, SIGNAL(clicked()), this, SLOT(accept()));
	connect(m_btBack, SIGNAL(clicked()), this, SLOT(reject()));
}

//CDialogStopCycle* CDialogStopCycle::getInstance(CWinMainModel* arg_WinMainModel)
CDialogStopCycle* CDialogStopCycle::getInstance()
{
	if(!singleton)
			singleton = new CDialogStopCycle();
	return singleton;
}