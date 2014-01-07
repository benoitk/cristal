#include "CWinMeasureCardView.h"
#include "CWinMeasureCardControler.h"
#include "CWinMeasureCardModel.h"

#include "header_qt.h"




CWinMeasureCardView::CWinMeasureCardView(CWinMeasureCardControler* argpControler, QWidget *parent,Qt::WindowFlags flags)
	: QWidget(parent, flags)
{
	m_pControler = argpControler;
}

void CWinMeasureCardView::init()
{
	
	QTabWidget* tabWidget = new QTabWidget();

	//*** onglet relais
	QWidget* widgetRelais = new QWidget();

	/*m_btOnStirrer = new QPushButton();
	m_btOnStirrer->setObjectName("btOn");
	m_btOffStirrer = new QPushButton();
	m_btOffStirrer->setObjectName("btOff");
	m_btOnDoor = new QPushButton();
	m_btOnDoor->setObjectName("btOn");
	m_btOffDoor = new QPushButton();
	m_btOffDoor->setObjectName("btOff");
	m_btOnValve = new QPushButton("");
	m_btOnValve->setObjectName("btOn");
	m_btOffValve = new QPushButton();
	m_btOffValve->setObjectName("btOff");
	m_btOnHeater = new QPushButton();
	m_btOnHeater->setObjectName("btOn");
	m_btOffHeater = new QPushButton();
	m_btOffHeater->setObjectName("btOff");*/

	/*QHBoxLayout* layoutBtStirrer = new QHBoxLayout();
	layoutBtStirrer->addWidget(m_btOnStirrer,50, Qt::AlignCenter);
	layoutBtStirrer->addWidget(m_btOffStirrer,50, Qt::AlignLeft);
	QHBoxLayout* layoutBtDoor = new QHBoxLayout();
	layoutBtDoor->addWidget(m_btOnDoor,50, Qt::AlignCenter);
	layoutBtDoor->addWidget(m_btOffDoor,50, Qt::AlignLeft);
	QHBoxLayout* layoutBtValve = new QHBoxLayout();
	layoutBtValve->addWidget(m_btOnValve,50, Qt::AlignCenter);
	layoutBtValve->addWidget(m_btOffValve,50, Qt::AlignLeft);
	QHBoxLayout* layoutBtHeater = new QHBoxLayout();
	layoutBtHeater->addWidget(m_btOnHeater,50, Qt::AlignCenter);
	layoutBtHeater->addWidget(m_btOffHeater,50, Qt::AlignLeft);*/

	//centre de la fenêtre
	QFormLayout* layoutCentral = new QFormLayout();
	QString sLocalLabel;
	foreach(sLocalLabel, m_pModel->getVectorLocalLabels())
	{
		QPushButton* btOnTemp = new QPushButton();
		btOnTemp->setObjectName("btOn");
		m_vBtOnLocal.append(btOnTemp);

		QPushButton* btOffTemp = new QPushButton();
		btOffTemp->setObjectName("btOff");
		m_vBtOffLocal.append(btOffTemp);

		QHBoxLayout* layoutBtLocal = new QHBoxLayout();
		layoutBtLocal->addWidget(btOnTemp,50, Qt::AlignCenter);
		layoutBtLocal->addWidget(btOffTemp,50, Qt::AlignLeft);

		layoutCentral->addRow(sLocalLabel, layoutBtLocal);	
	}
	/*layoutCentral->addRow(tr("Brasseur"), layoutBtStirrer);
	layoutCentral->addRow(tr("Porte"), layoutBtDoor);
	layoutCentral->addRow(tr("EV remplissage"), layoutBtValve);
	layoutCentral->addRow(tr("Chauffe"), layoutBtHeater);*/

	//Bando de navigation du bas
	/*m_btNextPage = new QPushButton();
	m_btNextPage->setObjectName("btNextPage");
	m_btPreviousPage = new QPushButton();
	m_btPreviousPage->setObjectName("btPreviousPage");
	QHBoxLayout* layoutNav= new QHBoxLayout();
	layoutNav->addWidget(m_btNextPage,5, Qt::AlignRight);
	layoutNav->addWidget(m_btPreviousPage,5, Qt::AlignLeft);*/

	//Assemblage centre et bando de nav
	QVBoxLayout* layoutGauche= new QVBoxLayout();
	layoutGauche->addLayout(layoutCentral);
	//layoutGauche->addLayout(layoutNav);

	//menu de gauche //toujours 4 items dans les menus en incluant les spacers
	m_btBack = new QPushButton();
	m_btBack->setObjectName("btBack");

	QVBoxLayout* layoutMenu = new QVBoxLayout();
	layoutMenu->addStretch();
	layoutMenu->addWidget(m_btBack);

	//assemblage du menu et du layoutGauche
	QHBoxLayout* layoutMain = new QHBoxLayout();
	layoutMain->addLayout(layoutGauche);
	layoutMain->addLayout(layoutMenu);
	widgetRelais->setLayout(layoutMain);
	//:Nom de l'onglet à garer en maj pour toutes les trad
	tabWidget->addTab(widgetRelais, tr("SORTIES NUMERIQUES CARTE MESURE"));

	//*** onglet sortie 4-20

	//*** onglet Entree ana/tor

    QHBoxLayout* layoutGlobal = new QHBoxLayout(); 
    layoutGlobal->setContentsMargins ( 0, 0, 0, 0 );
    layoutGlobal->addWidget(tabWidget);
	this->setLayout(layoutGlobal);
	
	setConnexion();
}

void CWinMeasureCardView::setConnexion()
{
	connect(m_btBack, SIGNAL(clicked()), m_pControler, SLOT(btBackPressed()));

	int nNbLocal = m_vBtOnLocal.count();
	if(0 < nNbLocal) connect(m_vBtOnLocal.at(0), SIGNAL(clicked()), m_pControler,SLOT(btOnLocal1Pressed()));
	if(0 < nNbLocal) connect(m_vBtOffLocal.at(0), SIGNAL(clicked()), m_pControler,SLOT(btOffLocal1Pressed()));
	if(1 < nNbLocal) connect(m_vBtOnLocal.at(1), SIGNAL(clicked()), m_pControler,SLOT(btOnLocal2Pressed()));
	if(1 < nNbLocal) connect(m_vBtOffLocal.at(1), SIGNAL(clicked()), m_pControler,SLOT(btOffLocal2Pressed()));
	if(2 < nNbLocal) connect(m_vBtOnLocal.at(2), SIGNAL(clicked()), m_pControler,SLOT(btOnLocal3Pressed()));
	if(2 < nNbLocal) connect(m_vBtOffLocal.at(2), SIGNAL(clicked()), m_pControler,SLOT(btOffLocal3Pressed()));
	if(3 < nNbLocal) connect(m_vBtOnLocal.at(3), SIGNAL(clicked()), m_pControler,SLOT(btOnLocal4Pressed()));
	if(3 < nNbLocal) connect(m_vBtOffLocal.at(3), SIGNAL(clicked()), m_pControler,SLOT(btOffLocal4Pressed()));
	if(4 < nNbLocal) connect(m_vBtOnLocal.at(4), SIGNAL(clicked()), m_pControler,SLOT(btOnLocal5Pressed()));
	if(4 < nNbLocal) connect(m_vBtOffLocal.at(4), SIGNAL(clicked()), m_pControler,SLOT(btOffLocal5Pressed()));
	if(5 < nNbLocal) connect(m_vBtOnLocal.at(5), SIGNAL(clicked()), m_pControler,SLOT(btOnLocal6Pressed()));
	if(5 < nNbLocal) connect(m_vBtOffLocal.at(5), SIGNAL(clicked()), m_pControler,SLOT(btOffLocal6Pressed()));
	/*connect(m_btOnStirrer, SIGNAL(clicked()), m_pControler, SLOT(btOnStirrerPressed()));
	connect(m_btOffStirrer, SIGNAL(clicked()), m_pControler, SLOT(btOffStirrerPressed()));
	connect(m_btOnDoor, SIGNAL(clicked()), m_pControler, SLOT(btOnDoorPressed()));
	connect(m_btOffDoor, SIGNAL(clicked()), m_pControler, SLOT(btOffDoorPressed()));
	connect(m_btOnValve, SIGNAL(clicked()), m_pControler, SLOT(btOnValvePressed()));
	connect(m_btOffValve, SIGNAL(clicked()), m_pControler, SLOT(btOffValvePressed()));
	connect(m_btOnHeater, SIGNAL(clicked()), m_pControler, SLOT(btOnHeaterPressed()));
	connect(m_btOffHeater, SIGNAL(clicked()), m_pControler, SLOT(btOffHeaterPressed()));*/
}