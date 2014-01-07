#include "CWinEVPompeView.h"
#include "CWinEVPompeControler.h"
#include "CWinEVPompeModel.h"

#include "header.h"
#include "header_ihm.h"





CWinEVPompeView::CWinEVPompeView(CWinEVPompeControler* argpControler, QWidget *parent,Qt::WindowFlags flags)
	: QMainWindow(parent, flags)
{
	qDebug() << "### Instance CWinEVPompeView" << endl;
	m_pControler = argpControler;
}

void CWinEVPompeView::init()
{
	
	m_tabWidget = new QTabWidget();
	//*** onglet EV

	QWidget* widgetEV = new QWidget();
	/*QLabel* lblNomRelais1 = new QLabel("Relais 1");
	lblNomRelais1->SetObjectName("lblNomRelais1");
	QLabel* lblNomRelais2 = new QLabel("Relais 2");
	lblNomRelais2->SetObjectName("lblNomRelais2");*/
/*-	m_btOnEV1 = new QPushButton();
	m_btOnEV1->setObjectName("btOn");
	m_btOffEV1 = new QPushButton();
	m_btOffEV1->setObjectName("btOff");

	QHBoxLayout* layoutBtEV1 = new QHBoxLayout();
	layoutBtEV1->addWidget(m_btOnEV1,50, Qt::AlignCenter);
	layoutBtEV1->addWidget(m_btOffEV1,50, Qt::AlignLeft);*/
	//QHBoxLayout* layoutBtRelais2 = new QHBoxLayout();
	//layoutBtRelais2->addWidget(m_btOnRelais2,50, Qt::AlignRight);
	//layoutBtRelais2->addWidget(m_btOffRelais2,50, Qt::AlignLeft);

	//centre de la fenêtre
	QFormLayout* layoutCentral = new QFormLayout();
//	layoutCentral->addRow(m_pModel->getEVLabel(0), layoutBtEV1);
	//layoutCentral->addRow("Relais 2", layoutBtRelais2);

	//Bando de navigation du bas
	/*m_btNextPage = new QPushButton();
	m_btNextPage->setObjectName("btNextPage");
	m_btPreviousPage = new QPushButton();
	m_btPreviousPage->setObjectName("btPreviousPage");
	QHBoxLayout* layoutNav= new QHBoxLayout();
	layoutNav->addWidget(m_btNextPage,5, Qt::AlignCenter);
	layoutNav->addWidget(m_btPreviousPage,5, Qt::AlignLeft);*/

	//Assemblage centre et bando de nav
	QVBoxLayout* layoutGauche= new QVBoxLayout();
	layoutGauche->addLayout(layoutCentral);
	//layoutGauche->addLayout(layoutNav);

	//menu de gauche //toujours 4 items dans les menus en incluant les spacers
	QPushButton* btBack = new QPushButton();
	m_vectorBtBack.append(btBack);
	btBack->setObjectName("btBack");

	QVBoxLayout* layoutMenu = new QVBoxLayout();
	layoutMenu->addStretch();
	layoutMenu->addWidget(btBack);

	//assemblage du menu et du layoutGauche
	QHBoxLayout* layoutMain = new QHBoxLayout();
	layoutMain->addLayout(layoutGauche);
	layoutMain->addLayout(layoutMenu);
	widgetEV->setLayout(layoutMain);
	//: Nom de l'onglet à laisser en maj pour toute les langues si possible
	m_tabWidget->addTab(widgetEV, tr("ELECTROVANNE"));

	//*** onglet Pompe
	QWidget* widgetPompe = new QWidget();
	/*QLabel* lblNomRelais1 = new QLabel("Relais 1");
	lblNomRelais1->SetObjectName("lblNomRelais1");
	QLabel* lblNomRelais2 = new QLabel("Relais 2");
	lblNomRelais2->SetObjectName("lblNomRelais2");*/

	//centre de la fenêtre
	layoutCentral = new QFormLayout();
	QString sPumpLabel;
	qDebug() << "#### foreach(sPumpLabel, m_pModel->getVectorPumpLabels())" << endl;
	foreach(sPumpLabel, m_pModel->getVectorPumpLabels())
	{
		QPushButton* btOnTemp = new QPushButton();
		btOnTemp->setObjectName("btOn");
		m_vBtOnPompe.append(btOnTemp);

		QPushButton* btOffTemp = new QPushButton();
		btOffTemp->setObjectName("btOff");
		m_vBtOffPompe.append(btOffTemp);

		QHBoxLayout* layoutBtPompe = new QHBoxLayout();
		layoutBtPompe->addWidget(btOnTemp,50, Qt::AlignCenter);
		layoutBtPompe->addWidget(btOffTemp,50, Qt::AlignLeft);

		layoutCentral->addRow(sPumpLabel, layoutBtPompe);	
	}
qDebug() << "#### 1";

	qDebug() << "#### AA FIN foreach(sPumpLabel, m_pModel->getVectorPumpLabels())" << endl;
	
qDebug() << "#### 1";
	
	//Assemblage centre et bando de nav
	layoutGauche= new QVBoxLayout();
	layoutGauche->addLayout(layoutCentral);
	//layoutGauche->addLayout(layoutNav);
qDebug() << "#### 1";

	//menu de gauche //toujours 4 items dans les menus en incluant les spacers
	btBack = new QPushButton();
	m_vectorBtBack.append(btBack);
	btBack->setObjectName("btBack");
qDebug() << "#### 1";

	layoutMenu = new QVBoxLayout();
	layoutMenu->addStretch();
	layoutMenu->addWidget(btBack);
qDebug() << "#### 1";

	//assemblage du menu et du layoutGauche
	layoutMain = new QHBoxLayout();
	layoutMain->addLayout(layoutGauche);
	layoutMain->addLayout(layoutMenu);
	widgetPompe->setLayout(layoutMain);
	//: Nom de l'onglet à laisser en maj pour toutes les langues
	m_tabWidget->addTab(widgetPompe, tr("POMPE"));
qDebug() << "#### 1";
	
	//*** 
	setCentralWidget(m_tabWidget);
qDebug() << "#### 1";
	setConnexion();
qDebug() << "#### 1";
}

void CWinEVPompeView::setConnexion()
{
	qDebug() << "#### CWinEVPompeView::setConnexion" << endl;
	QPushButton* btTemp;
	foreach(btTemp, m_vectorBtBack)
	{
		connect(btTemp, SIGNAL(clicked()), m_pControler,SLOT(btBackPressed()));	
	}
	//tab EV
//	connect(m_btOnEV1, SIGNAL(clicked()), m_pControler,SLOT(btOnEV1Pressed()));
//	connect(m_btOffEV1, SIGNAL(clicked()), m_pControler,SLOT(btOffEV1Pressed()));
	//Tab Pompe
	int nNbPompe = m_vBtOnPompe.count();
	qDebug() << "#### CWinEVPompeView::setConnexion | Nb pompe" << nNbPompe << endl;
	if(0 < nNbPompe) connect(m_vBtOnPompe.at(0), SIGNAL(clicked()), m_pControler,SLOT(btOnPompe1Pressed()));
	if(0 < nNbPompe) connect(m_vBtOffPompe.at(0), SIGNAL(clicked()), m_pControler,SLOT(btOffPompe1Pressed()));
	if(1 < nNbPompe) connect(m_vBtOnPompe.at(1), SIGNAL(clicked()), m_pControler,SLOT(btOnPompe2Pressed()));
	if(1 < nNbPompe) connect(m_vBtOffPompe.at(1), SIGNAL(clicked()), m_pControler,SLOT(btOffPompe2Pressed()));
	if(2 < nNbPompe) connect(m_vBtOnPompe.at(2), SIGNAL(clicked()), m_pControler,SLOT(btOnPompe3Pressed()));
	if(2 < nNbPompe) connect(m_vBtOffPompe.at(2), SIGNAL(clicked()), m_pControler,SLOT(btOffPompe3Pressed()));
	if(3 < nNbPompe) connect(m_vBtOnPompe.at(3), SIGNAL(clicked()), m_pControler,SLOT(btOnPompe4Pressed()));
	if(3 < nNbPompe) connect(m_vBtOffPompe.at(3), SIGNAL(clicked()), m_pControler,SLOT(btOffPompe4Pressed()));
	if(4 < nNbPompe) connect(m_vBtOnPompe.at(4), SIGNAL(clicked()), m_pControler,SLOT(btOnPompe5Pressed()));
	if(4 < nNbPompe) connect(m_vBtOffPompe.at(4), SIGNAL(clicked()), m_pControler,SLOT(btOffPompe5Pressed()));
	if(5 < nNbPompe) connect(m_vBtOnPompe.at(5), SIGNAL(clicked()), m_pControler,SLOT(btOnPompe6Pressed()));
	if(5 < nNbPompe) connect(m_vBtOffPompe.at(5), SIGNAL(clicked()), m_pControler,SLOT(btOffPompe6Pressed()));

	//Event des onglets
	connect(m_tabWidget, SIGNAL(currentChanged(int)), m_pControler, SLOT(tabChanged(int)));
}