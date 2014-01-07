#include "CWinExternalCardView.h"
#include "CWinExternalCardControler.h"
#include "CWinExternalCardModel.h"





CWinExternalCardView::CWinExternalCardView(CWinExternalCardControler* argpControler, QWidget *parent,Qt::WindowFlags flags)
	: QMainWindow(parent, flags)
{
	m_pControler = argpControler;
}

void CWinExternalCardView::init()
{
	
	QTabWidget* m_tabWidget = new QTabWidget();
	//*** onglet relais

	QWidget* widgetRelais = new QWidget();
	QFormLayout* layoutCentral = new QFormLayout();
	for(int i=0; i<m_pModel->getNbDigitOut(); ++i)
	{
		CPushButton* btOn = new CPushButton(i);
		btOn->setObjectName("btOn");
		m_listBtOnRelais.append(btOn);
		CPushButton* btOff = new CPushButton(i);
		btOff->setObjectName("btOff");
		m_listBtOffRelais.append(btOff);
		QHBoxLayout* layoutBtRelais = new QHBoxLayout();
		layoutBtRelais->addWidget(btOn,50, Qt::AlignCenter);
		layoutBtRelais->addWidget(btOff,50, Qt::AlignLeft);
		layoutCentral->addRow(m_pModel->getLblDigiOut(i), layoutBtRelais);
	}

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
	/*layoutGauche->addLayout(layoutNav);*/

	//menu de gauche //toujours 4 items dans les menus en incluant les spacers
	QPushButton* btBack = new QPushButton();
	m_listBtBack.append(btBack);
	btBack->setObjectName("btBack");

	QVBoxLayout* layoutMenu = new QVBoxLayout();
	layoutMenu->addStretch();
	layoutMenu->addWidget(btBack);

	//assemblage du menu et du layoutGauche
	QHBoxLayout* layoutMain = new QHBoxLayout();
	layoutMain->addLayout(layoutGauche);
	layoutMain->addLayout(layoutMenu);
	widgetRelais->setLayout(layoutMain);
	//: Nom de l'onglet à laisser en maj pour toute les trad
	m_tabWidget->addTab(widgetRelais, tr("RELAIS"));

	//*** onglet sortie 4-20
	QWidget* widgetAna = new QWidget();
	
	QPushButton* btValMesure = new QPushButton();
	btValMesure->setText(m_pModel->getValueMesure());
	btValMesure->setObjectName("btLineEdit");
	m_btValAna = new QPushButton();
	m_btValAna->setText(m_pModel->getValueValAna());
	m_btValAna->setObjectName("btLineEdit");
	m_btValMaxConvertisseur = new QPushButton();
	m_btValMaxConvertisseur->setText(m_pModel->getValueValMaxConvertisseur(0));
	m_btValMaxConvertisseur->setObjectName("btLineEdit");
	m_btValMaxConvertisseurPlus = new QPushButton();
	m_btValMaxConvertisseurMoins = new QPushButton();
	m_btValMinConvertisseur = new QPushButton();
	m_btValMinConvertisseur->setText(m_pModel->getValueValMinConvertisseur(0));
	m_btValMinConvertisseur->setObjectName("btLineEdit");
	m_btValMinConvertisseurPlus = new QPushButton();
	m_btValMinConvertisseurMoins = new QPushButton();
	
	QGridLayout* gridLayoutAna = new QGridLayout();
	gridLayoutAna->addWidget(new QLabel(m_pModel->getLblMesure()), 0, 0);
	gridLayoutAna->addWidget(btValMesure, 0, 1);
	gridLayoutAna->addWidget(new QLabel(m_pModel->getUniteMesure()), 0, 2);
	gridLayoutAna->addWidget(new QLabel(m_pModel->getLblValAna()), 1, 0);
	gridLayoutAna->addWidget(m_btValAna, 1, 1);
	gridLayoutAna->addWidget(new QLabel(m_pModel->getUniteValAna()), 1, 2);
	gridLayoutAna->addWidget(new QLabel(m_pModel->getLblValMaxConvertisseur()), 2, 0);
	gridLayoutAna->addWidget(m_btValMaxConvertisseur, 2, 1);
	gridLayoutAna->addWidget(new QLabel(m_pModel->getUniteValMaxConvertisseur()), 2, 2);
	gridLayoutAna->addWidget(new QLabel(m_pModel->getLblValMinConvertisseur()), 3, 0);
	gridLayoutAna->addWidget(m_btValMinConvertisseur, 3, 1);
	gridLayoutAna->addWidget(new QLabel(m_pModel->getUniteValMinConvertisseur()), 3, 2);

	m_btRadioTest4mA = new QRadioButton(tr("4mA"));
	m_btRadioTest4mA->setObjectName("btRadio");
	m_btRadioTest12mA = new QRadioButton(tr("12mA"));
	m_btRadioTest12mA->setObjectName("btRadio");
	m_btRadioTest20mA = new QRadioButton(tr("20mA"));
	m_btRadioTest20mA->setObjectName("btRadio");
	QGridLayout* gridLayoutRadio = new QGridLayout();
	gridLayoutRadio->addWidget(m_btRadioTest4mA, 0, 0);
	gridLayoutRadio->addWidget(m_btRadioTest12mA, 0, 1);
	gridLayoutRadio->addWidget(m_btRadioTest20mA, 0, 2);
	
	QVBoxLayout* boxLayout= new QVBoxLayout();
	boxLayout->addLayout(gridLayoutAna);
	boxLayout->addLayout(gridLayoutRadio);

	//menu de gauche //toujours 4 items dans les menus en incluant les spacers
    btBack = new QPushButton();
	m_listBtBack.append(btBack);
	btBack->setObjectName("btBack");

	QVBoxLayout* layoutMenuAna = new QVBoxLayout();
	layoutMenuAna->addStretch();
	layoutMenuAna->addWidget(btBack);

	//assemblage du menu et du layoutGauche
	QHBoxLayout* layoutMainAna = new QHBoxLayout();
	layoutMainAna->addLayout(boxLayout);
	layoutMainAna->addLayout(layoutMenuAna);
	
	widgetAna->setLayout(layoutMainAna);
	//: Nom de l'onglet à laisser en maj pour toute les trad
	m_tabWidget->addTab(widgetAna , tr("SORTIE 4-20mA"));



	//*** onglet Entree ana/tor



	setCentralWidget(m_tabWidget);
	setConnexion();
}

void CWinExternalCardView::setConnexion()
{
	QPushButton* btTmp;
	foreach(btTmp, m_listBtBack)
	{
		connect(btTmp, SIGNAL(clicked()), m_pControler,SLOT(btBackPressed()));	
	}

	CPushButton* btTemp;
	foreach(btTemp, m_listBtOnRelais)
	{
			connect(btTemp, SIGNAL(clicked(int)), m_pControler, SLOT(btOnRelaisPressed(int)));
	}
	foreach(btTemp, m_listBtOffRelais)
	{
			connect(btTemp, SIGNAL(clicked(int)), m_pControler, SLOT(btOffRelaisPressed(int)));
	}

	connect(m_btRadioTest4mA, SIGNAL(clicked()), m_pControler, SLOT(btRadioTest4mAPressed()));
	connect(m_btRadioTest12mA, SIGNAL(clicked()), m_pControler, SLOT(btRadioTest12mAPressed()));
	connect(m_btRadioTest20mA, SIGNAL(clicked()), m_pControler, SLOT(btRadioTest20mAPressed()));

	connect(m_btValMaxConvertisseur, SIGNAL(clicked()), m_pControler, SLOT(btValMaxConvertisseurPressed()));
	connect(m_btValMinConvertisseur, SIGNAL(clicked()), m_pControler, SLOT(btValMinConvertisseurPressed()));

}