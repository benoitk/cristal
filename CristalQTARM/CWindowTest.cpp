#include "CWindowTest.h"
#include "stdafx.h"
#include "header.h"
#include "header_qt.h"


CWindowTest::CWindowTest(CListStream* argAnalyseur,CCarteIO* argCarteIO, QWidget *parent, Qt::WFlags flags)
{
	m_pAnalyseur = argAnalyseur;
	m_oCarteIO = argCarteIO;
	//Groupe des bouton 
	btClose = new QPushButton("Close");
	btClose->setStyleSheet("* { color: red }");
	btCarteMesure = new QPushButton("Carte mesure");
	btEVPompe = new QPushButton("EV/Pompes");
	btCarteExt = new QPushButton("Cartes Ext");
	btPanelPC = new QPushButton("Panel PC");
	btAnalyseur = new QPushButton("Analyseur");
	
	mainGroupBox = new QGroupBox(tr("Tests menu"));
	QGridLayout *boutonsLayout = new QGridLayout(mainGroupBox);
	
	boutonsLayout->addWidget(btCarteMesure, 0, 0, Qt::AlignHCenter);
	boutonsLayout->addWidget(btEVPompe, 1, 0, Qt::AlignHCenter);
	boutonsLayout->addWidget(btCarteExt, 2, 0, Qt::AlignHCenter);
	boutonsLayout->addWidget(btPanelPC, 3, 0, Qt::AlignHCenter);
	boutonsLayout->addWidget(btAnalyseur, 4, 0, Qt::AlignHCenter);
	boutonsLayout->addWidget(btClose, 5, 1, Qt::AlignHCenter);
	
	//mainLayout->setRowStretch ( 0, 90 );
	//mainLayout->setRowStretch ( 1, 10 );
	//mainLayout->setColumnStretch( 1, 10 );

	mainGroupBox->setLayout(boutonsLayout);


	mainLayout = new QGridLayout(this);
	//this->setLayout(mainLayout);

	mainLayout->addWidget(mainGroupBox,0,0);
	/*mainLayout->addWidget(verticalGroupBox,1,0);
	mainLayout->setRowStretch ( 0, 90 );
	mainLayout->setRowStretch ( 1, 10 );*/


	//Fenêtres
	oWinTestCartesExt = new CWindowTestCartesExt(argAnalyseur, argCarteIO, this);

	setConnections();

}

CWindowTest::~CWindowTest(){}


//SLOT
void CWindowTest::btAcquitterPressed()
{

}


void CWindowTest::setConnections()
{

	connect(btClose, SIGNAL(clicked()), this, SLOT(close()));
	connect(btCarteExt, SIGNAL(clicked()), oWinTestCartesExt, SLOT(showFullScreen()));
	
}
