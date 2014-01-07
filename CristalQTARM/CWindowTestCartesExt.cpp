#include "CWindowTestCartesExt.h"
#include "stdafx.h"
#include "header.h"
#include "header_qt.h"


CWindowTestCartesExt::CWindowTestCartesExt(CListStream* argAnalyseur,CCarteIO* argCarteIO, QWidget *parent, Qt::WFlags flags)
{

	m_pAnalyseur = argAnalyseur;
	m_oCarteIO = argCarteIO;
	bBtSD1Pressed =false;

	btClose = new QPushButton("Close");
	btClose->setStyleSheet("* { color: red }");
	btSD1 = new QPushButton();
	btSD2 = new QPushButton();
	btSD3 = new QPushButton();
	btSD4 = new QPushButton();
	btSD5 = new QPushButton();
	btSD6 = new QPushButton();
	btSD7 = new QPushButton();
	btSD8 = new QPushButton();
	
	//Groupe principale
	mainGroupBox = new QGroupBox(tr("Digital Output"));

	QGridLayout *layoutCentral = new QGridLayout(mainGroupBox);
	QFormLayout *boutonsLayoutGauche = new QFormLayout();
	QFormLayout *boutonsLayoutDroit = new QFormLayout();
	
	boutonsLayoutGauche->addRow(tr("&Output 1:"), btSD1);
	boutonsLayoutGauche->addRow(tr("&Output 2:"), btSD2);
	boutonsLayoutGauche->addRow(tr("&Output 3:"), btSD3);
	boutonsLayoutGauche->addRow(tr("&Output 4:"), btSD4);
	boutonsLayoutDroit->addRow(tr("&Output 5:"), btSD5);
	boutonsLayoutDroit->addRow(tr("&Output 6:"), btSD6);
	boutonsLayoutDroit->addRow(tr("&Output 7:"), btSD7);
	boutonsLayoutDroit->addRow(tr("&Output 8:"), btSD8);

	layoutCentral->addLayout(boutonsLayoutGauche, 0,0);
	layoutCentral->addLayout(boutonsLayoutDroit, 0,1);
	
	mainGroupBox->setLayout(layoutCentral);
	//mainLayout->setRowStretch ( 0, 90 );
	//mainLayout->setRowStretch ( 1, 10 );
	//mainLayout->setColumnStretch( 1, 10 );

	//Groupe du bas
	actionGroupBox = new QGroupBox(tr(""));
	QGridLayout *boutonsLayoutBas = new QGridLayout(actionGroupBox);
	boutonsLayoutBas->addWidget(btClose,0,0);
	boutonsLayoutBas->setAlignment(btClose, Qt::AlignLeft);
	actionGroupBox->setLayout(boutonsLayoutBas);

	//Mise ne place des groupes
	mainLayout = new QGridLayout(this);
	
	mainLayout->addWidget(mainGroupBox,0,0);
	mainLayout->addWidget(actionGroupBox,1,0);

	mainLayout->setRowStretch ( 0, 90 );
	mainLayout->setRowStretch ( 1, 10 );

	setConnections();

}

CWindowTestCartesExt::~CWindowTestCartesExt(){}


//SLOT
void CWindowTestCartesExt::btbtSD1Pressed()
{
	if(bBtSD1Pressed)
	{
		btSD1->setDown(false);
		cycleStep.bExecuteNumExchange(0,m_oCarteIO->getListExchange(),TRUE,TRUE , m_pAnalyseur->m_ExternalInterface);
		
	}
	else
	{
		cycleStep.bExecuteNumExchange(1,m_oCarteIO->getListExchange(),TRUE,TRUE , m_pAnalyseur->m_ExternalInterface);
		btSD1->setDown(true);
	}

	bBtSD1Pressed = !bBtSD1Pressed;
}

void CWindowTestCartesExt::btbtSD2Pressed()
{
	m_pAnalyseur->m_CmdRemoteControl.bSetVal(1);
	m_pAnalyseur->SetRemoteControl();
	m_pAnalyseur->m_CmdRun.bSetVal(0);
}

void CWindowTestCartesExt::setConnections()
{

	connect(btClose, SIGNAL(clicked()), this, SLOT(close()));
	connect(btSD1, SIGNAL(clicked()), this, SLOT(btbtSD1Pressed()));
	connect(btSD2, SIGNAL(clicked()), this, SLOT(btbtSD2Pressed()));
		
}
