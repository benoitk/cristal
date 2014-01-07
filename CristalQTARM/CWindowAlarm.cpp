#include "CWindowAlarm.h"
#include "stdafx.h"
#include "header.h"
#include "header_qt.h"
CWindowAlarm::CWindowAlarm(QWidget *parent, Qt::WFlags flags)
{
	//Groupe de la liste des alarmes
	formGroupBox = new QGroupBox(tr("Alarmes"));
	listWidget = new QListWidget();
	QFormLayout *formLayout = new QFormLayout(formGroupBox);
	formLayout->addWidget(listWidget);
	formGroupBox->setLayout(formLayout);
	
	//Groupe du bouton close
	btClose = new QPushButton("Close");
	btAcquitter = new QPushButton("Acquitter");
	verticalGroupBox = new QGroupBox(tr("Actions"));
	QHBoxLayout *HBoxLayout = new QHBoxLayout(verticalGroupBox);
	HBoxLayout->addWidget(btClose);
	HBoxLayout->addWidget(btAcquitter);

	verticalGroupBox->setLayout(HBoxLayout);


	mainLayout = new QGridLayout(this);
	//this->setLayout(mainLayout);

	mainLayout->addWidget(formGroupBox,0,0);
	mainLayout->addWidget(verticalGroupBox,1,0);
	mainLayout->setRowStretch ( 0, 90 );
	mainLayout->setRowStretch ( 1, 10 );
	//mainLayout->setColumnStretch( 1, 10 );

	setConnections();

}


void CWindowAlarm::setAnalyseur(CListStream *argAnalyseur)
{
	m_pAnalyseur = argAnalyseur;
}

//SLOT
void CWindowAlarm::btAcquitterPressed()
{
	
}

//SLOT
void CWindowAlarm::updateAlarms()
{
	for(int i=0; i<m_pAnalyseur->m_ListMessageError.iGetCount();i++)
	{
		m_pAnalyseur->m_ListMessageError.pGetAt(i)->lGetLabelLength(); 
		//QString::fromUtf16(( const ushort *)CElemCycle::m_CurrentStep.szGetLabel()
		//			     , CElemCycle::m_CurrentStep.lGetLabelLength())
		if(QString::fromUtf16(( const ushort *)m_pAnalyseur->m_ListMessageError.pGetAt(i)->szGetLabel(), m_pAnalyseur->m_ListMessageError.pGetAt(i)->lGetLabelLength()) 
			!= "CElemBase")
		{		
			new QListWidgetItem( QString::fromUtf16(( const ushort *)m_pAnalyseur->m_ListMessageError.pGetAt(i)->szGetLabel()
														  , m_pAnalyseur->m_ListMessageError.pGetAt(i)->lGetLabelLength())
						   , listWidget);
		}
	}
	
}


void CWindowAlarm::setConnections()
{
	//Connection groupe de boutons de droite
	//connect(btAcquitter, SIGNAL(clicked()), this, SLOT(btAcquitterPressed()));
	connect(btClose, SIGNAL(clicked()), this, SLOT(close()));
	connect(btAcquitter, SIGNAL(clicked()), listWidget, SLOT(clear()));
	connect(btAcquitter, SIGNAL(clicked()), this, SLOT(btAcquitterPressed()));
}

void CWindowAlarm::showEvent ( QShowEvent * event )
{
	updateAlarms();
}