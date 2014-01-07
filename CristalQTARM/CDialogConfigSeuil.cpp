#include "CDialogConfigSeuil.h"

#include "header_qt.h"
CDialogConfigSeuil* CDialogConfigSeuil::singleton = 0;

CDialogConfigSeuil::CDialogConfigSeuil()
	: QDialog()
{
	
	m_tabWidget = new QTabWidget(this);
	QWidget* widgetMain= new QWidget(this);

	
	//Block du milleu
	m_lblValue = new QLineEdit("0000000", this);
	m_lblValue->setEnabled(false);
	m_lblValue->setAlignment(Qt::AlignRight);
	//m_lblValue->setObjectName("lineEdit");
	//m_lblValue->setObjectName("lblPaveNumValue");
	//: Virgule à changer en point pour les nombres
	
	m_btBasBas = new QPushButton(tr("Bas/Bas"), this);
	m_btBasBas->setObjectName("btPaveNumPause");
	m_btBasHaut= new QPushButton(tr("Bas/Haut"), this);
	m_btBasHaut->setObjectName("btPaveNumPause");
    m_btHautHaut = new QPushButton(tr("Haut/Haut"), this);
	m_btHautHaut->setObjectName("btPaveNumPause");
	
	
	QVBoxLayout* gridLayoutPaveNum = new QVBoxLayout();
	gridLayoutPaveNum->addWidget(m_btBasBas);
	gridLayoutPaveNum->addWidget(m_btBasHaut);
	gridLayoutPaveNum->addWidget(m_btHautHaut);
	
	
	QVBoxLayout* vLayoutPaveNum = new QVBoxLayout();
	vLayoutPaveNum->addWidget(m_lblValue, 0, Qt::AlignRight);
	vLayoutPaveNum->addLayout(gridLayoutPaveNum);

	//Menu de droite
	m_btApply = new QPushButton();
	m_btApply->setObjectName("btApply");
	m_btBack = new QPushButton();
	m_btBack->setObjectName("btCancel");
	

	QVBoxLayout* layoutMenu = new QVBoxLayout();
	layoutMenu->addStretch();
	layoutMenu->addWidget(m_btApply);
	layoutMenu->addWidget(m_btBack);
	
	//Assemblage des trois principaux layout
	QHBoxLayout* hLayout = new QHBoxLayout(); //parent: widgetMain
	/*hLayout->addLayout(formLayout);
	hLayout->addStretch(0);*/
	hLayout->addLayout(vLayoutPaveNum);
	//hLayout->addStretch(0);
	hLayout->addLayout(layoutMenu);
	widgetMain->setLayout(hLayout);
	//: Nom de l'onglet à mettre en majuscule dans toutes les langues si possible
	m_tabWidget->addTab(widgetMain, tr("TYPE DE SEUIL"));

	QHBoxLayout* layoutMain = new QHBoxLayout();
	layoutMain->addWidget(m_tabWidget);

	setLayout(layoutMain);
	this->setObjectName("dialogModal");
	this->setWindowFlags(Qt::FramelessWindowHint);
	
	setConnexion();
}

CDialogConfigSeuil* CDialogConfigSeuil::getInstance()
{
	if(!singleton)
			singleton = new CDialogConfigSeuil();
	disconnect(singleton, 0,0,0);
	return singleton;
}
void CDialogConfigSeuil::setValueName(const QString& sNameValue)
{
	//m_tabWidget->setTabText(0, sNameValue);
}
void CDialogConfigSeuil::setValue(int arg_numConfig)
{
	this->changeValue(arg_numConfig);	
}
int CDialogConfigSeuil::getValue()
{
	return m_nValue;
}
//SLOT
void CDialogConfigSeuil::btBasBasPressed()
{
	changeValue(0);
}
//SLOT
void CDialogConfigSeuil::btBasHautPressed()
{
	changeValue(1);
}
//SLOT
void CDialogConfigSeuil::btHautHautPressed()
{
	changeValue(2);
}

void CDialogConfigSeuil::changeValue(int arg_numConfig)
{
    QString sRetour = "";
    switch(arg_numConfig)
    {
    case 0:
        sRetour = tr("Bas/Bas");
        break;
    case 1:
        sRetour = tr("Bas/Haut");
        break;
    case 2:
    default: 
        sRetour = tr("Haut/Haut");
        break;
    }
    m_nValue = arg_numConfig;
	m_lblValue->setText(sRetour);
}
void CDialogConfigSeuil::setConnexion()
{
	connect(m_btBack, SIGNAL(clicked()), this, SLOT(reject()));
	connect(m_btApply, SIGNAL(clicked()), this, SLOT(accept()));
	connect(m_btBasBas, SIGNAL(clicked()), this, SLOT(btBasBasPressed()));
	connect(m_btBasHaut, SIGNAL(clicked()), this, SLOT(btBasHautPressed()));
	connect(m_btHautHaut, SIGNAL(clicked()), this, SLOT(btHautHautPressed()));
	
}