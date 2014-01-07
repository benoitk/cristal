#include "CDialogStreamChoice.h"

#include "header_qt.h"
CDialogStreamChoice* CDialogStreamChoice::singleton = 0;

CDialogStreamChoice::CDialogStreamChoice()
	: QDialog()
{
	
	m_tabWidget = new QTabWidget(this);
	QWidget* widgetMain= new QWidget(this);

	//Barre de gauche
	/*m_lblNameSeuil1 = new QLabel(tr("Valeur max :"), this);
	m_lblNameSeuil1->setObjectName("lblPaveNumTxtBorne");
	m_lblValueSeuil1 = new QLabel(tr("Value"), this);
	m_lblValueSeuil1->setObjectName("lblPaveNumValueBorne");
	m_lblNameSeuil2 = new QLabel(tr("Valeur min :"), this);
	m_lblNameSeuil2->setObjectName("lblPaveNumTxtBorne");
	m_lblValueSeuil2 = new QLabel(tr("Value"), this);
	m_lblValueSeuil2->setObjectName("lblPaveNumValueBorne");*/
	
	/*QFormLayout* formLayout = new QFormLayout();
	formLayout->addRow(m_lblNameSeuil1, m_lblValueSeuil1);
	formLayout->addRow(m_lblNameSeuil2, m_lblValueSeuil2);*/
		

	//Block du milleu
	m_lblValue = new QLineEdit("0000000", this);
	m_lblValue->setEnabled(false);
	m_lblValue->setAlignment(Qt::AlignRight);
	//m_lblValue->setObjectName("lineEdit");
	//m_lblValue->setObjectName("lblPaveNumValue");
	//: Virgule à changer en point pour les nombres
	
	m_btOne = new QPushButton("1", this);
	m_btOne->setObjectName("btPaveNum");
	m_btTwo = new QPushButton("2", this);
	m_btTwo->setObjectName("btPaveNum");
	m_btThree = new QPushButton("3", this);
	m_btThree->setObjectName("btPaveNum");
	m_btFour = new QPushButton("4", this);
	m_btFour->setObjectName("btPaveNum");
	m_btFive = new QPushButton("5", this);
	m_btFive->setObjectName("btPaveNum");
	m_btSix = new QPushButton("6", this);
	m_btSix->setObjectName("btPaveNum");
	
	m_btPause = new QPushButton("Pause", this);
	m_btPause->setObjectName("btPaveNumPause");
    /*QSizePolicy expandPolicy(QSizePolicy::Ignored,QSizePolicy::Ignored);
    m_btPause->setSizePolicy(expandPolicy);*/

	QGridLayout* gridLayoutPaveNum = new QGridLayout();
	gridLayoutPaveNum->addWidget(m_btOne, 0, 0, Qt::AlignCenter);
	gridLayoutPaveNum->addWidget(m_btTwo, 0, 1, Qt::AlignCenter);
	gridLayoutPaveNum->addWidget(m_btThree, 0, 2, Qt::AlignCenter);
	gridLayoutPaveNum->addWidget(m_btFour, 1, 0, Qt::AlignCenter);
	gridLayoutPaveNum->addWidget(m_btFive, 1, 1, Qt::AlignCenter);
	gridLayoutPaveNum->addWidget(m_btSix, 1, 2, Qt::AlignCenter);
	gridLayoutPaveNum->addWidget(m_btPause, 2, 0, 1, 2, Qt::AlignCenter);
	

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
	m_tabWidget->addTab(widgetMain, tr("CHOIX DE LA VOIE"));

	QHBoxLayout* layoutMain = new QHBoxLayout();
	layoutMain->addWidget(m_tabWidget);

	setLayout(layoutMain);
	this->setObjectName("dialogModal");
	this->setWindowFlags(Qt::FramelessWindowHint);
	
	setConnexion();
}

CDialogStreamChoice* CDialogStreamChoice::getInstance()
{
	if(!singleton)
			singleton = new CDialogStreamChoice();
	disconnect(singleton, 0,0,0);
	return singleton;
}
void CDialogStreamChoice::setValueName(const QString& sNameValue)
{
	//m_tabWidget->setTabText(0, sNameValue);
}
void CDialogStreamChoice::setValue(const QString& sValue)
{
	bool bConvertionOk;
    if(sValue == "100")
        m_lblValue->setText(tr("PAUSE"));
    else
	    m_lblValue->setText(sValue);
	m_fValue = sValue.toFloat(&bConvertionOk);
	if(!bConvertionOk) m_fValue=1;
	
}
QString CDialogStreamChoice::getValue()
{
	if(m_lblValue->text() == QString(tr("PAUSE")))
	{
		return QString("99"); //voie de pause
	}
	return m_lblValue->text();
}
void CDialogStreamChoice::setNbStreamEnabled(int arg_nbStream)
{
    m_btTwo->setEnabled(false);
    m_btThree->setEnabled(false);
    m_btFour->setEnabled(false);
    m_btFive->setEnabled(false);
    m_btSix->setEnabled(false);

    switch(arg_nbStream)
    {
    case 6:
        m_btSix->setEnabled(true);
    case 5:
        m_btFive->setEnabled(true);
    case 4:
        m_btFour->setEnabled(true);
    case 3:
        m_btThree->setEnabled(true);
    case 2:
        m_btTwo->setEnabled(true);
    case 1:
       break;
    }
}
//SLOT
void CDialogStreamChoice::btOnePressed()
{
	addCharToValue("1");
}
//SLOT
void CDialogStreamChoice::btTwoPressed()
{
	addCharToValue("2");
}
//SLOT
void CDialogStreamChoice::btThreePressed()
{
	addCharToValue("3");
}
//SLOT
void CDialogStreamChoice::btFourPressed()
{
	addCharToValue("4");
}
//SLOT
void CDialogStreamChoice::btFivePressed()
{
	addCharToValue("5");
}
//SLOT
void CDialogStreamChoice::btSixPressed()
{
	addCharToValue("6");
}

//SLOT
void CDialogStreamChoice::btPausePressed()
{
	addCharToValue(tr("PAUSE"));
}

void CDialogStreamChoice::addCharToValue(const QString& sChar)
{
	m_lblValue->setText(sChar);
}
void CDialogStreamChoice::setConnexion()
{
	connect(m_btBack, SIGNAL(clicked()), this, SLOT(reject()));
	connect(m_btApply, SIGNAL(clicked()), this, SLOT(accept()));
	connect(m_btOne, SIGNAL(clicked()), this, SLOT(btOnePressed()));
	connect(m_btTwo, SIGNAL(clicked()), this, SLOT(btTwoPressed()));
	connect(m_btThree, SIGNAL(clicked()), this, SLOT(btThreePressed()));
	connect(m_btFour, SIGNAL(clicked()), this, SLOT(btFourPressed()));
	connect(m_btFive, SIGNAL(clicked()), this, SLOT(btFivePressed()));
	connect(m_btSix, SIGNAL(clicked()), this, SLOT(btSixPressed()));
	connect(m_btPause, SIGNAL(clicked()), this, SLOT(btPausePressed()));
	
	
}