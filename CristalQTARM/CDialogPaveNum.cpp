#include "CDialogPaveNum.h"

#include "header_qt.h"
CDialogPaveNum* CDialogPaveNum::singleton = 0;

CDialogPaveNum::CDialogPaveNum()
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
	m_btComma = new QPushButton(tr(","), this);
	m_btComma->setObjectName("btPaveNum");
	m_btPlusMinus = new QPushButton("+/-", this);
	m_btPlusMinus->setObjectName("btPaveNum");
	m_btZero = new QPushButton("0", this);
	m_btZero->setObjectName("btPaveNum");
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
	m_btSeven = new QPushButton("7", this);
	m_btSeven->setObjectName("btPaveNum");
	m_btEight = new QPushButton("8", this);
	m_btEight->setObjectName("btPaveNum");
	m_btNine = new QPushButton("9", this);
	m_btNine->setObjectName("btPaveNum");

	QGridLayout* gridLayoutPaveNum = new QGridLayout();
	gridLayoutPaveNum->addWidget(m_btOne, 0, 0, Qt::AlignCenter);
	gridLayoutPaveNum->addWidget(m_btTwo, 0, 1, Qt::AlignCenter);
	gridLayoutPaveNum->addWidget(m_btThree, 0, 2, Qt::AlignCenter);
	gridLayoutPaveNum->addWidget(m_btFour, 1, 0, Qt::AlignCenter);
	gridLayoutPaveNum->addWidget(m_btFive, 1, 1, Qt::AlignCenter);
	gridLayoutPaveNum->addWidget(m_btSix, 1, 2, Qt::AlignCenter);
	gridLayoutPaveNum->addWidget(m_btSeven, 2, 0, Qt::AlignCenter);
	gridLayoutPaveNum->addWidget(m_btEight, 2, 1, Qt::AlignCenter);
	gridLayoutPaveNum->addWidget(m_btNine, 2, 2, Qt::AlignCenter);
	gridLayoutPaveNum->addWidget(m_btPlusMinus, 3, 0, Qt::AlignCenter);
	gridLayoutPaveNum->addWidget(m_btZero, 3, 1, Qt::AlignCenter);
	gridLayoutPaveNum->addWidget(m_btComma, 3, 2, Qt::AlignCenter);

	QVBoxLayout* vLayoutPaveNum = new QVBoxLayout();
	vLayoutPaveNum->addWidget(m_lblValue, 0, Qt::AlignRight);
	vLayoutPaveNum->addLayout(gridLayoutPaveNum);

	//Menu de droite
	m_btApply = new QPushButton();
	m_btApply->setObjectName("btApply");
	m_btBack = new QPushButton();
	m_btBack->setObjectName("btCancel");
	m_btDelete = new QPushButton();
	m_btDelete->setObjectName("btBack");

	QVBoxLayout* layoutMenu = new QVBoxLayout();
	layoutMenu->addStretch();
	layoutMenu->addWidget(m_btDelete);
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
	m_tabWidget->addTab(widgetMain, tr("PAVE NUMERIQUE"));

	QHBoxLayout* layoutMain = new QHBoxLayout();
	layoutMain->addWidget(m_tabWidget);

	setLayout(layoutMain);
	this->setObjectName("dialogModal");
	this->setWindowFlags(Qt::FramelessWindowHint);
	
	setConnexion();
}

CDialogPaveNum* CDialogPaveNum::getInstance()
{
	if(!singleton)
			singleton = new CDialogPaveNum();
	disconnect(singleton, 0,0,0);
	return singleton;
}
void CDialogPaveNum::setValueName(const QString& sNameValue)
{
	m_tabWidget->setTabText(0, sNameValue);
}
void CDialogPaveNum::setValue(const QString& sValue)
{
	bool bConvertionOk;
	m_lblValue->setText(sValue);
	m_fValue = sValue.toFloat(&bConvertionOk);
	if(!bConvertionOk) m_fValue=0;
	
}
QString CDialogPaveNum::getValue()
{
	if(m_lblValue->text().contains(",") || m_lblValue->text().contains(".")) 
	{
		QString sValue = m_lblValue->text();
		QString sRight = sValue.section(',',1,1);
		if(sRight.isEmpty())
		{
			sRight = sValue.section('.',1,1);
			if(sRight.count('0') == sRight.size()) sValue = sValue.section('.',0,0);
		}
		else 
		{
			if(sRight.count('0') == sRight.size()) sValue = sValue.section(',',0,0);
		}
		if(sValue.endsWith(",") || sValue.endsWith(".")) sValue.chop(1);
		m_lblValue->setText(sValue);
	}
	return m_lblValue->text();
}
//SLOT
void CDialogPaveNum::btDeletePressed()
{
	QString sValue = m_lblValue->text();
	sValue.chop(1);
	if(sValue == "") sValue = "0";
	m_lblValue->setText(sValue);

}
//SLOT
void CDialogPaveNum::btZeroPressed()
{
	addCharToValue("0");
}
//SLOT
void CDialogPaveNum::btOnePressed()
{
	addCharToValue("1");
}
//SLOT
void CDialogPaveNum::btTwoPressed()
{
	addCharToValue("2");
}
//SLOT
void CDialogPaveNum::btThreePressed()
{
	addCharToValue("3");
}
//SLOT
void CDialogPaveNum::btFourPressed()
{
	addCharToValue("4");
}
//SLOT
void CDialogPaveNum::btFivePressed()
{
	addCharToValue("5");
}
//SLOT
void CDialogPaveNum::btSixPressed()
{
	addCharToValue("6");
}
//SLOT
void CDialogPaveNum::btSevenPressed()
{
	addCharToValue("7");
}
//SLOT
void CDialogPaveNum::btEightPressed()
{
	addCharToValue("8");
}
//SLOT
void CDialogPaveNum::btNinePressed()
{
	addCharToValue("9");
}
//SLOT
void CDialogPaveNum::btCommaPressed()
{
	QString sValue = m_lblValue->text();
	if(!sValue.contains(",") && !sValue.contains("."))
		addCharToValue(".");
	
}
//SLOT
void CDialogPaveNum::btPlusMinusPressed()
{
	QString sValue = m_lblValue->text();
	if(sValue.left(1) == "-")
	{
		sValue.remove(0,1);
	}
	else
	{
		sValue.prepend('-');
	}
	m_lblValue->setText(sValue);
}
void CDialogPaveNum::addCharToValue(const QString& sChar)
{
	QString sValue = m_lblValue->text();
	if(sValue != "0" || (sValue == "0" && sChar == "."))
		sValue += sChar;
	else
		sValue = sChar;
	m_lblValue->setText(sValue);
}
void CDialogPaveNum::setConnexion()
{
	connect(m_btBack, SIGNAL(clicked()), this, SLOT(reject()));
	connect(m_btApply, SIGNAL(clicked()), this, SLOT(accept()));
	connect(m_btOne, SIGNAL(clicked()), this, SLOT(btOnePressed()));
	connect(m_btTwo, SIGNAL(clicked()), this, SLOT(btTwoPressed()));
	connect(m_btThree, SIGNAL(clicked()), this, SLOT(btThreePressed()));
	connect(m_btFour, SIGNAL(clicked()), this, SLOT(btFourPressed()));
	connect(m_btFive, SIGNAL(clicked()), this, SLOT(btFivePressed()));
	connect(m_btSix, SIGNAL(clicked()), this, SLOT(btSixPressed()));
	connect(m_btSeven, SIGNAL(clicked()), this, SLOT(btSevenPressed()));
	connect(m_btEight, SIGNAL(clicked()), this, SLOT(btEightPressed()));
	connect(m_btNine, SIGNAL(clicked()), this, SLOT(btNinePressed()));
	connect(m_btComma, SIGNAL(clicked()), this, SLOT(btCommaPressed()));
	connect(m_btZero, SIGNAL(clicked()), this, SLOT(btZeroPressed()));
	connect(m_btPlusMinus, SIGNAL(clicked()), this, SLOT(btPlusMinusPressed()));
	connect(m_btDelete, SIGNAL(clicked()), this, SLOT(btDeletePressed()));
	
}