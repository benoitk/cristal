#include "CDialogPassword.h"

#include "header_qt.h"
CDialogPassword* CDialogPassword::singleton = 0;
CDialogPassword::CDialogPassword(void)
{
	QTabWidget* tabWidget = new QTabWidget(this);
	QWidget* widgetMain= new QWidget(this);
		

	//Block du milleu
	m_lblValue = new QLineEdit(tr(""), this);
	m_lblValue->setEchoMode(QLineEdit::Password);
	m_lblValue->setEnabled(false);
	m_lblValue->setObjectName("lineEditPwd");
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
	m_btApply->setEnabled(false);
	m_btBack = new QPushButton();
	m_btBack->setObjectName("btCancel");
	m_btDelete = new QPushButton();
	m_btDelete->setObjectName("btBack");

	QVBoxLayout* layoutMenu = new QVBoxLayout();
	layoutMenu->addStretch();
	layoutMenu->addWidget(m_btDelete);
	//layoutMenu->addWidget(m_btApply);
	layoutMenu->addWidget(m_btBack);
	
	//Assemblage des trois principaux layout
	QHBoxLayout* hLayout = new QHBoxLayout(); //parent: widgetMain
	hLayout->addLayout(vLayoutPaveNum);
	hLayout->addLayout(layoutMenu);
	widgetMain->setLayout(hLayout);
	//: Nom de l'onglet à mettre en majuscule dans toutes les langues si possible
	tabWidget->addTab(widgetMain, tr("AUTHENTIFICATION"));

	QHBoxLayout* layoutMain = new QHBoxLayout();
	layoutMain->addWidget(tabWidget);
	setLayout(layoutMain);

	this->setObjectName("dialogModal");
	this->setWindowFlags(Qt::FramelessWindowHint);

	setConnexion();
}
void CDialogPassword::setPassordToCheck(const QString& sPwd,const QString& sPwd2)
{
    m_pwdToCheck = sPwd;
    m_pwdToCheck2 = sPwd2; 
    m_lblValue->clear();
}

//SLOT
void CDialogPassword::btDeletePressed()
{
	m_lblValue->setText("");

}
//SLOT
void CDialogPassword::btZeroPressed()
{
	addDigit("0");
}
//SLOT
void CDialogPassword::btOnePressed()
{
	addDigit("1");
}
//SLOT
void CDialogPassword::btTwoPressed()
{
	addDigit("2");
}
//SLOT
void CDialogPassword::btThreePressed()
{
	addDigit("3");
}
//SLOT
void CDialogPassword::btFourPressed()
{
	addDigit("4");
}
//SLOT
void CDialogPassword::btFivePressed()
{
	addDigit("5");
}
//SLOT
void CDialogPassword::btSixPressed()
{
	addDigit("6");
}
//SLOT
void CDialogPassword::btSevenPressed()
{
	addDigit("7");
}
//SLOT
void CDialogPassword::btEightPressed()
{
	addDigit("8");
}
//SLOT
void CDialogPassword::btNinePressed()
{
	addDigit("9");
}
void CDialogPassword::addDigit(QString sDigit)
{
	QString sTemp = m_lblValue->text();
	sTemp.append(sDigit);
	m_lblValue->setText(sTemp);
	if(m_lblValue->text().count() == 4)	
	{
		if(m_lblValue->text() == m_pwdToCheck || m_lblValue->text() == m_pwdToCheck2)
		{
			m_lblValue->setText(sTemp);
			m_pwdToCheck = sTemp;
			this->accept();
		}
		else
			m_lblValue->clear();		

	}


}
void CDialogPassword::setConnexion()
{

	//connect(m_btApply, SIGNAL(clicked()), this, SLOT(accept()));
	connect(m_btBack, SIGNAL(clicked()), this, SLOT(reject()));
	connect(m_btDelete, SIGNAL(clicked()), this, SLOT(btDeletePressed()));
	
	connect(m_btOne, SIGNAL(clicked()), this, SLOT(btOnePressed()));
	connect(m_btTwo, SIGNAL(clicked()), this, SLOT(btTwoPressed()));
	connect(m_btThree, SIGNAL(clicked()), this, SLOT(btThreePressed()));
	connect(m_btFour, SIGNAL(clicked()), this, SLOT(btFourPressed()));
	connect(m_btFive, SIGNAL(clicked()), this, SLOT(btFivePressed()));
	connect(m_btSix, SIGNAL(clicked()), this, SLOT(btSixPressed()));
	connect(m_btSeven, SIGNAL(clicked()), this, SLOT(btSevenPressed()));
	connect(m_btEight, SIGNAL(clicked()), this, SLOT(btEightPressed()));
	connect(m_btNine, SIGNAL(clicked()), this, SLOT(btNinePressed()));
	connect(m_btZero, SIGNAL(clicked()), this, SLOT(btZeroPressed()));

	//RAZ des valeurs lors de la fermeture
	connect(this, SIGNAL(accepted()), m_lblValue, SLOT(clear()));
	connect(m_btBack, SIGNAL(clicked()), m_lblValue, SLOT(clear()));
}

CDialogPassword* CDialogPassword::getInstance()
{
	if(!singleton)
			singleton = new CDialogPassword();
	disconnect(singleton, 0,0,0);
	return singleton;
}
