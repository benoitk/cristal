#include "CDialogResultatEtalon.h"
#include "CDialogPaveNum.h"

#include "header_qt.h"

CDialogResultatEtalon* CDialogResultatEtalon::singleton = 0;
CDialogResultatEtalon::CDialogResultatEtalon(void): QDialog()
{
	//menu de droite //toujours 4 items dans les menus en incluant les spacers
	m_btApply = new QPushButton();
	m_btApply->setObjectName("btApply");
	m_btBack = new QPushButton();
	m_btBack->setObjectName("btCancel");

	QVBoxLayout* layoutMenu = new QVBoxLayout();
	layoutMenu->addStretch();
	layoutMenu->addWidget(m_btApply);
	layoutMenu->addWidget(m_btBack);
	m_sTittle = "init";
	m_sValue = "init";
	m_sDialogTittle = "init";
	
	m_tabWidget = new QTabWidget();

	QWidget* widgetDialog = new QWidget();
	m_tabWidget->addTab(widgetDialog, "toto");

	m_btValue = new QPushButton();
	m_lblValue = new QLabel("**********");
	m_btValue->setObjectName("btLineEdit");
	m_btValue2 = new QPushButton();
	m_lblValue2 = new QLabel("**********");
	m_btValue2->setObjectName("btLineEdit");
	m_btValue3 = new QPushButton();
	m_lblValue3 = new QLabel("**********");
	m_btValue3->setObjectName("btLineEdit");
    m_btValue4 = new QPushButton();
	m_lblValue4 = new QLabel("**********");
	m_btValue4->setObjectName("btLineEdit");
	QFormLayout* formLayout = new QFormLayout();
	formLayout->addRow(m_lblValue, m_btValue);
	formLayout->addRow(m_lblValue2, m_btValue2);
	formLayout->addRow(m_lblValue3, m_btValue3);
	formLayout->addRow(m_lblValue4, m_btValue4);
	
	m_lblMessageErreur = new QLabel();
	m_lblMessageErreur->setObjectName("lblError");
	m_lblMessageErreur->setVisible(false);
	QVBoxLayout* layoutGauche = new QVBoxLayout();
	layoutGauche->addLayout(formLayout);
	layoutGauche->addWidget(m_lblMessageErreur);

	//assemblage du menu et du layoutGauche
	QHBoxLayout* layoutMain = new QHBoxLayout();
	layoutMain->addLayout(layoutGauche);
	layoutMain->addLayout(layoutMenu);
	widgetDialog->setLayout(layoutMain);
	
	
	QHBoxLayout* layout = new QHBoxLayout();
	layout->addWidget(m_tabWidget);

	setLayout(layout);
	this->setObjectName("dialogModal");
	this->setWindowFlags(Qt::FramelessWindowHint);

	setConnexion();
}

void CDialogResultatEtalon::setLblMessageErreur(const QString& arg_sMsg)
{
	m_lblMessageErreur->setVisible(true);
	m_lblMessageErreur->setText(arg_sMsg);
}
void CDialogResultatEtalon::disabledBtApply()
{
    m_btApply->setEnabled(false);
}

void CDialogResultatEtalon::setTittle(const QString& sTittle)
{
	 m_tabWidget->setTabText(0, sTittle);
}
void CDialogResultatEtalon::setLine(const QString& sLblTittle, const QString& sValue)
{
	m_lblValue->setText(sLblTittle);
	m_btValue->setText(sValue);
    m_lblValue2->setVisible(false);
    m_btValue2->setVisible(false);
    m_lblValue3->setVisible(false);
    m_btValue3->setVisible(false);
    m_lblValue4->setVisible(false);
    m_btValue4->setVisible(false);
	this->updateGeometry();
}

void CDialogResultatEtalon::setLine2(const QString& sLblTittle, const QString& sValue)
{
    m_lblValue2->setVisible(true);
    m_btValue2->setVisible(true);
	m_lblValue2->setText(sLblTittle);
	m_btValue2->setText(sValue);
	this->updateGeometry();
}

void CDialogResultatEtalon::setLine3(const QString& sLblTittle, const QString& sValue)
{
	m_lblValue3->setVisible(true);
    m_btValue3->setVisible(true);
	m_lblValue3->setText(sLblTittle);
	m_btValue3->setText(sValue);
	this->updateGeometry();
}
void CDialogResultatEtalon::setLine4(const QString& sLblTittle, const QString& sValue)
{
	m_lblValue4->setVisible(true);
    m_btValue4->setVisible(true);
	m_lblValue4->setText(sLblTittle);
	m_btValue4->setText(sValue);
	this->updateGeometry();
}
	
QString CDialogResultatEtalon::getReturnValue()
{
	return m_btValue->text();
}
QString CDialogResultatEtalon::getReturnValue2()
{
	return m_btValue2->text();
}
QString CDialogResultatEtalon::getReturnValue3()
{
	return m_btValue3->text();
}
QString CDialogResultatEtalon::getReturnValue4()
{
	return m_btValue4->text();
}

void CDialogResultatEtalon::init()
{

}

CDialogResultatEtalon* CDialogResultatEtalon::getInstance()
{
	if(!singleton)
		singleton = new CDialogResultatEtalon();
	disconnect(singleton, 0, 0, 0); //Déconnect tout les objet qui se sont connecté à ses signal
	singleton->m_lblMessageErreur->setVisible(false);
	singleton->m_btApply->setEnabled(true);
	return singleton;
}
//SLOT
void CDialogResultatEtalon::btValuePressed()
{
	m_pPaveNum = CDialogPaveNum::getInstance();
	connect(m_pPaveNum, SIGNAL(accepted()), this, SLOT(valueChanged()));
	//connect(m_pPaveNum, SIGNAL(rejected()), this, SLOT(valueUnChanged()));
	m_pPaveNum->setValueName(m_lblValue->text());
	m_pPaveNum->setValue(m_btValue->text());
	m_pPaveNum->exec();
}
//SLOT
void CDialogResultatEtalon::btValue2Pressed()
{
	m_pPaveNum = CDialogPaveNum::getInstance();
	connect(m_pPaveNum, SIGNAL(accepted()), this, SLOT(value2Changed()));
	//connect(m_pPaveNum, SIGNAL(rejected()), this, SLOT(valueUnChanged()));
	m_pPaveNum->setValueName(m_lblValue2->text());
	m_pPaveNum->setValue(m_btValue2->text());
	m_pPaveNum->exec();
}
//SLOT
void CDialogResultatEtalon::btValue3Pressed()
{
	m_pPaveNum = CDialogPaveNum::getInstance();
	connect(m_pPaveNum, SIGNAL(accepted()), this, SLOT(value3Changed()));
	//connect(m_pPaveNum, SIGNAL(rejected()), this, SLOT(valueUnChanged()));
	m_pPaveNum->setValueName(m_lblValue3->text());
	m_pPaveNum->setValue(m_btValue3->text());
	m_pPaveNum->exec();
}
//SLOT
void CDialogResultatEtalon::valueChanged()
{
	m_btValue->setText(m_pPaveNum->getValue());
	this->updateGeometry();
}
//SLOT
void CDialogResultatEtalon::value2Changed()
{
	m_btValue2->setText(m_pPaveNum->getValue());
	this->updateGeometry();
}
//SLOT
void CDialogResultatEtalon::value3Changed()
{
	m_btValue3->setText(m_pPaveNum->getValue());
	this->updateGeometry();
}
void CDialogResultatEtalon::setConnexion()
{
	connect(m_btBack, SIGNAL(clicked()), this, SLOT(reject()));
	connect(m_btApply, SIGNAL(clicked()), this, SLOT(accept()));
	/*connect(m_btValue, SIGNAL(clicked()), this, SLOT(btValuePressed()));
	connect(m_btValue2, SIGNAL(clicked()), this, SLOT(btValue2Pressed()));
	connect(m_btValue3, SIGNAL(clicked()), this, SLOT(btValue3Pressed()));*/
}