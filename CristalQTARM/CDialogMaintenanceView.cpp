#include "CDialogMaintenanceView.h"

#include "header_qt.h"

CDialogMaintenanceView::CDialogMaintenanceView(void)
{
	m_iIndexLine = -1;

	//menu de droite //toujours 4 items dans les menus en incluant les spacers
	m_btBack = new QPushButton();
	m_btBack->setObjectName("btBack");

	QVBoxLayout* layoutMenu = new QVBoxLayout();
	layoutMenu->addStretch();
	layoutMenu->addWidget(m_btBack);

	/*setConnexion();*/
}

void CDialogMaintenanceView::setTittle(const QString& sTittle)
{
	m_sDialogTittle = sTittle;
}
void CDialogMaintenanceView::addLine(const QString& sLblTittle, const QString& sValue)
{
	m_vTittle.append(sLblTittle);
	m_vValue.append(sValue);
	m_iIndexLine++;
}
	
QString CDialogMaintenanceView::getNextValue()
{
	if(m_iIndexLine > -1)
	{
		return m_vValue.at(m_iIndexLine--);
	}
	else
		return "";
}

void CDialogMaintenanceView::init()
{
	QTabWidget* tabWidget = new QTabWidget();

	QWidget* widgetRelais = new QWidget();

	QFormLayout *formLayout = new QFormLayout();
	QString pString;
	int i=0;
	foreach(pString, m_vTittle)
	{
		formLayout->addRow(pString, new QPushButton(m_vValue.at(i)));
	}
	

	//QHBoxLayout* layoutBtRelais1 = new QHBoxLayout();
	//layoutBtRelais1->addWidget(m_btOnRelais1,50, Qt::AlignRight);
	//layoutBtRelais1->addWidget(m_btOffRelais1,50, Qt::AlignLeft);
	//QHBoxLayout* layoutBtRelais2 = new QHBoxLayout();
	//layoutBtRelais2->addWidget(m_btOnRelais2,50, Qt::AlignRight);
	//layoutBtRelais2->addWidget(m_btOffRelais2,50, Qt::AlignLeft);

	////centre de la fenêtre
	//QFormLayout* layoutCentral = new QFormLayout();
	//layoutCentral->addRow("Relais 1", layoutBtRelais1);
	//layoutCentral->addRow("Relais 2", layoutBtRelais2);

	////Bando de navigation du bas
	//m_btNextPage = new QPushButton();
	//m_btNextPage->setObjectName("btNextPage");
	//m_btPreviousPage = new QPushButton();
	//m_btPreviousPage->setObjectName("btPreviousPage");
	//QHBoxLayout* layoutNav= new QHBoxLayout();
	//layoutNav->addWidget(m_btNextPage,5, Qt::AlignRight);
	//layoutNav->addWidget(m_btPreviousPage,5, Qt::AlignLeft);

	////Assemblage centre et bando de nav
	//QVBoxLayout* layoutGauche= new QVBoxLayout();
	//layoutGauche->addLayout(layoutCentral);
	//layoutGauche->addLayout(layoutNav);

	//

	////assemblage du menu et du layoutGauche
	//QHBoxLayout* layoutMain = new QHBoxLayout();
	//layoutMain->addLayout(layoutGauche);
	//layoutMain->addLayout(m_layoutMenu);
	//widgetRelais->setLayout(layoutMain);
	//
	//tabWidget->addTab(widgetRelais, m_sDialogTittle);

	////*** onglet sortie 4-20

	////*** onglet Entree ana/tor


	//setCentralWidget(tabWidget);
	//setConnexion();
}
