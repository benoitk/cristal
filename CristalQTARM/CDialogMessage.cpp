#include "CDialogMessage.h"
#include "header_qt.h"


CDialogMessage* CDialogMessage::singleton = 0;
CDialogMessage::CDialogMessage()
{
	m_btBack = new QPushButton();
	m_btBack->setObjectName("btCancel");
	m_btApply = new QPushButton();
	m_btApply->setObjectName("btApply");
	
	QTabWidget* tabWidget = new QTabWidget();

	QWidget* widgetDialog = new QWidget();
	tabWidget->addTab(widgetDialog, tr("ATTENTION !"));
	
	QVBoxLayout* layoutMenu = new QVBoxLayout();
	layoutMenu->addStretch();
	layoutMenu->addWidget(m_btApply);
	layoutMenu->addWidget(m_btBack);

	//assemblage du menu et du layoutGauche
	QHBoxLayout* layoutMain = new QHBoxLayout();
	m_lblMsg = new QLabel();
	layoutMain->addWidget(m_lblMsg);
	layoutMain->addLayout(layoutMenu);
	widgetDialog->setLayout(layoutMain);
	
	
	QHBoxLayout* layout = new QHBoxLayout();
    layoutMain->setContentsMargins ( 0, 0, 0, 0 );
	layout->addWidget(tabWidget);

	setLayout(layout);

	this->setObjectName("dialogModal");
	this->setWindowFlags(Qt::FramelessWindowHint);

	setConnexion();
}

void CDialogMessage::setConnexion()
{
	connect(m_btBack, SIGNAL(clicked()), this, SLOT(reject()));
	connect(m_btApply, SIGNAL(clicked()), this, SLOT(accept()));
}

void CDialogMessage::setLblMsg(const QString& arg_sMsg,const bool& arg_BtApplyVisible)
{
	m_lblMsg->setText(arg_sMsg);
	m_btApply->setVisible(arg_BtApplyVisible);
}

CDialogMessage* CDialogMessage::getInstance()
{
	if(!singleton)
			singleton = new CDialogMessage();

	return singleton;
}

void CDialogMessage::buttonVisible(bool arg_visible)
{
    m_btBack->setVisible(arg_visible);
    m_btApply->setVisible(arg_visible);
}
