#include "CDialogRestauration.h"
#include "CDialogMessage.h"
#include "CUserSession.h"
#include "Network.h"
#include "header_qt.h"

#define SZ_FILE_CONFIG_BACKUP	_T(".\\config_backup.ini")
#define SZ_FILE_CONFIG			_T("config.ini")

CDialogRestauration* CDialogRestauration::singleton = 0;
CDialogRestauration::CDialogRestauration()
{
	m_btApply = new QPushButton();
	m_btApply->setObjectName("btApply");
	m_btBack = new QPushButton();
	m_btBack->setObjectName("btCancel");
	m_btSave = new QPushButton();
	m_btSave->setObjectName("btSave");

	QTabWidget* tabWidget = new QTabWidget();

	QWidget* widgetDialog = new QWidget();
	tabWidget->addTab(widgetDialog, tr("RESTAURATION"));
	
	QVBoxLayout* layoutMenu = new QVBoxLayout();
	layoutMenu->addStretch();
	layoutMenu->addWidget(m_btSave);
	layoutMenu->addWidget(m_btApply);
	layoutMenu->addWidget(m_btBack);

	//assemblage du menu et du layoutGauche
	QHBoxLayout* layoutMain = new QHBoxLayout();
	layoutMain->addWidget(new QLabel(tr("Voulez vous restaurer la \nconfiguration d'usine ? \nToutes les valeurs sauvegardées \nseront écrasées.")));
	layoutMain->addLayout(layoutMenu);
	widgetDialog->setLayout(layoutMain);
	
	
	QHBoxLayout* layout = new QHBoxLayout();
	layout->addWidget(tabWidget);

	setLayout(layout);

	this->setObjectName("dialogModal");
	this->setWindowFlags(Qt::FramelessWindowHint);

	setConnexion();
}
//SLOT
void CDialogRestauration::saveConfig()
{
	//CopyFile(szSrc,szDst,FALSE)
	TCHAR szText[500];
	TCHAR szText2[500];
	qDebug() << "CopyFile(SZ_FILE_CONFIG, SZ_FILE_CONFIG_BACKUP,FALSE);" ;
	if(bCopyFile(szGetFullPathName(SZ_FILE_CONFIG,szText),szGetFullPathName(SZ_FILE_CONFIG_BACKUP,szText2), FALSE))
        CDialogMessage::getInstance()->setLblMsg(tr("Sauvegarde réussi."), false);    	
	else
        CDialogMessage::getInstance()->setLblMsg(tr("Sauvegarde échoué."), false);    
		
    
    CDialogMessage::getInstance()->exec();
	this->accept();
}
//SLOT
void CDialogRestauration::restaurerConfig()
{
	TCHAR szText[500];
	TCHAR szText2[500];
	qDebug() << "CopyFile(SZ_FILE_CONFIG_BACKUP, SZ_FILE_CONFIG,FALSE);" ;

	if(bCopyFile(szGetFullPathName(SZ_FILE_CONFIG_BACKUP,szText),szGetFullPathName(SZ_FILE_CONFIG,szText2),FALSE))
        CDialogMessage::getInstance()->setLblMsg(tr("Restauration réussi. \nVeuillez redémarrer électriquement\nl'appareil"), false);    
    else
        CDialogMessage::getInstance()->setLblMsg(tr("Restauration échoué. \nVeuillez contacter un\ntechnicien SERES"), false);
    
    
    CDialogMessage::getInstance()->exec();
    
	this->accept();
	
}

void CDialogRestauration::setConnexion()
{
	connect(m_btSave, SIGNAL(clicked()), this, SLOT(saveConfig()));
	connect(m_btApply, SIGNAL(clicked()), this, SLOT(restaurerConfig()));
	connect(m_btBack, SIGNAL(clicked()), this, SLOT(reject()));
}

CDialogRestauration* CDialogRestauration::getInstance()
{
	if(!singleton)
			singleton = new CDialogRestauration();

	if(CUserSession::getInstance()->amIAdmin())
		singleton->m_btSave->setVisible(true);
	else
		singleton->m_btSave->setVisible(false);

	return singleton;
}