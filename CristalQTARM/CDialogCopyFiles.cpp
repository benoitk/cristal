#include "CDialogCopyFiles.h"
#include "Network.h"
#include "header_qt.h"

#define USB_DIR "\\Hard Disk"

CDialogCopyFiles* CDialogCopyFiles::singleton = 0;
CDialogCopyFiles::CDialogCopyFiles()
{
	m_progressBar.setVisible(false);
	m_progressBar.setMaximum(100);
	m_progressBar.setMinimum(0);
	m_logErrorPrgFileDir = new QDir(QString::fromUtf16(( const ushort *)_szLogErrorPrgFileDir));
	m_logFileDir = new QDir(QString::fromUtf16(( const ushort *)_szLogFileDir));
	m_logUserFileDir = new QDir(QString::fromUtf16(( const ushort *)_szUserLogFileDir));

	m_btApply = new QPushButton();
	m_btApply->setObjectName("btApply");
	m_btBack = new QPushButton();
	m_btBack->setObjectName("btBack");
	
	QTabWidget* tabWidget = new QTabWidget();

	QWidget* widgetDialog = new QWidget();
	tabWidget->addTab(widgetDialog, tr("TRANSFERT DES LOGS"));
	
	QVBoxLayout* layoutMenu = new QVBoxLayout();
	layoutMenu->addStretch();
	layoutMenu->addWidget(m_btApply);
	layoutMenu->addWidget(m_btBack);

	//assemblage du menu et du layoutGauche
	m_lblInfo = new QLabel(tr("Transferer les fichiers \nlog sur la clé USB ?"));
	QVBoxLayout* layoutCentral = new QVBoxLayout();
	layoutCentral->addWidget(m_lblInfo);
	layoutCentral->addWidget(&m_progressBar);
	QHBoxLayout* layoutMain = new QHBoxLayout();
	layoutMain->addLayout(layoutCentral);
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
void CDialogCopyFiles::execCopy()
{
	int nbFiles=0;
	int nCoef=1;
	QDir dirUSB(USB_DIR);
	
	QString sFilePath;
	if(dirUSB.exists())
	{
		dirUSB.mkpath(dirUSB.absolutePath()+"/CRISTAL_LOG/CristalErrorPrgLog");
		dirUSB.mkpath(dirUSB.absolutePath()+"/CRISTAL_LOG/UserLogFileDir");
		dirUSB.mkpath(dirUSB.absolutePath()+"/CRISTAL_LOG/CristalLog");
		m_btApply->setEnabled(false);
		m_btBack->setEnabled(false);
		m_progressBar.setVisible(true);
		m_progressBar.setValue(0);
		m_lblInfo->setText(tr("Copie en cours :"));
		nbFiles += m_logErrorPrgFileDir->count();
		nbFiles += m_logUserFileDir->count();
		nbFiles += m_logFileDir->count();
		nCoef = 100/nbFiles;
		nbFiles = 0;
		foreach(sFilePath, m_logErrorPrgFileDir->entryList())
		{
			++nbFiles;
			QFile fileSource(m_logErrorPrgFileDir->absolutePath()+ "/" + sFilePath);
			QFile fileDest(dirUSB.absolutePath()+ "/CRISTAL_LOG/CristalErrorPrgLog/" + sFilePath);
			if(fileDest.exists()) 
			{
				fileDest.remove();
			}
			fileSource.copy(fileDest.fileName());
			
			m_progressBar.setValue(nbFiles*nCoef);
		}
		foreach(sFilePath, m_logUserFileDir->entryList())
		{
			++nbFiles;
			QFile fileSource(m_logUserFileDir->absolutePath()+ "/" + sFilePath);
			QFile fileDest(dirUSB.absolutePath()+ "/CRISTAL_LOG/UserLogFileDir/" + sFilePath);
			if(fileDest.exists()) 
			{
				fileDest.remove();
			}
			fileSource.copy(fileDest.fileName());
			
			m_progressBar.setValue(nbFiles*nCoef);
		}
		foreach(sFilePath, m_logFileDir->entryList())
		{
			++nbFiles;
			QFile fileSource(m_logFileDir->absolutePath()+ "/" + sFilePath);
			QFile fileDest(dirUSB.absolutePath()+ "/CRISTAL_LOG/CristalLog/" + sFilePath);
			if(fileDest.exists()) 
			{
				fileDest.remove();
			}
			fileSource.copy(fileDest.fileName());
			
			m_progressBar.setValue(nbFiles*nCoef);
		}
		m_progressBar.setValue(100);
		m_lblInfo->setText(tr("Copie terminée !"));
		
		
	}
	else
	{
		m_lblInfo->setText(tr("Clé USB non trouvée. \nBrancher une clé USB \net recommencer"));
	}
	
	
	m_btBack->setEnabled(true);
	

}
//SLOT
void CDialogCopyFiles::resetDialog()
{
	m_btApply->setEnabled(true);
	m_lblInfo->setText(tr("Transferer les fichiers \nlog sur la clé USB ?"));
	m_progressBar.setVisible(false);

}
void CDialogCopyFiles::setConnexion()
{
	connect(m_btBack, SIGNAL(clicked()), this, SLOT(resetDialog()));
	connect(m_btBack, SIGNAL(clicked()), this, SLOT(reject()));
	connect(m_btApply, SIGNAL(clicked()), this, SLOT(execCopy()));
}

CDialogCopyFiles* CDialogCopyFiles::getInstance()
{
	if(!singleton)
			singleton = new CDialogCopyFiles();

	return singleton;
}