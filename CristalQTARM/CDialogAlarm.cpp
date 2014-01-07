#include "CDialogAlarm.h"
#include "CSupervision.h"
#include "CUserSession.h"
#include "CAlarmSortedView.h"

#include "header_qt.h"

CDialogAlarm::CDialogAlarm(CSupervision* argpSupervision)
{
	m_pSupervision = argpSupervision;
	m_btApply = new QPushButton();
	m_btApply->setObjectName("btApply");
	m_btBack = new QPushButton();
	m_btBack->setObjectName("btBack");
    m_btNext = new QPushButton();
	m_btNext->setObjectName("btNextBig");
    m_btPrev = new QPushButton();
	m_btPrev->setObjectName("btPrevBig");

	QTabWidget* tabWidget = new QTabWidget();

	QWidget* widgetDialog = new QWidget();
	tabWidget->addTab(widgetDialog, tr("ALARME"));
	
	QVBoxLayout* layoutMenu = new QVBoxLayout();
	layoutMenu->addStretch();
	layoutMenu->addWidget(m_btPrev);
	layoutMenu->addWidget(m_btNext);
	layoutMenu->addWidget(m_btApply);
	layoutMenu->addWidget(m_btBack);

    m_listModel = new QStringListModel();
	m_listView = new CAlarmSortedView(this);
    m_listView->setModel(m_listModel);

	//assemblage du menu et du layoutGauche
	QHBoxLayout* layoutMain = new QHBoxLayout();
	layoutMain->addWidget(m_listView);
	layoutMain->addLayout(layoutMenu);
	widgetDialog->setLayout(layoutMain);
	

	QHBoxLayout* layout = new QHBoxLayout();
    layout->setContentsMargins ( 0, 0, 0, 0 );
	layout->addWidget(tabWidget);

	setLayout(layout);

	setConnexion();
}


//Retour : VRAI alarme présente
//		   FAUX pas d'alarme
bool CDialogAlarm::updateAlarms()
{
	QString sDate;
	QString sHeure;
	QString sMsg;
	QString sTmp;
    
    QStringList listItem;
	int iRow = -1;
	qDebug() << "### CDialogAlarm::updateAlarms " ;

	for(int i=0; i<m_pSupervision->getAnalyseur()->m_ListMessageError.iGetCount();i++)
	{
		/*m_pSupervision->getAnalyseur()->m_ListMessageError.pGetAt(i)->lGetLabelLength(); 
		qDebug() << QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->m_ListMessageError.pGetAt(i)->szGetLabel()
										, m_pSupervision->getAnalyseur()->m_ListMessageError.pGetAt(i)->lGetLabelLength());
		*///QString::fromUtf16(( const ushort *)CElemCycle::m_CurrentStep.szGetLabel()
		//			     , CElemCycle::m_CurrentStep.lGetLabelLength())
		if(QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->m_ListMessageError.pGetAt(i)->szGetLabel()
											 , m_pSupervision->getAnalyseur()->m_ListMessageError.pGetAt(i)->lGetLabelLength()) 
			!= "CElemBase")
		{		
			qDebug() << QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->m_ListMessageError.pGetAt(i)->szGetLabel()
														  , m_pSupervision->getAnalyseur()->m_ListMessageError.pGetAt(i)->lGetLabelLength());
		
			sTmp = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->m_ListMessageError.pGetAt(i)->szGetLabel());
			sDate = sTmp.split(";").at(2);
			sHeure = sTmp.split(";").at(3);
			sMsg = sTmp.split(";").at(4);
            sTmp = sMsg.split("|").at(0);
            //qDebug() << sMsg.split('@');
            if(sMsg.split('@').at(0) != sMsg)
                 sMsg = QString(tr("Voie ")) + sMsg.split('@').at(1) + QString(" ") + sTmp;
            else
                sMsg = sTmp;
			
			qDebug() << "sDate:" <<sDate << " sHeure:" << sHeure<< " sMsg:" << sMsg;
			//new QListWidgetItem(sDate+" "+sHeure+" "+sMsg, m_listView);
            listItem.append(QString(sDate+" "+sHeure+" "+sMsg));
    
			
			
		}
	}
	/*if(listItem.count() > 0)
		return true;
	else
		return false;*/
    m_listModel->setStringList(listItem);
    m_listView->slotChangePage();
    return true;
}

//SLOT 
void CDialogAlarm::acquiter()
{
   // qDebug() << "ERASE ALL" ;
    if(CUserSession::getInstance()->loginUser())
	{
        for(int i=0; i<m_pSupervision->getAnalyseur()->m_ListMessageError.iGetCount();i++)
            m_pSupervision->getAnalyseur()->m_ListMessageError.bAddAndRollText(_T("CElemBase"));

        QStringList listEmpty;
        m_listModel->setStringList(listEmpty);

        m_pSupervision->getAnalyseur()->m_bStatusFailure.bSetVal(0);
        for(int i=0; i<m_pSupervision->getAnalyseur()->iGetNbrStream(); ++i)
        {
            m_pSupervision->getAnalyseur()->pGetAt(i)->m_StatusFailure.bSetVal(0);
            for(int j=0; j<m_pSupervision->getAnalyseur()->pGetAt(i)->iGetNbrMesure(); ++j)
                m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(j)->m_StatusFailure.bSetVal(0);
                
        }
        m_listView->slotChangePage();
    }
    
}

void CDialogAlarm::setConnexion()
{
	connect(m_btBack, SIGNAL(clicked()), this, SLOT(close()));
	connect(m_btApply, SIGNAL(clicked()), this, SLOT(acquiter()));
	//connect(m_btApply, SIGNAL(clicked()), m_listView, SLOT(clear()));
	connect(m_btNext, SIGNAL(clicked()), m_listView, SLOT(slotNextPage()));
	connect(m_btPrev, SIGNAL(clicked()), m_listView, SLOT(slotPrevPage()));
	
}

void CDialogAlarm::setEnabledBtNext(const bool& arg_state)
{
    m_btNext->setEnabled(arg_state);
}

void CDialogAlarm::setEnabledBtPrev(const bool& arg_state)
{
    m_btPrev->setEnabled(arg_state);

}



