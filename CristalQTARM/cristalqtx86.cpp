#include "cristalqtx86.h"
#include "stdafx.h"
#include "header.h"
#include "header_qt.h"


CristalQTx86::CristalQTx86(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);
	//QApplication::setStyle(new QPlastiqueStyle()); Utiliser plutot les stylessheets
	actionStart = new QAction(this);
    actionStart->setObjectName(QString::fromUtf8("actionStart"));
	ui.menu_File->addAction(actionStart);
	actionStart->setText(QApplication::translate("CristalQTx86Class", "S&tart", 0, QApplication::UnicodeUTF8));
	//QTimer::singleShot ( 1000, this, SLOT(ui_start() ));
	m_i = 0;
		//QObject::connect(actionStart, SIGNAL(triggered()), this, SLOT(ui_start())))

	 //Boutons  de droite pas encore à droite
	 /*QPushButton *btPlay = new QPushButton("Play");
     QPushButton *btPause = new QPushButton("Pause");
     QPushButton *btStop = new QPushButton("Stop");
     QPushButton *btNext = new QPushButton("Next");
     QPushButton *btTools = new QPushButton("Tools");

     QVBoxLayout *VBoxLayout = new QVBoxLayout;
     VBoxLayout->addWidget(btPlay);
     VBoxLayout->addWidget(btPause);
     VBoxLayout->addWidget(btStop);
     VBoxLayout->addWidget(btNext);
     VBoxLayout->addWidget(btTools);

     ui.centralWidget->setLayout(VBoxLayout);*/
	 
	 //layout central 
	 m_label = new QLabel(this);
	 m_label2 = new QLabel(this);
	 /*QFormLayout *formLayout = new QFormLayout;
	formLayout->addRow(tr("&Num pas:"), m_label);
	formLayout->addRow(tr("&Détail pas:"), m_label2);
	ui.centralWidget->setLayout(formLayout);*/

	//QLabel *lblMesure = new QLabel(this);
	 QTimer *m_timer = new QTimer(this);
     connect(m_timer, SIGNAL(timeout()), this, SLOT(ui_start()));
     m_timer->start(1000);
}

void CristalQTx86::ui_start()
{
	/*QString str = "toto";
	m_label = new QLabel(this);
	m_label->setFrameStyle(QFrame::Panel | QFrame::Sunken);
	m_label->setText(str);
	//label->setAlignment(Qt::AlignBottom | Qt::AlignRight);
	m_label->move(100,50);
	m_label->show();*/

	
	//str = QString::fromUtf16((const ushort *)CElemCycle::m_CurrentStep.m_Step.szGetLabel(), sizeof(CElemCycle::m_CurrentStep.m_Step.szGetLabel())); 
	m_label->setText(QString::fromUtf16(( const ushort *)CElemCycle::m_CurrentStep.szGetLabel()
								       , CElemCycle::m_CurrentStep.lGetLabelLength()));
	m_label->update();

	m_label2->setText(QString::number(CElemCycle::m_CurrentStep.m_Step.nGetVal()));
	m_label2->update();
	
}

void CristalQTx86::ui_stop()
{
	m_bSortie = true;
}

CristalQTx86::~CristalQTx86()
{

}

void CristalQTx86::setAnalyseur(CListStream* argAnalyseur)
{
	this->m_oAnalyseur = argAnalyseur;
	
	m_oVoie = this->m_oAnalyseur->pGetAt(0);
	m_oMesure = m_oVoie->pGetAt(0);
		//oMesure->szGetLabel();
		//oMesure->m_Val.fGetVal();
	/*if (sizeof(wchar_t) == sizeof(QChar)) {
        return fromUtf16((const ushort *)string, size);
    } else {
        return fromUcs4((uint *)string, size);
    }*/
	QString str = QString::fromUtf16((const ushort *)m_oMesure->m_Val.szGetLabel(), sizeof(m_oMesure->m_Val.szGetLabel())*sizeof(TCHAR)+2); 
	
	m_label->setFrameStyle(QFrame::Panel | QFrame::Sunken);
	m_label->setText(str);
//	label->setAlignment(Qt::AlignBottom | Qt::AlignRight);
	m_label->move(100,100);
	m_label->show();

	//m_label2 = new QLabel(this);
	m_label2->setFrameStyle(QFrame::Panel | QFrame::Sunken);
	m_label2->setText(str);
//	label->setAlignment(Qt::AlignBottom | Qt::AlignRight);
	m_label2->move(80,80);
	m_label2->show();
}
