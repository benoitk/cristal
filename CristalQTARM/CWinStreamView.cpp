#include "CWinStreamView.h"
#include "CWinStreamControler.h"
#include "CWinStreamModel.h"
#include "CMesureModel.h"
#include "CStreamModel.h"
#include "header_qt.h"

#include <QMessageBox>

CWinStreamView::CWinStreamView(CWinStreamControler* argoControler, QWidget *parent,Qt::WindowFlags flags)
	: QWidget(parent, flags)
{
	m_pControler = argoControler;
}

void CWinStreamView::setModel(CWinStreamModel* argoModel)
{
    m_pModel = argoModel; 
    init();
}

void CWinStreamView::init()
{
    qDebug() << "### CWinStreamView::init()";
	setUpdatesEnabled(false);
	
	m_tabWidget = new QTabWidget();

	//*** onglet Voie
	QWidget* widgetVoie = new QWidget();

	//Bouton ON/OFF
	m_btOnVoieActive = new QPushButton();
	m_btOnVoieActive->setObjectName("btOn");
	m_btOffVoieActive = new QPushButton();
	m_btOffVoieActive->setObjectName("btOff");
	m_btOnCycleEnCours = new QPushButton();
	m_btOnCycleEnCours->setObjectName("btEntree");
    m_btStatus = new QPushButton();
	m_btStatus->setObjectName("btEntree");
    m_btStatusSeuil = new QPushButton();
	m_btStatusSeuil->setObjectName("btEntree");
    m_btStatusWaterFailure = new QPushButton();
	m_btStatusWaterFailure->setObjectName("btEntree");
	QHBoxLayout* layoutBtVoieActive = new QHBoxLayout();
	layoutBtVoieActive->addWidget(m_btOnVoieActive,50, Qt::AlignCenter);
	layoutBtVoieActive->addWidget(m_btOffVoieActive,50, Qt::AlignLeft);

	//centre de la fenêtre
	m_lblCycleEnCours = new QLabel(tr("en cours"));
	m_lblCycleEnCours->setObjectName("lblValeur");
	m_lblStatutVoie = new QLabel(tr("aucun"));
	m_lblStatutVoie->setObjectName("lblValeur");
	m_lblStatutDefautEau = new QLabel(tr("aucun"));
	m_lblStatutDefautEau->setObjectName("lblValeur");
	m_lblCptCycle = new QLabel("0");
	m_lblCptCycle->setObjectName("lblValeur");

    m_lblDefauttVoie = new QLabel();
	m_lblDefauttVoie->setObjectName("lblStatusWaterFailure");
    m_lblDefautEau = new QLabel();
	m_lblDefautEau->setObjectName("lblStatusWaterFailure");
    m_lblDefautSeuil = new QLabel();
	m_lblDefautSeuil->setObjectName("lblStatusWaterFailure");
	QGridLayout* layoutCentral = new QGridLayout();
	//layoutCentral->setFormAlignment(Qt::AlignHCenter);
	//layoutCentral->addRow(tr("Voie active"), layoutBtVoieActive);
	//layoutCentral->addRow(tr("Cycle en cours"), m_lblCycleEnCours);
	//layoutCentral->addRow(tr("Statut voie"), m_lblStatutVoie);
	//layoutCentral->addRow(tr("Statut defaut d'eau"), m_lblStatutDefautEau);
    //layoutCentral->addRow(tr("Compteur de cycle"), m_lblCptCycle);
    
    int rowVoie = 0;
    m_lblVoieActive = new QLabel(tr("Voie n°"));
    layoutCentral->addWidget(m_lblVoieActive, rowVoie, 0);
    layoutCentral->addLayout(layoutBtVoieActive, rowVoie++, 1);
    //layoutCentral->addWidget(m_lblDefauttVoie, rowVoie++, 2);
    layoutCentral->addWidget(new QLabel(tr("Cycle en cours")), rowVoie, 0);
    layoutCentral->addWidget(m_btOnCycleEnCours, rowVoie++, 1);
    //layoutCentral->addWidget(m_lblDefauttVoie, rowVoie++, 2);
    layoutCentral->addWidget(new QLabel(tr("Statut voie")), rowVoie, 0);
    layoutCentral->addWidget(m_btStatus, rowVoie, 1);
    layoutCentral->addWidget(m_lblDefauttVoie, rowVoie++, 2);
    layoutCentral->addWidget(new QLabel(tr("Statut defaut d'eau")), rowVoie, 0);
    layoutCentral->addWidget(m_btStatusWaterFailure, rowVoie, 1);
    layoutCentral->addWidget(m_lblDefautEau, rowVoie++, 2);
    layoutCentral->addWidget(new QLabel(tr("Statut seuil 1 et 2")), rowVoie, 0);
    layoutCentral->addWidget(m_btStatusSeuil, rowVoie, 1);
    layoutCentral->addWidget(m_lblDefautSeuil, rowVoie++, 2);
	
	//Bando de navigation du bas
	/*m_btNextPage = new QPushButton();
	m_btNextPage->setObjectName("btNextPage");
	m_btPreviousPage = new QPushButton();
	m_btPreviousPage->setObjectName("btPreviousPage");
	QHBoxLayout* layoutNav= new QHBoxLayout();
	layoutNav->addWidget(m_btNextPage,5, Qt::AlignRight);
	layoutNav->addWidget(m_btPreviousPage,5, Qt::AlignLeft);*/

	//Assemblage centre et bando de nav
	QVBoxLayout* layoutGauche= new QVBoxLayout();
	layoutGauche->addLayout(layoutCentral);
    layoutGauche->addStretch();
	//layoutGauche->addLayout(layoutNav);

	//menu de gauche //toujours 4 items dans les menus en incluant les spacers
	QPushButton* btBack = new QPushButton();
	m_vectorBtBack.append(btBack);
	btBack->setObjectName("btBack");
	/*QPushButton* btApply = new QPushButton();
	m_vectorBtApply.append(btApply);
	btApply->setObjectName("btApply");*/
	
	QVBoxLayout* layoutMenu = new QVBoxLayout();
	layoutMenu->addStretch();
	//layoutMenu->addWidget(btApply);
	layoutMenu->addWidget(btBack);

	//assemblage du menu et du layoutGauche
	QHBoxLayout* layoutMain = new QHBoxLayout();
	layoutMain->addLayout(layoutGauche);
    layoutMain->addStretch();
	layoutMain->addLayout(layoutMenu);
	widgetVoie->setLayout(layoutMain);
	//:Nom de l'onglet à garder en maj pour toutes les trad
#ifdef MULTI_STREAM
	m_tabWidget->addTab(widgetVoie, tr("VOIE"));
#endif
	//*** onglets mesure
	CStreamModel* pStream;
	CMesureModel* pMesure;
	pStream = m_pModel->getVectorStream().first();
	//foreach(pStream, m_pModel->getVectorStream())
	//{
	
	int numMesure = 0;
	foreach(pMesure, pStream->getVectorMesure())
	{
        int nIndex = 0;
        m_listLayoutMesure.append(new QGridLayout());
		QWidget* widgetMesure = new QWidget();
		//qDebug() << "QWidget* widgetMesure = new QWidget();";
		
		
		
		//for(i = m_pModel->getValuesIteratorBegin(); i != m_pModel->getValuesIteratorEnd() && nIndex < NOMBRE_VALUE_PAR_PAGE; ++i)
		//Récupération du nombre d'élément sur la voie 0, mesure 0, identique sur toutes les voies/mesures
        for(int i = 0; i < m_pModel->getNombreValues(0,0) && nIndex < NOMBRE_VALUE_PAR_PAGE; ++i)
		{
            m_listBtEdit.append(new CPushButton(nIndex, m_pModel->getValue(0, 0, i)));
			m_listBtEdit.last()->setObjectName("btLineEdit");
			QLabel* lblTmp = new QLabel( m_pModel->getValueLbl(0, 0, i));
			m_listLblEdit.append(lblTmp);
			lblTmp->setObjectName("lblMeasure");
			m_listLayoutMesure.last()->addWidget(lblTmp, 0+nIndex,0);
			m_listLayoutMesure.last()->addWidget(m_listBtEdit.last(), 0+nIndex, 1);
			lblTmp = new QLabel(m_pModel->getValueUnit(0, 0, i));
			lblTmp->setObjectName("lblMeasure");
			m_listLayoutMesure.last()->addWidget(lblTmp, 0+nIndex,2);

			/*m_listBtEdit.append(new CPushButton(nIndex, (*i)->getValue()));
			m_listBtEdit.last()->setObjectName("btLineEdit");
			QLabel* lblTmp = new QLabel((*i)->getLabel());
			m_listLblEdit.append(lblTmp);
			lblTmp->setObjectName("lblMeasure");
			m_listLayoutMesure.at(arg_numMeasure)->addWidget(lblTmp, 0+nIndex,0);
			m_listLayoutMesure.at(arg_numMeasure)->addWidget(m_listBtEdit.last(), 0+nIndex, 1);
			lblTmp = new QLabel((*i)->getUnit());
			lblTmp->setObjectName("lblMeasure");
			m_listLayoutMesure.at(arg_numMeasure)->addWidget(lblTmp, 0+nIndex,2);*/
				
			++nIndex;
		}
		
		//Bando de navigation 
		m_listBtNextPage.append(new CPushButton(numMesure));
		m_listBtNextPage.last()->setObjectName("btNextBig");
		m_listBtPreviousPage.append(new CPushButton(numMesure));
		m_listBtPreviousPage.last()->setObjectName("btPrevBig");
		m_listBtPreviousPage.last()->setEnabled(false);
		m_lblPagination = new QLabel("1/1");
		//m_lblPagination->setObjectName("btPreviousPage");
		QHBoxLayout* layoutNav= new QHBoxLayout();
		/*layoutNav->addWidget(m_btPreviousPage,5, Qt::AlignRight);
		layoutNav->addWidget(m_lblPagination,5, Qt::AlignCenter);
		layoutNav->addWidget(m_btNextPage,5, Qt::AlignLeft);*/

		//Assemblage centre et bando de nav
		QVBoxLayout* layoutGauche= new QVBoxLayout();
		layoutGauche->addLayout(m_listLayoutMesure.last());
		//layoutGauche->addLayout(layoutNav);

		//menu de gauche //toujours 4 items dans les menus en incluant les spacers
		btBack = new QPushButton();
		m_vectorBtBack.append(btBack);
		btBack->setObjectName("btBack");
		/*btApply = new QPushButton();
		m_vectorBtApply.append(btApply);
		btApply->setObjectName("btApply");*/
		
		QVBoxLayout* layoutMenu = new QVBoxLayout();
		layoutMenu->addStretch();
		//layoutMenu->addWidget(btApply);
		layoutMenu->addWidget(m_listBtPreviousPage.last());
		layoutMenu->addWidget(m_listBtNextPage.last());
		layoutMenu->addWidget(btBack);

		//assemblage du menu et du layoutGauche
		QHBoxLayout* layoutMain = new QHBoxLayout();
		layoutMain->addLayout(layoutGauche);
        layoutMain->addStretch();
		layoutMain->addLayout(layoutMenu);
		widgetMesure->setLayout(layoutMain);
		//:Nom d'onglet à garder en maj pour toutes les trads
		m_tabWidget->addTab(widgetMesure, tr("MESURE ")+ QString::number(++numMesure));
	}
	//}


	//*** onglet Réglage 

    QHBoxLayout* layoutGlobal = new QHBoxLayout(); 
    layoutGlobal->setContentsMargins ( 0, 0, 0, 0 );
    layoutGlobal->addWidget(m_tabWidget);
	this->setLayout(layoutGlobal);
	
	setConnexion();
	setUpdatesEnabled(true);
    qDebug() << "### CWinStreamView::init()";

}
void CWinStreamView::setEditText(int arg_numStream, int arg_numMeasure, int arg_index, int arg_numPage, const QString& arg_sText)
{
	//m_listBtEdit.at(arg_index)->setText(arg_sText);
	int tmp = arg_index+(NOMBRE_VALUE_PAR_PAGE*arg_numPage);
	//(*(m_pModel->getValuesIteratorBegin()+tmp))->setValue(arg_sText);
	m_pModel->setValue(arg_numStream, arg_numMeasure, tmp, arg_sText);
	//m_pModel->setValue(tmp, arg_sText);
	
}
void CWinStreamView::setDownBtOnVoieActive(bool bIsDown)
{
//	m_btOnVoieActive->setDown(bIsDown);
	m_btOnVoieActive->setEnabled(!bIsDown);
};
void CWinStreamView::setDownBtOffVoieActive(bool bIsDown)
{
//	m_btOffVoieActive->setDown(bIsDown);
	m_btOffVoieActive->setEnabled(!bIsDown);
};
	
//SLOT
// argNumPage numéro de la page de 0 à n pages
void CWinStreamView::loadPage(int arg_numStream, int arg_numMeasure, int arg_NumPage)
{
#ifdef MULTI_STREAM
    m_tabWidget->setTabText(0, QString(tr("VOIE")) + QString(" ") + QString::number(arg_numStream+1));
    m_lblVoieActive->setText(tr("Voie n°") + QString::number(arg_numStream+1));

    m_btOnVoieActive->setEnabled(!m_pModel->getStreamIsActive(arg_numStream));
    m_btOffVoieActive->setEnabled(m_pModel->getStreamIsActive(arg_numStream));
    m_btOnCycleEnCours->setEnabled(m_pModel->getStreamStatusCycleRunning(arg_numStream));
    m_btStatus->setEnabled(m_pModel->getStreamStatus(arg_numStream));
    if(!m_pModel->getStreamStatus(arg_numStream))
        m_lblDefauttVoie->setText(tr("En défaut"));
    else
        m_lblDefauttVoie->setText("");

    m_btStatusWaterFailure->setEnabled(m_pModel->getStreamStatusWaterFailure(arg_numStream));
    if(!m_pModel->getStreamStatusWaterFailure(arg_numStream))
        m_lblDefautEau->setText(tr("En défaut d'eau"));
    else
        m_lblDefautEau->setText("")   ;
    m_btStatusSeuil->setEnabled( m_pModel->getStreamStatusSeuil1(arg_numStream)
                               &&m_pModel->getStreamStatusSeuil2(arg_numStream));
    if(!m_pModel->getStreamStatusSeuil1(arg_numStream) && !m_pModel->getStreamStatusSeuil2(arg_numStream))
        m_lblDefautSeuil->setText(tr("Seuil 1 et 2 dépassés"));
    else if(!m_pModel->getStreamStatusSeuil1(arg_numStream))
        m_lblDefautSeuil->setText(tr("Seuil 1 dépassé"));
    else if(!m_pModel->getStreamStatusSeuil2(arg_numStream))
        m_lblDefautSeuil->setText(tr("Seuil 2 dépassé"));
    else
        m_lblDefautSeuil->setText("");
#endif
	qDebug() << "#### btNextPagePressed count item :" << m_listLayoutMesure.at(arg_numMeasure)->count() << endl;
	int nIndex = 0;
    int offSet = NOMBRE_VALUE_PAR_PAGE*(arg_NumPage);
    for(int i = offSet; i != m_pModel->getNombreValues(arg_numStream, arg_numMeasure) && nIndex < NOMBRE_VALUE_PAR_PAGE; ++i)
	{
	    qDebug() << "#### arg_numStream :" << arg_numStream << "#### arg_numMeasure :" << arg_numMeasure <<"#### i :" << i ;

		((QLabel*) m_listLayoutMesure.at(arg_numMeasure)->itemAtPosition(nIndex, 0)->widget())->setText(m_pModel->getValueLbl(arg_numStream, arg_numMeasure, i));
		((QPushButton*) m_listLayoutMesure.at(arg_numMeasure)->itemAtPosition(nIndex, 1)->widget())->setText(m_pModel->getValue(arg_numStream, arg_numMeasure, i));
		((QPushButton*) m_listLayoutMesure.at(arg_numMeasure)->itemAtPosition(nIndex, 1)->widget())->setEnabled(true);
		((QLabel*) m_listLayoutMesure.at(arg_numMeasure)->itemAtPosition(nIndex, 2)->widget())->setText(m_pModel->getValueUnit(arg_numStream, arg_numMeasure, i));
		++nIndex;
	
	}
	while(nIndex < NOMBRE_VALUE_PAR_PAGE)
	{
		((QLabel*) m_listLayoutMesure.at(arg_numMeasure)->itemAtPosition(nIndex, 0)->widget())->setText("");
		((QPushButton*) m_listLayoutMesure.at(arg_numMeasure)->itemAtPosition(nIndex, 1)->widget())->setText("");
		((QPushButton*) m_listLayoutMesure.at(arg_numMeasure)->itemAtPosition(nIndex, 1)->widget())->setEnabled(false);
		((QLabel*) m_listLayoutMesure.at(arg_numMeasure)->itemAtPosition(nIndex, 2)->widget())->setText("");
		++nIndex;
	}
	this->update();

	/*QList<CValue*>::iterator i;
	
	
	
	for(i = m_pModel->getValuesIteratorBegin()+offSet; i != m_pModel->getValuesIteratorEnd() && nIndex < NOMBRE_VALUE_PAR_PAGE; ++i)
	{
		((QLabel*) m_listLayoutMesure.at(arg_numMeasure)->itemAtPosition(nIndex, 0)->widget())->setText((*i)->getLabel());
		((QPushButton*) m_listLayoutMesure.at(arg_numMeasure)->itemAtPosition(nIndex, 1)->widget())->setText((*i)->getValue());
		((QPushButton*) m_listLayoutMesure.at(arg_numMeasure)->itemAtPosition(nIndex, 1)->widget())->setEnabled(true);
		((QLabel*) m_listLayoutMesure.at(arg_numMeasure)->itemAtPosition(nIndex, 2)->widget())->setText((*i)->getUnit());
		++nIndex;
	
	}
	while(nIndex < NOMBRE_VALUE_PAR_PAGE)
	{
		((QLabel*) m_listLayoutMesure.at(arg_numMeasure)->itemAtPosition(nIndex, 0)->widget())->setText("");
		((QPushButton*) m_listLayoutMesure.at(arg_numMeasure)->itemAtPosition(nIndex, 1)->widget())->setText("");
		((QPushButton*) m_listLayoutMesure.at(arg_numMeasure)->itemAtPosition(nIndex, 1)->widget())->setEnabled(false);
		((QLabel*) m_listLayoutMesure.at(arg_numMeasure)->itemAtPosition(nIndex, 2)->widget())->setText("");
		++nIndex;
	}
    int nIndex = 0;
	int offSet = NOMBRE_VALUE_PAR_PAGE*(argnNumPage);*/
	
	
}
void CWinStreamView::setConnexion()
{
	QPushButton* btTemp;
	foreach(btTemp, m_vectorBtApply)
	{
		connect(btTemp, SIGNAL(clicked()), m_pControler,SLOT(btBackPressed()));	
	}
	foreach(btTemp, m_vectorBtBack)
	{
		connect(btTemp, SIGNAL(clicked()), m_pControler,SLOT(btBackPressed()));	
	}
		
	connect(m_btOnVoieActive, SIGNAL(clicked()), m_pControler,SLOT(btOnVoieActivePressed()));	
	connect(m_btOffVoieActive, SIGNAL(clicked()), m_pControler,SLOT(btOffVoieActivePressed()));	

    CPushButton* btTemp2;
    foreach(btTemp2, m_listBtNextPage)
    {
	    connect(btTemp2, SIGNAL(clicked(int)), m_pControler, SLOT(btNextPagePressed(int)));
    }
    foreach(btTemp2, m_listBtPreviousPage)
    {
        connect(btTemp2, SIGNAL(clicked(int)), m_pControler, SLOT(btPreviousPagePressed(int)));
    }
	
	foreach(btTemp, m_listBtEdit)
	{
		connect(btTemp, SIGNAL(clicked(int)), m_pControler, SLOT(btEditPressed(int)));

	}

    connect(m_tabWidget, SIGNAL(currentChanged(int)), m_pControler, SLOT(slotTabChanged(int)));
	
}

