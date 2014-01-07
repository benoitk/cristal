#include "CWinElecTestView.h"
#include "CWinElecTestControler.h"
#include "CWinExternalCardControler.h"
#include "CWinExternalCardModel.h"
#include "CWinEVPompeControler.h"
#include "CWinEVPompeModel.h"
#include "CWinStreamSelectorModel.h"
#include "CWinMeasureCardControler.h"
#include "CWinMeasureCardModel.h"
#include "CWinMainModel.h"

#include "header_qt.h"


CWinElecTestView::CWinElecTestView(CWinElecTestControler* argpControler, QWidget *parent,Qt::WindowFlags flags)
	: QWidget(parent, flags)
{
	qDebug() << "### Instance CWinEVPompeView" << endl;
	m_pControler = argpControler;
}

void CWinElecTestView::init()
{
	
	m_tabWidget = new QTabWidget();
	

	//*** onglet Pompe
	QWidget* widgetPompe = new QWidget();
	/*QLabel* lblNomRelais1 = new QLabel("Relais 1");
	lblNomRelais1->SetObjectName("lblNomRelais1");
	QLabel* lblNomRelais2 = new QLabel("Relais 2");
	lblNomRelais2->SetObjectName("lblNomRelais2");*/

	//centre de la fenêtre
	QFormLayout* layoutCentral = new QFormLayout();
	QString sPumpLabel;
	qDebug() << "#### foreach(sPumpLabel, m_pModel->getVectorPumpLabels())" << endl;
	int numPompe = 0;
	foreach(sPumpLabel, m_pModelEVPompe->getVectorPumpLabels())
	{
		CPushButton* btOnTemp = new CPushButton(numPompe);
		btOnTemp->setObjectName("btOn");
		m_listBtOnPompe.append(btOnTemp);

		CPushButton* btOffTemp = new CPushButton(numPompe++);
		btOffTemp->setObjectName("btOff");
		m_listBtOffPompe.append(btOffTemp);

		QHBoxLayout* layoutBtPompe = new QHBoxLayout();
		layoutBtPompe->addWidget(btOnTemp,50, Qt::AlignCenter);
		layoutBtPompe->addWidget(btOffTemp,50, Qt::AlignLeft);

		layoutCentral->addRow(sPumpLabel, layoutBtPompe);	
	}
	qDebug() << "#### FIN foreach(sPumpLabel, m_pModel->getVectorPumpLabels())" << endl;
	
	
	//Assemblage centre et bando de nav
	QVBoxLayout* layoutGauche= new QVBoxLayout();
	layoutGauche->addLayout(layoutCentral);
	//layoutGauche->addLayout(layoutNav);

	//menu de gauche //toujours 4 items dans les menus en incluant les spacers
	QPushButton* btBack = new QPushButton();
	m_listBtBack.append(btBack);
	btBack->setObjectName("btBack");

	QVBoxLayout* layoutMenu = new QVBoxLayout();
	layoutMenu->addStretch();
	layoutMenu->addWidget(btBack);


	//assemblage du menu et du layoutGauche
	QHBoxLayout* layoutMain = new QHBoxLayout();
	layoutMain->addLayout(layoutGauche);
	layoutMain->addLayout(layoutMenu);
	widgetPompe->setLayout(layoutMain);
	//: Nom de l'onglet à laisser en maj pour toutes les langues
#ifndef COULEUR
	m_tabWidget->addTab(widgetPompe, tr("POMPE"));
#endif


	////*** Onglet RELAIS
	QWidget* widgetRelais = new QWidget();
	m_layoutCentralRelais = new QFormLayout();
  
	for(int i=0; (i < m_pModelExternalCard->getNbDigitOut()) && (i < NB_RELAIS_MAX) ; ++i)
	{
		CPushButton* btOn = new CPushButton(i);
		btOn->setObjectName("btOn");
		m_listBtOnRelais.append(btOn);
		CPushButton* btOff = new CPushButton(i);
		btOff->setObjectName("btOff");
		m_listBtOffRelais.append(btOff);
		QHBoxLayout* layoutBtRelais = new QHBoxLayout();
		layoutBtRelais->addWidget(btOn,50, Qt::AlignCenter);
		layoutBtRelais->addWidget(btOff,50, Qt::AlignLeft);
		m_layoutCentralRelais->addRow(m_pModelExternalCard->getLblDigiOut(i), layoutBtRelais);
	}


    //Assemblage centre et bando de nav si besoin
	QVBoxLayout* layoutGaucheRelais= new QVBoxLayout();
	layoutGaucheRelais->addLayout(m_layoutCentralRelais);
	
    //menu de gauche //toujours 4 items dans les menus en incluant les spacers
	btBack = new QPushButton();
	m_listBtBack.append(btBack);
	btBack->setObjectName("btBack");
    m_btNextPageRelais = new QPushButton();
    m_btNextPageRelais->setObjectName("btNextBig");
    m_btPrevPageRelais = new QPushButton();
    m_btPrevPageRelais->setObjectName("btPrevBig");
    m_btPrevPageRelais->setEnabled(false);
    QVBoxLayout* layoutMenuRelais = new QVBoxLayout();
    layoutMenuRelais->addStretch();
	//Bouton de navigation de gauche
    if(m_pModelExternalCard->getNbDigitOut() > NB_RELAIS_MAX)
    {
	   
	    // QHBoxLayout* layoutNav= new QHBoxLayout();
	    layoutMenuRelais->addWidget(m_btPrevPageRelais);
        layoutMenuRelais->addWidget(m_btNextPageRelais);
        //layoutGaucheRelais->addLayout(layoutNav);
    }
	layoutMenuRelais->addWidget(btBack);

	

	//assemblage du menu et du layoutGauche
	QHBoxLayout* layoutMainRelais = new QHBoxLayout();
	layoutMainRelais->addLayout(layoutGaucheRelais);
	layoutMainRelais->addLayout(layoutMenuRelais);
	widgetRelais->setLayout(layoutMainRelais);
	//: Nom de l'onglet à laisser en maj pour toute les trad
	m_tabWidget->addTab(widgetRelais, tr("RELAIS"));

//*** onglet EV
	
	QWidget* widgetEV = new QWidget();
	/*QLabel* lblNomRelais1 = new QLabel("Relais 1");
	lblNomRelais1->SetObjectName("lblNomRelais1");
	QLabel* lblNomRelais2 = new QLabel("Relais 2");
	lblNomRelais2->SetObjectName("lblNomRelais2");*/
	/*m_btOnEV1 = new CPushButton(0);
	m_btOnEV1->setObjectName("btOn");
	m_btOffEV1 = new CPushButton(0);
	m_btOffEV1->setObjectName("btOff");*/

	QHBoxLayout* layoutBtEV1 = new QHBoxLayout();
	
	{
		QFormLayout* layoutCentralMesure = new QFormLayout();
		QString sEVLabel;
		int index = 0;
		foreach(sEVLabel, m_pModelEVPompe->getVectorEVLabels())
		{
			CPushButton* btOnTemp = new CPushButton(index);
			btOnTemp->setObjectName("btOn");
			m_listBtOnEV.append(btOnTemp);

			CPushButton* btOffTemp = new CPushButton(index++);
			btOffTemp->setObjectName("btOff");
			m_listBtOffEV.append(btOffTemp);

			QHBoxLayout* layoutBtLocal = new QHBoxLayout();
			layoutBtLocal->addWidget(btOnTemp,50, Qt::AlignCenter);
			layoutBtLocal->addWidget(btOffTemp,50, Qt::AlignLeft);

			layoutCentralMesure->addRow(sEVLabel, layoutBtLocal);	
		}
		if(m_listBtOnEV.count() > 0){
		layoutBtEV1->addWidget(m_listBtOnEV.at(0),50, Qt::AlignCenter);
		layoutBtEV1->addWidget(m_listBtOffEV.at(0),50, Qt::AlignLeft);
		}
		//centre de la fenêtre
		//layoutCentral = new QFormLayout();
		//layoutCentral->addRow(m_pModelEVPompe->getEVLabel(0), layoutBtEV1);
		//layoutCentral->addRow("Relais 2", layoutBtRelais2);

		//Bando de navigation du bas
		/*m_btNextPage = new QPushButton();
		m_btNextPage->setObjectName("btNextPage");
		m_btPreviousPage = new QPushButton();
		m_btPreviousPage->setObjectName("btPreviousPage");
		QHBoxLayout* layoutNav= new QHBoxLayout();
		layoutNav->addWidget(m_btNextPage,5, Qt::AlignCenter);
		layoutNav->addWidget(m_btPreviousPage,5, Qt::AlignLeft);*/

		//Assemblage centre et bando de nav
		layoutGauche= new QVBoxLayout();
		layoutGauche->addLayout(layoutCentralMesure);
		//layoutGauche->addLayout(layoutNav);


		//menu de gauche //toujours 4 items dans les menus en incluant les spacers
		btBack = new QPushButton();
		m_listBtBack.append(btBack);
		btBack->setObjectName("btBack");

		layoutMenu = new QVBoxLayout();
		layoutMenu->addStretch();
		layoutMenu->addWidget(btBack);

		//assemblage du menu et du layoutGauche
		layoutMain = new QHBoxLayout();
		layoutMain->addLayout(layoutGauche);
		layoutMain->addLayout(layoutMenu);
		widgetEV->setLayout(layoutMain);
		//: Nom de l'onglet à laisser en maj pour toute les langues si possible
#ifdef MULTI_EV
//		m_tabWidget->addTab(widgetEV, tr("ELECTROVANNE"));
#endif
	}

	//*** Onglet carte mesure (Actionneur)
	QWidget* widgetMesure = new QWidget();
	
	//centre de la fenêtre
	QFormLayout* layoutCentralMesure = new QFormLayout();
	QString sLocalLabel;
	int index = 0;

	foreach(sLocalLabel, m_pModelMeasureCard->getVectorLocalLabels())
	{
		CPushButton* btOnTemp = new CPushButton(index);
		btOnTemp->setObjectName("btOn");
		m_listBtOnLocal.append(btOnTemp);

		CPushButton* btOffTemp = new CPushButton(index++);
		btOffTemp->setObjectName("btOff");
		m_listBtOffLocal.append(btOffTemp);

		QHBoxLayout* layoutBtLocal = new QHBoxLayout();
		layoutBtLocal->addWidget(btOnTemp,50, Qt::AlignCenter);
		layoutBtLocal->addWidget(btOffTemp,50, Qt::AlignLeft);

		layoutCentralMesure->addRow(sLocalLabel, layoutBtLocal);	
	}
#ifndef COULEUR
    layoutCentralMesure->addRow(m_pModelEVPompe->getEVLabel(0), layoutBtEV1);
#ifdef MULTI_EV
	{
	QHBoxLayout* layoutBt;
	for(int i=1; i<m_listBtOffEV.count(); ++i){
		layoutBt = new QHBoxLayout();
		layoutBt->addWidget(m_listBtOnEV.at(i),50, Qt::AlignCenter);
		layoutBt->addWidget(m_listBtOffEV.at(i),50, Qt::AlignLeft);
		layoutCentralMesure->addRow(m_pModelEVPompe->getEVLabel(i), layoutBt);
	}
	
	}
#endif
#endif
	
    QLabel* lblTemperature = new QLabel(tr("Température cuve :"));
	lblTemperature->setObjectName("lblCurrentStream");
    m_lblTemperature = new QLabel("0°C");
	m_lblTemperature->setObjectName("lblCurrentStep");
	
    QHBoxLayout* layoutTemperature = new QHBoxLayout();
    layoutTemperature->addWidget(lblTemperature);
    layoutTemperature->addWidget(m_lblTemperature);

    //Assemblage centre et bando de nav
	QVBoxLayout* layoutGaucheMesure= new QVBoxLayout();
	layoutGaucheMesure->addLayout(layoutCentralMesure);
    layoutGaucheMesure->addStretch();
	layoutGaucheMesure->addLayout(layoutTemperature);

	//layoutGauche->addLayout(layoutNav);

	//menu de gauche //toujours 4 items dans les menus en incluant les spacers
	btBack = new QPushButton();
	m_listBtBack.append(btBack);
	btBack->setObjectName("btBack");

	QVBoxLayout* layoutMenuMesure = new QVBoxLayout();
	layoutMenuMesure->addStretch();
	layoutMenuMesure->addWidget(btBack);

	//assemblage du menu et du layoutGauche
	QHBoxLayout* layoutMainMesure = new QHBoxLayout();
	layoutMainMesure->addLayout(layoutGaucheMesure);
	layoutMainMesure->addLayout(layoutMenuMesure);
	widgetMesure->setLayout(layoutMainMesure);
	//:Nom de l'onglet à garer en maj pour toutes les trad
	m_tabWidget->addTab(widgetMesure, tr("ACTIONNEURS"));

	

	//*** onglet sortie 4-20
	QWidget* widgetAna = new QWidget();
	
	QPushButton* btValMesure = new QPushButton();
	btValMesure->setText(m_pModelExternalCard->getValueMesure());
	btValMesure->setObjectName("btLineEdit");
	m_btValAna = new QPushButton();
	m_btValAna->setText(m_pModelExternalCard->getValueValAna());
	m_btValAna->setObjectName("btLineEdit");
	m_btValMaxConvertisseur = new QPushButton();
	m_btValMaxConvertisseur->setText(m_pModelExternalCard->getValueValMaxConvertisseur(0));
	m_btValMaxConvertisseur->setObjectName("btLineEdit");
	m_btValMaxConvertisseurPlus = new QPushButton();
	m_btValMaxConvertisseurMoins = new QPushButton();
	m_btValMinConvertisseur = new QPushButton();
	m_btValMinConvertisseur->setText(m_pModelExternalCard->getValueValMinConvertisseur(0));
	m_btValMinConvertisseur->setObjectName("btLineEdit");
	m_btValMinConvertisseurPlus = new QPushButton();
	m_btValMinConvertisseurMoins = new QPushButton();
	
	QGridLayout* gridLayoutAna = new QGridLayout();
    int row = 0;
	/*gridLayoutAna->addWidget(new QLabel(m_pModelExternalCard->getLblMesure()), row, 0);
	gridLayoutAna->addWidget(btValMesure, row, 1);
	gridLayoutAna->addWidget(new QLabel(m_pModelExternalCard->getUniteMesure()), row++, 2);
	gridLayoutAna->addWidget(new QLabel(m_pModelExternalCard->getLblValAna()), row, 0);
	gridLayoutAna->addWidget(m_btValAna, row, 1);
	gridLayoutAna->addWidget(new QLabel(m_pModelExternalCard->getUniteValAna()), row++, 2);*/
    m_lblValMaxConvertisseur = new QLabel(m_pModelExternalCard->getLblValMaxConvertisseur());
	gridLayoutAna->addWidget(m_lblValMaxConvertisseur, row, 0);
	gridLayoutAna->addWidget(m_btValMaxConvertisseur, row, 1);
	gridLayoutAna->addWidget(new QLabel(m_pModelExternalCard->getUniteValMaxConvertisseur()), row++, 2);
    m_lblValMinConvertisseur = new QLabel(m_pModelExternalCard->getLblValMinConvertisseur());
	gridLayoutAna->addWidget(m_lblValMinConvertisseur, row, 0);
	gridLayoutAna->addWidget(m_btValMinConvertisseur, row, 1);
	gridLayoutAna->addWidget(new QLabel(m_pModelExternalCard->getUniteValMinConvertisseur()), row++, 2);


	m_btRadioTest4mA = new QRadioButton(tr("4mA"));
	m_btRadioTest4mA->setObjectName("btRadio");
	m_btRadioTest12mA = new QRadioButton(tr("12mA"));
	m_btRadioTest12mA->setObjectName("btRadio");
	m_btRadioTest20mA = new QRadioButton(tr("20mA"));
	m_btRadioTest20mA->setObjectName("btRadio");
	QGridLayout* gridLayoutRadio = new QGridLayout();
	gridLayoutRadio->addWidget(m_btRadioTest4mA, 0, 0);
	gridLayoutRadio->addWidget(m_btRadioTest12mA, 0, 1);
	gridLayoutRadio->addWidget(m_btRadioTest20mA, 0, 2);

    QLabel* lblTxtNumSortie = new QLabel(tr("Sortie numéro :"));
    lblTxtNumSortie->setObjectName("lblCurrentStream");
    m_lblNumSortieAna = new QLabel("1");
    m_lblNumSortieAna->setObjectName("lblCurrentStream");
    QHBoxLayout* layoutBas = new QHBoxLayout();
    layoutBas->addWidget(lblTxtNumSortie);
    layoutBas->addWidget(m_lblNumSortieAna);

	
	QVBoxLayout* boxLayout= new QVBoxLayout();
    boxLayout->addStretch();
  	boxLayout->addLayout(gridLayoutAna);
    boxLayout->addStretch();
	boxLayout->addLayout(gridLayoutRadio);
    boxLayout->addStretch();
	boxLayout->addLayout(layoutBas);

	//menu de gauche //toujours 4 items dans les menus en incluant les spacers
    btBack = new QPushButton();
	m_listBtBack.append(btBack);
    m_btNextPageSortieAna = new QPushButton();
    m_btNextPageSortieAna->setObjectName("btNextBig");
    m_btPrevPageSortieAna = new QPushButton();
    m_btPrevPageSortieAna->setObjectName("btPrevBig");
    m_btPrevPageSortieAna->setEnabled(false);
    QVBoxLayout* layoutMenuAna = new QVBoxLayout();
        
	layoutMenuAna->addStretch();
    if(m_pModelExternalCard->getNbAnalogOut()>1)
    {
 	    layoutMenuAna->addWidget(m_btPrevPageSortieAna);
        layoutMenuAna->addWidget(m_btNextPageSortieAna);       
    }
	btBack->setObjectName("btBack");

	
	layoutMenuAna->addWidget(btBack);

	//assemblage du menu et du layoutGauche
	QHBoxLayout* layoutMainAna = new QHBoxLayout();
	layoutMainAna->addLayout(boxLayout);
    layoutMainAna->addStretch();
	layoutMainAna->addLayout(layoutMenuAna);
	
	widgetAna->setLayout(layoutMainAna);
	//: Nom de l'onglet à laisser en maj pour toute les trad
	m_tabWidget->addTab(widgetAna , tr("SORTIE 4-20mA"));


	////*** Onglet ENTREE
	QWidget* widgetEntree = new QWidget();
	m_layoutCentralEntree = new QFormLayout();
    {
        QHBoxLayout* hBox = new QHBoxLayout();
        hBox->addWidget(new QLabel(tr("Logique   ")), Qt::AlignLeft);
        hBox->addWidget(new QLabel(tr("Physique")), Qt::AlignLeft);
        m_layoutCentralEntree->addRow(new QLabel(tr("Etat ")), hBox);
    }
	for(int i=0; (i < m_pModelExternalCard->getNbDigitIn()) && (i < NB_RELAIS_MAX) ; ++i)
	{
		CPushButton* btEtatLoqique = new CPushButton(i);
		btEtatLoqique->setObjectName("btEntree");
        CPushButton* btEtatPhysique = new CPushButton(i);
		btEtatPhysique->setObjectName("btEntree");
		m_listBtEtatLogiqueEntree.append(btEtatLoqique);
		m_listBtEtatPhysiqueEntree.append(btEtatPhysique);
        QHBoxLayout* hBox = new QHBoxLayout();
        hBox->addWidget(btEtatLoqique, Qt::AlignLeft);
        hBox->addWidget(btEtatPhysique, Qt::AlignLeft);
		m_layoutCentralEntree->addRow(m_pModelExternalCard->getLblDigiIn(i), hBox);
	}

    //Assemblage centre et bando de nav si besoin
	QVBoxLayout* layoutGaucheEntree= new QVBoxLayout();
	layoutGaucheEntree->addLayout(m_layoutCentralEntree);

	
    //menu de gauche //toujours 4 items dans les menus en incluant les spacers
	btBack = new QPushButton();
	m_listBtBack.append(btBack);
	btBack->setObjectName("btBack");
    m_btNextPageEntree = new QPushButton();
    m_btNextPageEntree->setObjectName("btNextBig");
    m_btPrevPageEntree = new QPushButton();
    m_btPrevPageEntree->setObjectName("btPrevBig");
    m_btPrevPageEntree->setEnabled(false);

    QVBoxLayout* layoutMenuEntree = new QVBoxLayout();
    layoutMenuEntree->addStretch();
	//Bouton de navigation de gauche
    if(m_pModelExternalCard->getNbDigitIn() > NB_RELAIS_MAX)
    {
        // QHBoxLayout* layoutNav= new QHBoxLayout();
	    layoutMenuEntree->addWidget(m_btPrevPageEntree);
        layoutMenuEntree->addWidget(m_btNextPageEntree);
        //layoutGaucheRelais->addLayout(layoutNav);
    }
	layoutMenuEntree->addWidget(btBack);
	


	//assemblage du menu et du layoutGauche
	QHBoxLayout* layoutMainEntree = new QHBoxLayout();
	layoutMainEntree->addLayout(layoutGaucheEntree);
    layoutMainEntree->addStretch();
	layoutMainEntree->addLayout(layoutMenuEntree);
	widgetEntree->setLayout(layoutMainEntree);
	//: Nom de l'onglet à laisser en maj pour toute les trad
//#ifdef RES_640_480
	m_tabWidget->addTab(widgetEntree, tr("ENTREES"));
//#endif
    //*** Onglet SELECTEUR de voie rotatif
    QWidget* widgetSelector = new QWidget();
	QFormLayout* layoutCentralSelector = new QFormLayout();
    
	for(int i=0; i < m_pModelStreamSelector->getNbStream(); ++i)
	{
		CPushButton* btOn = new CPushButton(i);
		btOn->setObjectName("btOn");
		m_listBtOnStreamSelector.append(btOn);
		CPushButton* btOff = new CPushButton(i);
		btOff->setObjectName("btOff");
		m_listBtOffStreamSelector.append(btOff);
		QHBoxLayout* layoutBtSelector = new QHBoxLayout();
		layoutBtSelector->addWidget(btOn,50, Qt::AlignCenter);
		//layoutBtSelector->addWidget(btOff,50, Qt::AlignLeft);
        layoutCentralSelector->addRow(QString(tr("Selection voie ")+ QString::number(i+1)), layoutBtSelector);
	}

    //Assemblage centre et bando de nav si besoin
	QVBoxLayout* layoutGaucheSelector= new QVBoxLayout();
	layoutGaucheSelector->addLayout(layoutCentralSelector);
	
    //menu de gauche //toujours 4 items dans les menus en incluant les spacers
	btBack = new QPushButton();
	m_listBtBack.append(btBack);
	btBack->setObjectName("btBack");
    QVBoxLayout* layoutMenuSelector = new QVBoxLayout();
    layoutMenuSelector->addStretch();
	layoutMenuSelector->addWidget(btBack);

	

	//assemblage du menu et du layoutGauche
	QHBoxLayout* layoutMainSelector = new QHBoxLayout();
	layoutMainSelector->addLayout(layoutGaucheSelector);
	layoutMainSelector->addLayout(layoutMenuSelector);
	widgetSelector->setLayout(layoutMainSelector);
	//: Nom de l'onglet à laisser en maj pour toute les trad
#if defined(MULTI_STREAM) && defined(SELECTEUR) 
	m_tabWidget->addTab(widgetSelector, tr("SELECTEUR"));
#endif

	//*** 
    QHBoxLayout* layoutGlobal = new QHBoxLayout(); 
    layoutGlobal->setContentsMargins ( 0, 0, 0, 0 );
    layoutGlobal->addWidget(m_tabWidget);
	this->setLayout(layoutGlobal);

	
	setConnexion();

	qDebug() << "#### FIN CWinElecTestView::init()" << endl;

}
void CWinElecTestView::dataUpdated()
{
    CPushButton* btTmp;
    int index=0; 
    foreach(btTmp, m_listBtEtatLogiqueEntree)
    {
        btTmp->setEnabled(m_pModelExternalCard->getEtatEntree(index));
        ++index;
    }
    index=0;
    foreach(btTmp, m_listBtEtatPhysiqueEntree)
    {
        btTmp->setEnabled(m_pModelExternalCard->getEtatEntreePhysique(index));
        ++index;
    }
    
}
//SLOT
void CWinElecTestView::slotTemperatureUpdated()
{
    m_lblTemperature->setText(m_pModelMain->getTemperatureCuve()+ QString(tr("°C")));
}
//SLOT
// argNumPage numéro de la page de 0 à n pages
void CWinElecTestView::loadPageExternalCard(int argnNumPage)
{
     
	int nIndex = 0;
    int offSet = NB_RELAIS_MAX*(argnNumPage);
    for(int i = offSet; i != m_pModelExternalCard->getNbDigitOut() && nIndex < NB_RELAIS_MAX; ++i)
	{

	    QLayout* layout =  m_layoutCentralRelais->itemAt(nIndex, QFormLayout::FieldRole)->layout();
        ((QLabel*)m_layoutCentralRelais->labelForField(layout))->setText(m_pModelExternalCard->getLblDigiOut(i));
        //btOn
        ((QPushButton*)layout->itemAt(0)->widget())->setVisible(true);
        ((QPushButton*)layout->itemAt(0)->widget())->setEnabled(!m_pControler->getEtatRelais(i));
        //btOn
        ((QPushButton*)layout->itemAt(1)->widget())->setVisible(true);
        ((QPushButton*)layout->itemAt(1)->widget())->setEnabled(m_pControler->getEtatRelais(i));
       
        ((QLabel*)m_layoutCentralRelais->labelForField(layout))->setVisible(true);
		++nIndex;
	
	}
	while(nIndex < NB_RELAIS_MAX)
	{
		QLayout* layout =  m_layoutCentralRelais->itemAt(nIndex, QFormLayout::FieldRole)->layout();
        //btOn
        ((QPushButton*)layout->itemAt(0)->widget())->setVisible(false);
        //btOn
        ((QPushButton*)layout->itemAt(1)->widget())->setVisible(false);
        ((QLabel*)m_layoutCentralRelais->labelForField(layout))->setVisible(false);
		++nIndex;
	}
	this->update();
	
}
//SLOT
void CWinElecTestView::loadPageEntree(int argnNumPage)
{

}
//SLOT
void CWinElecTestView::loadPageSortieAna(int argnNumPage)
{
    m_lblNumSortieAna->setText(QString::number(argnNumPage+1));
    m_btValMaxConvertisseur->setText(m_pModelExternalCard->getValueValMaxConvertisseur(argnNumPage));
    m_btValMinConvertisseur->setText(m_pModelExternalCard->getValueValMinConvertisseur(argnNumPage));
   	
	this->update();
}
void CWinElecTestView::setConnexion()
{
	qDebug() << "#### CWinEVPompeView::setConnexion" << endl;
	QPushButton* btTemp;
	foreach(btTemp, m_listBtBack)
	{
		connect(btTemp, SIGNAL(clicked()), m_pControler,SLOT(btBackPressed()));	
	}
	//tab EV
	/*connect(m_btOnEV1, SIGNAL(clicked(int)), m_pControler,SLOT(btOnEVPressed(int)));
	connect(m_btOffEV1, SIGNAL(clicked(int)), m_pControler,SLOT(btOffEVPressed(int)));*/
	foreach(btTemp, m_listBtOnEV)
	{
			connect(btTemp, SIGNAL(clicked(int)), m_pControler, SLOT(btOnEVPressed(int)));
	}
	foreach(btTemp, m_listBtOffEV)
	{
			connect(btTemp, SIGNAL(clicked(int)), m_pControler, SLOT(btOffEVPressed(int)));
	}
	//Tab Pompe
	int nNbPompe = m_listBtOnPompe.count();
	qDebug() << "#### CWinEVPompeView::setConnexion | Nb pompe" << nNbPompe << endl;
	
	foreach(btTemp, m_listBtOnPompe)
	{
		connect(btTemp, SIGNAL(clicked(int)), m_pControler,SLOT(btOnPompePressed(int)));
		
	}
	foreach(btTemp, m_listBtOffPompe)
	{
		connect(btTemp, SIGNAL(clicked(int)), m_pControler,SLOT(btOffPompePressed(int)));

	}
	//Tab Mesure
	foreach(btTemp, m_listBtOnLocal)
	{
		connect(btTemp, SIGNAL(clicked(int)), m_pControler,SLOT(btOnLocalPressed(int)));

	}
	foreach(btTemp, m_listBtOffLocal)
	{
		connect(btTemp, SIGNAL(clicked(int)), m_pControler,SLOT(btOffLocalPressed(int)));

	}
	
	//Tab relais
	foreach(btTemp, m_listBtOnRelais)
	{
			connect(btTemp, SIGNAL(clicked(int)), m_pControler, SLOT(btOnRelaisPressed(int)));
	}
	foreach(btTemp, m_listBtOffRelais)
	{
			connect(btTemp, SIGNAL(clicked(int)), m_pControler, SLOT(btOffRelaisPressed(int)));
	}
	connect(m_btNextPageRelais, SIGNAL(clicked()), m_pControler, SLOT(btNextPageRelaisPressed()));
	connect(m_btPrevPageRelais, SIGNAL(clicked()), m_pControler, SLOT(btPrevPageRelaisPressed()));
    
	//Tab 4-20
	connect(m_btRadioTest4mA, SIGNAL(clicked()), m_pControler, SLOT(btRadioTest4mAPressed()));
	connect(m_btRadioTest12mA, SIGNAL(clicked()), m_pControler, SLOT(btRadioTest12mAPressed()));
	connect(m_btRadioTest20mA, SIGNAL(clicked()), m_pControler, SLOT(btRadioTest20mAPressed()));

	connect(m_btValMaxConvertisseur, SIGNAL(clicked()), m_pControler, SLOT(btValMaxConvertisseurPressed()));
	connect(m_btValMinConvertisseur, SIGNAL(clicked()), m_pControler, SLOT(btValMinConvertisseurPressed()));

    connect(m_btNextPageSortieAna, SIGNAL(clicked()), m_pControler, SLOT(btNextPageSortieAnaPressed()));
	connect(m_btPrevPageSortieAna, SIGNAL(clicked()), m_pControler, SLOT(btPrevPageSortieAnaPressed()));
    //Tab selecteur de voie
	foreach(btTemp, m_listBtOnStreamSelector)
	{
			connect(btTemp, SIGNAL(clicked(int)), m_pControler, SLOT(btOnStreamSelectorPressed(int)));
	}
	/*foreach(btTemp, m_listBtOffStreamSelector)
	{
			connect(btTemp, SIGNAL(clicked(int)), m_pControler, SLOT(btOffStreamSelectorPressed(int)));
	}*/
	//Event des onglets
	connect(m_tabWidget, SIGNAL(currentChanged(int)), m_pControler, SLOT(tabChanged(int)));
}
