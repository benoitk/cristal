#include "CWinMainView.h"
#include "CWinMainControler.h"
#include "CWinMainModel.h"
#include "CGraphicsRectItem.h"

#include "header_qt.h"

#if defined(RES_640_480) && defined(MULTI_STREAM)
    #define SCENE_WIDTH 500
    #define SCENE_HEIGHT 300
#elif defined(RES_640_480)
    #define SCENE_WIDTH 440
    #define SCENE_HEIGHT 180
#else
    #define SCENE_WIDTH 400//440
    #define SCENE_HEIGHT 160
#endif


CWinMainView::CWinMainView(CWinMainControler* argoControler, QWidget *parent, Qt::WFlags flags)
	: QWidget(parent, flags)
{
	qDebug() << "#### CWinMainControler::CWinMainView" << endl;
   // qDebug() << "#### QThread::idealThreadCount () " << QThread::idealThreadCount();
	m_pControler = argoControler;

	for(int i=0; i<NB_MESURE_GRAPH; ++i)
		m_tabMesureMax[i]=0;
	m_fCoefAOld = 1;
}

void CWinMainView::setModel(CWinMainModel* argoModel)
{   
    m_pModel = argoModel;
    init();
}

void CWinMainView::init()
{
	qDebug() << "#### CWinMainControler::init" << endl;

	m_tabWidgetCentral = new QTabWidget(); //Pas de parent, setCentralWidget l'attribura à la fenêtre
    QHBoxLayout* layoutGlobal = new QHBoxLayout(); 
    layoutGlobal->setContentsMargins ( 0, 0, 0, 0 );
    layoutGlobal->addWidget(m_tabWidgetCentral);
    
    this->setLayout(layoutGlobal);
	//setCentralWidget(m_tabWidgetCentral);

	//***HISTOGRAMME
	QGraphicsScene* scene = new QGraphicsScene();
#if !defined(RES_640_480)// || defined(MULTI_STREAM)
	scene->setSceneRect(0,0,SCENE_WIDTH, SCENE_HEIGHT);
#endif
	QPen pen(Qt::lightGray, 1, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin);
	QColor color(Qt::lightGray);
	color.setAlpha(200);
	QBrush brush(color);
	for(int i=0; i<SCENE_HEIGHT-1; i=i+10)
	{
		scene->addLine(0,i,SCENE_WIDTH-15, i, pen);
		/*scene->addText(QString::number(i))->setPos(-10,i-5);	*/		
	}
	pen.setColor(Qt::black);
	scene->addLine(0,SCENE_HEIGHT,SCENE_WIDTH-15, SCENE_HEIGHT, pen);
	m_lblMesureGraph = new QLabel("                            ");
	scene->addWidget(m_lblMesureGraph)->setPos(0,-20);
	m_lblConcentrationMax = new QLabel("1000");
	m_lblConcentrationMax->setObjectName("lblGraphUnit");
	m_lblConcentrationMin = new QLabel("0");
	m_lblConcentrationMin->setObjectName("lblGraphUnit");
	m_lblConcentrationMoy = new QLabel("500");
	m_lblConcentrationMoy->setObjectName("lblGraphUnit");
	QLabel* lblInfo = new QLabel();
	lblInfo->setObjectName("lblGraphInfo");
	
	scene->addWidget(m_lblConcentrationMax)->setPos(SCENE_WIDTH-23,-10);
	scene->addWidget(m_lblConcentrationMoy)->setPos(SCENE_WIDTH-13,(SCENE_HEIGHT/2)-10);
	scene->addWidget(m_lblConcentrationMin)->setPos(SCENE_WIDTH-13,SCENE_HEIGHT-10);
	QGraphicsProxyWidget* proxyLblInfo= new QGraphicsProxyWidget();
	proxyLblInfo->setWidget(lblInfo);
	//proxyLblInfo = scene->addWidget(lblInfo)
	proxyLblInfo->resize(100, 60);
	proxyLblInfo->setPos(SCENE_WIDTH - 140, -20);
	proxyLblInfo->setVisible(false);
	
	int i;
    for(int j=0; j<m_pModel->getNbStream(); ++j)
    {
        QList<CGraphicsRectItem*> list;
	    for(i=0; i<SCENE_WIDTH-20; i=i+10)
	    {
            if(j==0)
            {
		        if(i%4==0 || i==0)
		        {
			        scene->addLine(i,SCENE_HEIGHT+3, i,SCENE_HEIGHT-3, pen);
			        m_listGraphicsRectItem.append(new CGraphicsRectItem(i, SCENE_HEIGHT, 20, 0, proxyLblInfo));//, proxyLblMesure));
			        m_listGraphicsRectItem.last()->setBrush(brush);
			        m_listGraphicsRectItem.last()->setPen(color);
			        scene->addItem(m_listGraphicsRectItem.last());
		        }
		        else
			        scene->addLine(i,SCENE_HEIGHT, i,SCENE_HEIGHT-3, pen);
            }
            if(i%4==0 || i==0)
            {
                list.append(new CGraphicsRectItem(i, SCENE_HEIGHT, 20, 0, proxyLblInfo));//, proxyLblMesure));
                list.last()->setBrush(brush);
                list.last()->setPen(color);
            }
    			
	    }
        m_listDataGraph.append(list);
    }
	scene->addLine(i,SCENE_HEIGHT+3, i,SCENE_HEIGHT-3, pen);
	pen.setColor(Qt::green);
	scene->addItem(proxyLblInfo);
	QGraphicsView* view= new QGraphicsView(scene);
	QHBoxLayout* graphLayout = new QHBoxLayout();
	graphLayout->addWidget(view);
    graphLayout->setContentsMargins ( 0, 0, 0, 0 );
   
	QWidget* widgetGraph = new QWidget();
	widgetGraph->setLayout(graphLayout);
	//FIN HISTGRAMME

	
    
	qDebug() << "#### CWinMainControler::init 0" << endl;
    
	QVBoxLayout* centralLayout = new QVBoxLayout();
	for(int i=0; i<m_pModel->getNbStream(); ++i)
	{

        QList<QLabel*> listLblMesure;
        QList<QLabel*> listLblValMesure;
        qDebug() << "#### CWinMainControler::init 1 " << i <<endl;
        m_mesureLayout = new QGridLayout(); //Pas de parent, setLayout affect m_groupBoxCentral en parent
        //m_mesureLayout->setHorizontalSpacing(1);

        CPushButton* btDetail = new CPushButton(i);
        btDetail->setObjectName("btDetail");
        m_listBtDetail.append(btDetail);

        QLabel* lblStatusVoie = new QLabel("0000000000");
        lblStatusVoie->setObjectName("lblStatusWaterFailure");
        m_listLblStatusVoie.append(lblStatusVoie);
        
		for(int j=0; j<m_pModel->getNbMeasure(i); ++j)
		{
			qDebug() << "#### CWinMainControler::init 2 " << j <<endl;
            QLabel* lblMesure = new QLabel(QString(" ")+ m_pModel->getMesureValueLbl(i, j));
			lblMesure->setObjectName("lblMesure");
			listLblMesure.append(lblMesure);
			
            QLabel* lblNumVoie = new QLabel(QString("_") +QString::number(i+1));
			lblNumVoie->setObjectName("lblMesure");
            
			QLabel* lblValMesure = new QLabel(m_pModel->getMesureValue(i, j) + m_pModel->getMesureValueUnit(i, j));
			lblValMesure->setObjectName("lblValMesure");
			listLblValMesure.append(lblValMesure);
		
            int row = i+j;
            int col = 0;

#ifdef MULTI_MEASURE
            if(j==0) //Afficher le bouton de détail uniquement pour la première mesure.
            {
                m_mesureLayout->addWidget(btDetail,row, col++, Qt::AlignLeft);

            }
            else
                col++;
			m_mesureLayout->addWidget(lblMesure,row, col++,  Qt::AlignLeft);//m_lblValMesure);
			m_mesureLayout->addWidget(lblValMesure,row, col++,  Qt::AlignLeft);
#ifdef MULTI_STREAM
            if(j==0) 
            m_mesureLayout->addWidget(lblStatusVoie,row, col++,  Qt::AlignRight);
#endif
			 m_mesureLayout->setColumnStretch ( col, 1 );
#else
			if(j==0)
			{
				m_mesureLayout->addWidget(btDetail,row, col++, Qt::AlignLeft);
				m_mesureLayout->addWidget(lblMesure,row, col++,  Qt::AlignLeft);//m_lblValMesure);
				m_mesureLayout->addWidget(lblValMesure,row, col++,  Qt::AlignLeft);
#ifdef MULTI_STREAM
				m_mesureLayout->addWidget(lblStatusVoie,row, col++,  Qt::AlignRight);
#endif
				m_mesureLayout->setColumnStretch ( col, 1 );
			}
#endif
            
#ifdef MAGNESIUM
			++j; //ne pas afficher la deuxième mesure
#endif      
           
		}
        m_listLblValMesure.append(listLblValMesure);
		m_listLblMesure.append(listLblMesure);

		centralLayout->addLayout(m_mesureLayout); 
	}

	//m_lblMesure = new QLabel(tr("MESURE"));
	//m_lblMesure->setObjectName("lblMesure");
	//m_lblValMesure = new QLabel("VAL MESURE");
	//m_lblValMesure->setObjectName("lblValMesure");
	//m_btDetail = new QPushButton();
	//m_btDetail->setObjectName("btDetail");
	//QHBoxLayout* mesureLayout = new QHBoxLayout(); //Pas de parent, setLayout affect m_groupBoxCentral en parent
	//mesureLayout->addWidget(m_btDetail,0, Qt::AlignLeft);
	//mesureLayout->addWidget(m_lblMesure,0, Qt::AlignLeft);//m_lblValMesure);
	//mesureLayout->addWidget(m_lblValMesure,50 , Qt::AlignLeft);


	//info du cycle
	m_lblStatusAnalyseur = new QLabel("INITIALISATION");
	m_lblStatusAnalyseur->setObjectName("lblStatusAnalyseur");
	m_lblStatusWaterFailure= new QLabel;
	m_lblStatusWaterFailure->setObjectName("lblStatusWaterFailure");
	m_lblStatusSeuil= new QLabel;
	m_lblStatusSeuil->setObjectName("lblStatusSeuil");
	m_lblCurrentStream = new QLabel;
	m_lblCurrentStream->setObjectName("lblCurrentStream");
	m_lblCurrentStep = new QLabel;
	m_lblCurrentStep->setObjectName("lblCurrentStep");
	m_lblTotalStep = new QLabel;
	m_lblTotalStep->setObjectName("lblTotalStep");
	m_lblNameStep = new QLabel;
	m_lblNameStep->setObjectName("lblNameStep");
	m_lblDateHeure = new QLabel;
	m_lblDateHeure->setObjectName("lblDateHeure");

	QHBoxLayout* horizontalLayout = new QHBoxLayout();
	horizontalLayout->setObjectName("horizontalLayout");
	//horizontalLayout->addWidget(m_lblStatusAnalyseur, 40); //40%
	horizontalLayout->addWidget(m_lblCurrentStream, 30);
	horizontalLayout->addWidget(m_lblCurrentStep, 15); 
	horizontalLayout->addWidget(m_lblTotalStep, 15); 

	
	QVBoxLayout* verticalTmpLayout = new QVBoxLayout();
	verticalTmpLayout->addStretch();
#if defined(RES_640_480) && defined(MULTI_STREAM)
	
	verticalTmpLayout->addWidget(m_lblStatusAnalyseur);
#elif defined(RES_640_480)
    if(m_pModel->getNbStream() < 2) //pour test
	{
		verticalTmpLayout->addWidget(m_lblStatusWaterFailure);
		verticalTmpLayout->addWidget(m_lblStatusSeuil);
	}
	verticalTmpLayout->addWidget(m_lblStatusAnalyseur);
#else
	QHBoxLayout* layoutTmpH = new QHBoxLayout();
	QVBoxLayout* layoutTmpV = new QVBoxLayout();
	layoutTmpV->addWidget(m_lblStatusWaterFailure);
	layoutTmpV->addWidget(m_lblStatusSeuil);
	layoutTmpH->addWidget(m_lblStatusAnalyseur);
	layoutTmpH->addLayout(layoutTmpV);
	verticalTmpLayout->addLayout(layoutTmpH);
#endif
	verticalTmpLayout->addLayout(horizontalLayout);
	verticalTmpLayout->addWidget(m_lblNameStep); 
	verticalTmpLayout->addWidget(m_lblDateHeure);


	//QVBoxLayout* horizontalBottomTmpLayout = new QVBoxLayout();
	//horizontalBottomTmpLayout->addWidget(m_lblNameStep); 
	//horizontalBottomTmpLayout->addWidget(m_lblDateHeure);

	//QVBoxLayout* verticalTmpLayout = new QVBoxLayout();
	//verticalTmpLayout->addWidget(m_lblStatusAnalyseur);
	//verticalTmpLayout->addLayout(horizontalLayout);
	//verticalTmpLayout->addLayout(horizontalBottomTmpLayout);


	//Assemblage m_groupBoxCentral et m_groupBoxInfo
	
#if defined(RES_640_480) && !defined(MULTI_STREAM) && !defined(MULTI_MEASURE)
	centralLayout->addWidget(widgetGraph);
#endif
	centralLayout->addLayout(verticalTmpLayout); //5%

	//Bouttons de droite
	m_btAlarm = new QPushButton();
	m_btAlarm->setObjectName("btAlarm");
	m_btAlarm->setCheckable(true);
	m_btPlayPause = new QPushButton();
	m_btPlayPause->setObjectName("btPlayPause");
	m_btStop = new QPushButton();
	m_btStop->setObjectName("btStop");
	m_btStopEndCycle = new QPushButton();
	m_btStopEndCycle->setObjectName("btStopEndCycle");
	m_btNext = new QPushButton();
	m_btNext->setObjectName("btNext");

	QVBoxLayout* verticalLayout = new QVBoxLayout();
	verticalLayout->addStretch();
	verticalLayout->addWidget(m_btAlarm);
	verticalLayout->addWidget(m_btPlayPause);
	verticalLayout->addWidget(m_btStop);
	verticalLayout->addWidget(m_btStopEndCycle);
#if defined(RES_640_480)
	verticalLayout->addWidget(m_btNext);
#endif

	//Assemblage m_groupBoxRight et centralLayout
	QHBoxLayout* topLayout = new QHBoxLayout();
	topLayout->addLayout(centralLayout, 90); //95%
	//topLayout->addWidget(m_groupBoxRight, 10); //5%
	topLayout->addLayout(verticalLayout, 10); //5%
	
	QWidget* widgetMain = new QWidget();
	widgetMain->setLayout(topLayout);
	
	m_tabWidgetCentral->addTab(widgetMain, tr("MESURE"));
//	m_tabWidgetCentral->setLayout(mainLayout);
	

	//*** Page Diagnostique
	QWidget* widgetDiag = new QWidget();
	
	//Utilisation des boutons pour l'affichage seul (pour ne pas refaire le CSS), ils ne sont pas connectés
	m_btTemperatureCuve = new QPushButton;
	m_btTemperatureCuve->setObjectName("btLineEdit");
	m_btPressionEau = new QPushButton;
	m_btPressionEau->setObjectName("btLineEdit");
	m_btMesureOptique = new QPushButton;
	m_btMesureOptique->setObjectName("btLineEdit");
	m_btOpticalGain = new QPushButton;
	m_btOpticalGain->setObjectName("btLineEdit");
	m_btOpticalMeasurement = new QPushButton;
	m_btOpticalMeasurement->setObjectName("btLineEdit");
	m_btZeroOpticalMeasurement = new QPushButton;
	m_btZeroOpticalMeasurement->setObjectName("btLineEdit");
    m_btAbsorbanceValue = new QPushButton;
	m_btAbsorbanceValue->setObjectName("btLineEdit");
	QGridLayout* gridLayout = new QGridLayout();
    int row =0;
    gridLayout->addWidget(new QLabel(m_pModel->getOpticalGainLbl()), row,0);
	gridLayout->addWidget(m_btOpticalGain, row, 1);
	gridLayout->addWidget(new QLabel(m_pModel->getOpticalGainUnit()), row++,2);
    gridLayout->addWidget(new QLabel(m_pModel->getZeroOpticalMeasurementLbl()), row,0);
	gridLayout->addWidget(m_btZeroOpticalMeasurement, row, 1);
	gridLayout->addWidget(new QLabel(m_pModel->getZeroOpticalMeasurementUnit()), row++,2);
    gridLayout->addWidget(new QLabel(m_pModel->getOpticalMeasurementLbl()), row,0);
	gridLayout->addWidget(m_btOpticalMeasurement, row, 1);
	gridLayout->addWidget(new QLabel(m_pModel->getOpticalMeasurementUnit()), row++,2);
    gridLayout->addWidget(new QLabel(m_pModel->getAbsorbanceValueLbl()), row,0);
	gridLayout->addWidget(m_btAbsorbanceValue, row, 1);
	gridLayout->addWidget(new QLabel(m_pModel->getAbsorbanceValueUnit()), row++,2);
#ifdef SONDE
	gridLayout->addWidget(new QLabel(tr("Mesure électrode")), row,0);
#else
	gridLayout->addWidget(new QLabel(tr("Mesure optique direct")), row,0);
#endif
	gridLayout->addWidget(m_btMesureOptique, row, 1);
	gridLayout->addWidget(new QLabel(tr("Pts")), row++,2);
#ifndef COULEUR
	gridLayout->addWidget(new QLabel(tr("Température Cuve")), row,0);
	gridLayout->addWidget(m_btTemperatureCuve, row, 1);
	gridLayout->addWidget(new QLabel(tr("°C")), row++,2);
#endif
	gridLayout->addWidget(new QLabel(tr("Capteur de pression d'eau")), row,0);
	gridLayout->addWidget(m_btPressionEau, row, 1);
	gridLayout->addWidget(new QLabel(tr("V")), row++,2);

	
	
	
	
	m_lblCurrentStreamDiag = new QLabel;
	m_lblCurrentStreamDiag->setObjectName("lblCurrentStream");
	m_lblCurrentStepDiag = new QLabel;
	m_lblCurrentStepDiag->setObjectName("lblCurrentStep");
	m_lblTotalStepDiag = new QLabel;
	m_lblTotalStepDiag->setObjectName("lblTotalStep");
	m_lblNameStepDiag = new QLabel;
	m_lblNameStepDiag->setObjectName("lblNameStep");
	

	QHBoxLayout* horizontalLayoutDiag = new QHBoxLayout();
	horizontalLayoutDiag->setObjectName("horizontalLayout");
	horizontalLayoutDiag->addWidget(m_lblCurrentStreamDiag, 30);
	horizontalLayoutDiag->addWidget(m_lblCurrentStepDiag, 15); 
	horizontalLayoutDiag->addWidget(m_lblTotalStepDiag, 15); 
    
    QVBoxLayout* verticalLayoutDiag = new QVBoxLayout();
    verticalLayoutDiag->addStretch();
    verticalLayoutDiag->addLayout(gridLayout);
    verticalLayoutDiag->addStretch();
#if defined(RES_640_480)
    verticalLayoutDiag->addLayout(horizontalLayoutDiag);
    verticalLayoutDiag->addWidget(m_lblNameStepDiag);
#endif

	

	widgetDiag->setLayout(verticalLayoutDiag);
	//: Nom de l'onglet à laisser en maj pour toutes les trads
	m_tabWidgetCentral->addTab(widgetDiag, tr("DIAGNOSTIC"));

	//***Menu outils

	//Groupe des boutons 
	//Colonne 1 
	m_btMaintenance = new QPushButton();
	m_btMaintenance->setObjectName("btMaintenance");
	QLabel* lblMaintenance = new QLabel(tr("Maintenance"));
	lblMaintenance->setObjectName("lblOutils");
	m_btSequenceur = new QPushButton();
	m_btSequenceur->setObjectName("btSequenceur");
	QLabel* lblSequenceur = new QLabel(tr("Options"));
	lblSequenceur->setObjectName("lblOutils");
	m_btCopyLogFiles = new QPushButton();
	m_btCopyLogFiles->setObjectName("btCopyLogFiles");
	QLabel* lblCopyLogFiles = new QLabel(tr("Copie des fichiers log"));
	lblCopyLogFiles->setObjectName("lblOutils");
	/*m_btHelp = new QPushButton("");
	m_btHelp->setObjectName("btHelp");
	QLabel* lblHelp = new QLabel("Aide");
	lblHelp->setObjectName("lblOutils");*/
		//Colonne 2
	m_btMeasureCard = new QPushButton();
	m_btMeasureCard->setObjectName("btMeasureCard");
	QLabel* lblMeasureCard = new QLabel(tr("Test électrique"));
	lblMeasureCard->setObjectName("lblOutils");
	/*m_btSave = new QPushButton("");
	m_btSave->setObjectName("btSave");
	QLabel* lblSave = new QLabel("Sauvegarde");
	lblSave->setObjectName("lblOutils");
	m_btInformation = new QPushButton("");
	m_btInformation->setObjectName("btInformation");
	QLabel* lblInformation = new QLabel("Information");
	lblInformation->setObjectName("lblOutils");*/
		//Colonne 3
	/*m_btExternalCard = new QPushButton();
	m_btExternalCard->setObjectName("btExternalCard");
	QLabel* lblExternalCard = new QLabel(tr("Carte externe"));
	lblExternalCard->setObjectName("lblOutils");*/
	/*m_btParameter = new QPushButton();
	m_btParameter->setObjectName("btParameter");
	QLabel* lblParameter = new QLabel("Pramètres");
	lblParameter->setObjectName("lblOutils");
	m_btExplorer = new QPushButton();
	m_btExplorer->setObjectName("btExplorer");
	QLabel* lblExplorer = new QLabel("Exploreur");
	lblExplorer->setObjectName("lblOutils");*/
		//Colonne 4
	/*m_btEvPump = new QPushButton();
	m_btEvPump->setObjectName("btEvPump");
	QLabel* lblEvPump = new QLabel(tr("EV/Pompe"));
	lblEvPump->setObjectName("lblOutils");*/
	/*m_btAnalyseur = new QPushButton();
	m_btAnalyseur->setObjectName("btAnalyseur");
	QLabel* lblAnalyseur = new QLabel("Analyseur");
	lblAnalyseur->setObjectName("lblOutils");*/
	
	QGridLayout *gridLayoutBt = new QGridLayout();
	
	gridLayoutBt->addWidget(m_btMaintenance, 0, 0, Qt::AlignHCenter);
	gridLayoutBt->addWidget(lblMaintenance, 1, 0, Qt::AlignTop|Qt::AlignHCenter);
	gridLayoutBt->addWidget(m_btSequenceur, 2, 0, Qt::AlignHCenter);
	gridLayoutBt->addWidget(lblSequenceur, 3, 0, Qt::AlignTop|Qt::AlignHCenter);
#if defined(RES_640_480) //pas de copie de fichier pour le petit panel
	gridLayoutBt->addWidget(m_btCopyLogFiles, 4, 0, Qt::AlignHCenter);
	gridLayoutBt->addWidget(lblCopyLogFiles, 5, 0, Qt::AlignTop|Qt::AlignHCenter);
#endif
	/*gridLayoutBt->addWidget(m_btHelp, 4, 0, Qt::AlignHCenter);
	gridLayoutBt->addWidget(lblHelp, 5, 0, Qt::AlignTop|Qt::AlignHCenter);*/
	gridLayoutBt->addWidget(m_btMeasureCard, 0, 3, Qt::AlignHCenter);
	gridLayoutBt->addWidget(lblMeasureCard, 1, 3, Qt::AlignTop|Qt::AlignHCenter);
	/*gridLayoutBt->addWidget(m_btSave, 2, 1, Qt::AlignHCenter);
	gridLayoutBt->addWidget(lblSave, 3, 1, Qt::AlignTop|Qt::AlignHCenter);
	gridLayoutBt->addWidget(m_btInformation, 4, 1, Qt::AlignHCenter);
	gridLayoutBt->addWidget(lblInformation, 5, 1, Qt::AlignTop|Qt::AlignHCenter);*/
	/*gridLayoutBt->addWidget(m_btExternalCard, 2, 3, Qt::AlignHCenter);
	gridLayoutBt->addWidget(lblExternalCard, 3, 3, Qt::AlignTop|Qt::AlignHCenter);*/
	/*gridLayoutBt->addWidget(m_btParameter, 2, 2, Qt::AlignHCenter);
	gridLayoutBt->addWidget(lblParameter, 3, 2, Qt::AlignTop|Qt::AlignHCenter);
	gridLayoutBt->addWidget(m_btExplorer, 4, 2, Qt::AlignHCenter);
	gridLayoutBt->addWidget(lblExplorer, 5, 2, Qt::AlignTop|Qt::AlignHCenter);*/
	/*gridLayoutBt->addWidget(m_btEvPump, 4, 3, Qt::AlignHCenter);
	gridLayoutBt->addWidget(lblEvPump, 5, 3, Qt::AlignTop|Qt::AlignHCenter);*/
	/*gridLayoutBt->addWidget(m_btAnalyseur, 2, 3, Qt::AlignHCenter);
	gridLayoutBt->addWidget(lblAnalyseur, 3, 3, Qt::AlignTop|Qt::AlignHCenter);*/
	
	QWidget* widgetMenuTools = new QWidget();
	widgetMenuTools->setLayout(gridLayoutBt);

	m_tabWidgetCentral->addTab(widgetMenuTools, tr("OUTILS"));

    //*** Onglet HISTOGRAMME
    m_btNextGraph  = new QPushButton();
    m_btNextGraph->setObjectName("btNextBig");
    m_btPrevGraph = new QPushButton();
    m_btPrevGraph->setObjectName("btPrevBig");
    m_btPrevGraph->setEnabled(false);;
    m_lblInfoGraph = new QLabel("INFO GRAPH");
    m_lblInfoGraph->setObjectName("lblNameStep");
#if !defined(RES_640_480) || defined(MULTI_STREAM) || defined(MULTI_MEASURE)
	
    {
        
        QVBoxLayout* layoutMenuGraph = new QVBoxLayout();
        layoutMenuGraph->setContentsMargins ( 0, 0, 0, 0 );
        layoutMenuGraph->addStretch();
	    layoutMenuGraph->addWidget(m_btPrevGraph);
	    layoutMenuGraph->addWidget(m_btNextGraph);
        
        QVBoxLayout* layoutGraph = new QVBoxLayout();
        layoutGraph->addWidget(widgetGraph);
    #ifdef MULTI_STREAM
        layoutGraph->addWidget(m_lblInfoGraph);
    #endif
        QHBoxLayout* layoutMain = new QHBoxLayout();
	    layoutMain->addLayout(layoutGraph);
    #ifdef MULTI_STREAM
        layoutMain->addLayout(layoutMenuGraph);
    #endif
        QWidget* widgetGraphTool = new QWidget();
        widgetGraphTool->setLayout(layoutMain);
#ifndef MULTI_MEASURE
#ifndef CERIUM
	    m_tabWidgetCentral->addTab(widgetGraphTool, tr("HISTOGRAMME"));
#endif
#endif
    }
	//**** Onglet des choses en plus pas importante
		
	//Groupe des boutons 
#endif

	/*m_btSequenceur = new QPushButton();
	m_btSequenceur->setObjectName("btSequenceur");
	QLabel* lblSequenceur = new QLabel(tr("Séquenceur"));
	lblSequenceur->setObjectName("lblOutils");*/
	m_btSave = new QPushButton("");
	m_btSave->setObjectName("btSave");
	QLabel* lblSave = new QLabel(tr("Restaurer"));
	lblSave->setObjectName("lblOutils");
	m_btInformation = new QPushButton("");
	m_btInformation->setObjectName("btInformation");
	QLabel* lblInformation = new QLabel(tr("Information"));
	lblInformation->setObjectName("lblOutils");
	m_btParameter = new QPushButton();
	m_btParameter->setObjectName("btParameter");
	QLabel* lblParameter = new QLabel(tr("Paramètres"));
	lblParameter->setObjectName("lblOutils");
	m_btExplorer = new QPushButton();
	m_btExplorer->setObjectName("btExplorer");
	QLabel* lblExplorer = new QLabel(tr("Exploreur"));
	lblExplorer->setObjectName("lblOutils");
	m_btQuit = new QPushButton();
	m_btQuit->setObjectName("btExit");
	QLabel* lblQuit = new QLabel(tr("Quitter"));
	lblQuit->setObjectName("lblOutils");
	/*m_btAnalyseur = new QPushButton();
	m_btAnalyseur->setObjectName("btAnalyseur");
	QLabel* lblAnalyseur = new QLabel("Analyseur");
	lblAnalyseur->setObjectName("lblOutils");*/
	/*m_btHelp = new QPushButton("");
	m_btHelp->setObjectName("btHelp");
	QLabel* lblHelp = new QLabel("Aide");
	lblHelp->setObjectName("lblOutils");*/
	QGridLayout *gridLayoutBtPlus = new QGridLayout();
	
	
	//gridLayoutBtPlus->addWidget(m_btSequenceur, 0, 1, Qt::AlignHCenter);
	//gridLayoutBtPlus->addWidget(lblSequenceur, 1, 1, Qt::AlignTop|Qt::AlignHCenter);
	/*gridLayoutBtPlus->addWidget(m_btParameter, 0, 1, Qt::AlignHCenter);
	gridLayoutBtPlus->addWidget(lblParameter, 1, 1, Qt::AlignTop|Qt::AlignHCenter);*/
	gridLayoutBtPlus->addWidget(m_btExplorer, 0, 0, Qt::AlignHCenter);
	gridLayoutBtPlus->addWidget(lblExplorer, 1, 0, Qt::AlignTop|Qt::AlignHCenter);
	gridLayoutBtPlus->addWidget(m_btSave, 2, 0, Qt::AlignHCenter);
	gridLayoutBtPlus->addWidget(lblSave, 3, 0, Qt::AlignTop|Qt::AlignHCenter);
	gridLayoutBtPlus->addWidget(m_btInformation, 4, 0, Qt::AlignHCenter);
	gridLayoutBtPlus->addWidget(lblInformation, 5, 0, Qt::AlignTop|Qt::AlignHCenter);
	gridLayoutBtPlus->addWidget(m_btQuit, 4, 1, Qt::AlignTop|Qt::AlignHCenter);
	gridLayoutBtPlus->addWidget(lblQuit, 5, 1, Qt::AlignTop|Qt::AlignHCenter);
	/*gridLayoutBtPlus->addWidget(m_btHelp, 4, 0, Qt::AlignHCenter);
	gridLayoutBtPlus->addWidget(lblHelp, 5, 0, Qt::AlignTop|Qt::AlignHCenter);*/
	/*gridLayoutBtPlus->addWidget(m_btAnalyseur, 2, 3, Qt::AlignHCenter);
	gridLayoutBtPlus->addWidget(lblAnalyseur, 3, 3, Qt::AlignTop|Qt::AlignHCenter);*/
	
	QWidget* widgetPlus = new QWidget();
	widgetPlus->setLayout(gridLayoutBtPlus);

	m_tabWidgetCentral->addTab(widgetPlus, " + ");
	
	setConnexion();
	qDebug() << "#### FIN CWinMainControler::CWinMainView" << endl;
}
//SLOT
void CWinMainView::updateDateTime()
{
	//QDateTime dateTime = QDateTime::currentDateTime();
	m_lblDateHeure->setText(QDateTime::currentDateTime().toString());
    
}

//SLOT
void CWinMainView::dataUpdate()
{
	//qDebug() << "#### CWinMainView::dataUpdate()" ;
   // m_mesureLayout->setColumnMinimumWidth(0, m_mesureLayout->cellRect(0, 0).width()  );
    
    
	//clignotage alarm
	if(m_pModel->getEnAlarm())
	{
		m_btAlarm->setChecked(!m_btAlarm->isChecked());
		//qDebug() << "Alarm ON" ;
	}
	else
	{
		m_btAlarm->setChecked(false);
		//qDebug() << "Alarm OFF" ;

	}

	if(m_pModel->getStatusWaterFailure(m_pModel->nGetCurrentStream()))
		m_lblStatusWaterFailure->setText(tr("Défaut d'eau"));
	else
		m_lblStatusWaterFailure->setText("");
		
	if(m_pModel->getStatusSeuil(m_pModel->nGetCurrentStream()))
		m_lblStatusSeuil->setText(tr("Seuil dépassé"));
	else
		m_lblStatusSeuil->setText("");

    for(int index = 0; index < m_pModel->getNbStream(); ++index)
    {
        if(!m_pModel->getVoieActive(index))
        {
            m_listLblStatusVoie[index]->setText(tr("En arrêt"));
        }
        else if(    m_pModel->getStatusWaterFailure(index)
            || m_pModel->getStatusSeuil(index))
     //       || m_pModel->getStreamStatus(index))
        {
            m_listLblStatusVoie[index]->setText(tr("En défaut"));
        }
        else
        {
            m_listLblStatusVoie[index]->setText("");
        }
    }
    

	//Trouver la première voie précédente active
	int i = m_pModel->nGetPreviousStream();
	
	qDebug() << i << "  " << m_listLblMesure;
    for(int j = 0; j<m_pModel->nGetNombreMesure(); ++j)
    {
		qDebug() << "&&&&&&&&&&&&&& "<< i << "  " << j;

        m_listLblMesure[i][j]->setText(QString(" ")+ m_pModel->getMesureValueLbl(i, j));
        m_listLblValMesure[i][j]->setText(m_pModel->getMesureValue(i, j) + m_pModel->getMesureValueUnit(i, j));
        float fMesure = m_pModel->getMesureValue(i, j).toFloat();
        //float fMesure = (double(rand())/RAND_MAX)*m_pModel->getBoutPlageMax();
        QString sMesureUnit = m_pModel->getMesureValueUnit(i, j);
        addMeasureToGraph(i, fMesure, sMesureUnit);
		#ifdef MAGNESIUM
			++j; //ne pas afficher la deuxième mesure
		#endif 
    }
	
	qDebug() << "Voie en cours " << m_pModel->nGetCurrentStream();
    
	if(m_pModel->nGetCurrentStream()<6 && !m_pModel->getStatusPeriodic(m_pModel->nGetCurrentStream()))
    {
		m_lblCurrentStream->setText(QString(tr("Voie ")) + m_pModel->getCurrentStream());
		m_lblCurrentStreamDiag->setText(QString(tr("Voie ")) + m_pModel->getCurrentStream());
    }
    else if(m_pModel->nGetCurrentStream() == 99)
    {
        m_lblCurrentStream->setText(QString(tr("Décompte ")));
        m_lblCurrentStreamDiag->setText(QString(""));
    }
    else
    {
#ifdef KMNO4
		m_lblCurrentStream->setText(m_pModel->getNbCycleAvantBlanc() + QString(tr(" cycle avant le blanc")) );
		m_lblCurrentStreamDiag->setText(m_pModel->getNbCycleAvantBlanc() + QString(tr(" cycle avant le blanc")) );
#else
		m_lblCurrentStream->setText(m_pModel->getNbCycleAvantBlanc() + QString(tr(" cycle avant le nettoyage")) );
		m_lblCurrentStreamDiag->setText(m_pModel->getNbCycleAvantBlanc() + QString(tr(" cycle avant le nettoyage")) );
#endif
    }


    m_lblCurrentStep->setText(QString(tr("Pas n°:")) + m_pModel->getCurrentStep());
	m_lblTotalStep->setText(QString(tr("Sur :")) +m_pModel->getTotalStep());
	m_lblNameStep->setText(m_pModel->getNameStep());
	m_lblStatusAnalyseur->setText(m_pModel->getEtatAnalyseur());
	
	
	//*** Onglet Diagnostic
    if(m_tabWidgetCentral->currentIndex()==1)
    {
	    m_btTemperatureCuve->setText(m_pModel->getTemperatureCuve());
	    m_btPressionEau->setText(m_pModel->getPressionEau());
	    m_btMesureOptique->setText(m_pModel->getMesureOptique());
	    m_btOpticalGain->setText(m_pModel->getOpticalGainValue());
	    m_btOpticalMeasurement->setText(m_pModel->getOpticalMeasurementValue());
	    m_btZeroOpticalMeasurement->setText(m_pModel->getZeroOpticalMeasurementValue());
	    m_btAbsorbanceValue->setText(m_pModel->getAbsorbanceValueValue());
        
        m_lblCurrentStepDiag->setText(QString(tr("Pas n°:")) + m_pModel->getCurrentStep());
	    m_lblTotalStepDiag->setText(QString(tr("Sur :")) +m_pModel->getTotalStep());
	    m_lblNameStepDiag->setText(m_pModel->getNameStep());
    }
	//qDebug() << "#### FIN CWinMainView::dataUpdate()" ;

    //tiens la fenêtre bien cadré
    update();
	
}
void CWinMainView::addMeasureToGraph(int arg_numStream, float arg_fMesure, const QString& arg_sMesureUnit)
{
	if(m_pModel->getFlagEndCycle())
	{
        qDebug() << "int arg_numStream, float arg_fMesure, const QString& arg_sMesureUnit"
                 <<  arg_numStream << " " <<arg_fMesure<< " " << arg_sMesureUnit;
		//ax+b = y ou : 
		//a = -SCENE_HEIGHT/x quand x=concentration max, x est la concentration et y = SCENE_HEIGHT quand x=0
		float yPrecedent;
		float yActuel;
		QString sDatePrecedente;
		QString sHeurePrecedente;
		QString sMesurePrecedente;
		QString sDateActuel;
		QString sHeureActuel;
		QString sMesureActuel;
		/*float heightPrecedent;
		float heightActuel;*/
		float a;
		//Pour les échelle dynamique
		float concentrationMax; //aucun rapport avec les coordonnée, sert à calculer yActuel de la dernière mesure
		float fCorrectionY=1;
		
		////(a décomenter pour une echelle qui s'ajuste en auto)calcule de concentrationMax 
		//a = m_tabMesureMax[0];
		//m_tabMesureMax[0] = arg_fMesure;
		//concentrationMax = arg_fMesure;
		//for(int i=1; i<NB_MESURE_GRAPH; ++i)
		//{
		//	tmp = m_tabMesureMax[i];
		//	m_tabMesureMax[i] = a;
		//	a = tmp;
		//	if(concentrationMax < m_tabMesureMax[i])
		//		concentrationMax = m_tabMesureMax[i];
		//}
		if(arg_fMesure > m_pModel->getBoutPlageMax(arg_numStream)) 
            arg_fMesure = m_pModel->getBoutPlageMax(arg_numStream);
		concentrationMax = m_pModel->getBoutPlageMax(arg_numStream); //(à commenter pour repasser ç=à une echel ajusté en auto)
		concentrationMax = concentrationMax + (concentrationMax* (0.25));
		concentrationMax = ceil(concentrationMax);
							
		
		m_lblConcentrationMax->setText(QString::number(concentrationMax));
		m_lblConcentrationMoy->setText(QString::number(ceil(concentrationMax/2)));
				
		a = (-SCENE_HEIGHT)/concentrationMax;
		qDebug() << a;
		yActuel = a*arg_fMesure+SCENE_HEIGHT;
		

		qDebug() << m_listDataGraph.at(arg_numStream).count();
		for(int i=m_listDataGraph.at(arg_numStream).count()-1; i>=0; --i)
		{
			
			if(i == m_listDataGraph.at(arg_numStream).count()-1)
			{
				sDatePrecedente = m_listDataGraph.at(arg_numStream).at(i)->getDate();
				sHeurePrecedente = m_listDataGraph.at(arg_numStream).at(i)->getHeure();
				sMesurePrecedente = m_listDataGraph.at(arg_numStream).at(i)->getMesure();
				m_listDataGraph.at(arg_numStream).at(i)->setDate(QDate::currentDate().toString(Qt::ISODate));
				m_listDataGraph.at(arg_numStream).at(i)->setHeure(QTime::currentTime().toString("hh:mm:ss"));
				m_listDataGraph.at(arg_numStream).at(i)->setMesure(QString::number(arg_fMesure, 'f', 2)+ " " + arg_sMesureUnit);
				
				yPrecedent = m_listDataGraph.at(arg_numStream).at(i)->rect().y();
				m_listDataGraph.at(arg_numStream).at(i)->setRect(m_listDataGraph.at(arg_numStream).at(i)->rect().x(), yActuel, m_listDataGraph.at(arg_numStream).at(i)->rect().width(), SCENE_HEIGHT-yActuel);
				
			}
			else
			{
				sDateActuel = m_listDataGraph.at(arg_numStream).at(i)->getDate();
				sHeureActuel = m_listDataGraph.at(arg_numStream).at(i)->getHeure();
				sMesureActuel = m_listDataGraph.at(arg_numStream).at(i)->getMesure();
				m_listDataGraph.at(arg_numStream).at(i)->setDate(sDatePrecedente);
				m_listDataGraph.at(arg_numStream).at(i)->setHeure(sHeurePrecedente);
				m_listDataGraph.at(arg_numStream).at(i)->setMesure(sMesurePrecedente);
				
				yActuel = m_listDataGraph.at(arg_numStream).at(i)->rect().y();
				yPrecedent = a* (yPrecedent-SCENE_HEIGHT)/m_fCoefAOld + SCENE_HEIGHT;
				m_listDataGraph.at(arg_numStream).at(i)->setRect(m_listDataGraph.at(arg_numStream).at(i)->rect().x()
													, yPrecedent
													, m_listDataGraph.at(arg_numStream).at(i)->rect().width()
													, SCENE_HEIGHT-(yPrecedent));
				yPrecedent = yActuel;
				
				sMesurePrecedente = sMesureActuel;
				sDatePrecedente = sDateActuel;
				sHeurePrecedente = sHeureActuel;
			}
		}

		m_fCoefAOld = a;
        m_pControler->askRepaintGraph(arg_numStream);
	}
}
void CWinMainView::repaintGraph(int arg_numStream)
{
    m_lblInfoGraph->setText(QString(tr("voie ")) 
                          + QString::number(arg_numStream+1));
    for(int i=0; i<m_listGraphicsRectItem.count(); ++i)
	{
       m_listGraphicsRectItem.at(i)->setDate(m_listDataGraph.at(arg_numStream).at(i)->getDate());
       m_listGraphicsRectItem.at(i)->setHeure(m_listDataGraph.at(arg_numStream).at(i)->getHeure());
       m_listGraphicsRectItem.at(i)->setMesure(m_listDataGraph.at(arg_numStream).at(i)->getMesure());
       m_listGraphicsRectItem.at(i)->setRect(m_listDataGraph.at(arg_numStream).at(i)->rect().x()
                                            ,m_listDataGraph.at(arg_numStream).at(i)->rect().y()
                                            ,m_listDataGraph.at(arg_numStream).at(i)->rect().width()
                                            ,m_listDataGraph.at(arg_numStream).at(i)->rect().height());
    }
}
void CWinMainView::setConnexion()
{
	QTimer *m_timer = new QTimer(this);
	connect(m_timer, SIGNAL(timeout()), this, SLOT(updateDateTime()));
	m_timer->start(1000);

	//Bt onglet principale
	connect(m_btPlayPause, SIGNAL(clicked()), m_pControler, SLOT(btPlayPausePressed()));
	connect(m_btStop, SIGNAL(clicked()), m_pControler, SLOT(btStopPressed()));
	connect(m_btStopEndCycle, SIGNAL(clicked()), m_pControler, SLOT(btStopEndCylePressed()));
	connect(m_btNext, SIGNAL(clicked()), m_pControler, SLOT(btNextPressed()));
	connect(m_btAlarm, SIGNAL(clicked()), m_pControler, SLOT(btAlarmPressed()));
	CPushButton* btTmp;
	foreach(btTmp, m_listBtDetail)
	{	
		connect(btTmp, SIGNAL(clicked(int)), m_pControler, SLOT(btDetailPressed(int)));
	}

	//Bt onglet menu outil
	connect(m_btMeasureCard, SIGNAL(clicked()), m_pControler, SLOT(btMeasureCardPressed()));
	/*connect(m_btEvPump, SIGNAL(clicked()), m_pControler, SLOT(btEVPompePressed()));
	connect(m_btExternalCard, SIGNAL(clicked()), m_pControler, SLOT(btExternalCardPressed()));*/
	//connect(m_btAnalyseur, SIGNAL(clicked()), m_pControler, SLOT(btDetailPressed())); /**MODIF A FAIRE**/
	connect(m_btMaintenance, SIGNAL(clicked()), m_pControler, SLOT(btMaintenancePressed()));

	//Bt onglet plus
	connect(m_btExplorer, SIGNAL(clicked()), m_pControler, SLOT(btExplorerPressed()));
	connect(m_btInformation, SIGNAL(clicked()), m_pControler, SLOT(btInformationPressed()));
	connect(m_btSequenceur, SIGNAL(clicked()), m_pControler, SLOT(btSequenceurPressed()));
	connect(m_btCopyLogFiles, SIGNAL(clicked()), m_pControler, SLOT(btCopyLogFilesPressed()));
	connect(m_btParameter, SIGNAL(clicked()), m_pControler, SLOT(btParameterPressed()));
	connect(m_btSave, SIGNAL(clicked()), m_pControler, SLOT(btSavePressed()));
	connect(m_btQuit, SIGNAL(clicked()), m_pControler, SLOT(btQuitPressed()));
	
	connect(m_btNextGraph, SIGNAL(clicked()), m_pControler, SLOT(btNextGraphPressed()));
	connect(m_btPrevGraph, SIGNAL(clicked()), m_pControler, SLOT(btPrevGraphPressed()));

    
	//Event des onglets
	connect(m_tabWidgetCentral, SIGNAL(currentChanged(int)), m_pControler, SLOT(tabChanged(int)));

}