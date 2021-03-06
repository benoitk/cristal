#include "header.h"
#include "header_ihm.h"

#ifdef RES_640_480
#define SCENE_WIDTH 500//440
#define SCENE_HEIGHT 190//180
#else
#define SCENE_WIDTH 440
#define SCENE_HEIGHT 180
#endif
CWinMainView::CWinMainView(CWinMainControler* argoControler, QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	qDebug() << "#### CWinMainControler::CWinMainView" << endl;

	m_pControler = argoControler;

	for(int i=0; i<NB_MESURE_GRAPH; ++i)
		m_tabMesureMax[i]=0;
	m_fCoefAOld = 1;
}

void CWinMainView::init()
{
	qDebug() << "#### CWinMainControler::init" << endl;

	m_tabWidgetCentral = new QTabWidget(); //Pas de parent, setCentralWidget l'attribura à la fenêtre
	setCentralWidget(m_tabWidgetCentral);

	//***HISTOGRAMME
	QGraphicsScene* scene = new QGraphicsScene();
#ifndef RES_640_480
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
	m_lblConcentrationMax = new QLabel("300");
	m_lblConcentrationMax->setObjectName("lblGraphUnit");
	m_lblConcentrationMin = new QLabel("0");
	m_lblConcentrationMin->setObjectName("lblGraphUnit");
	m_lblConcentrationMoy = new QLabel("150");
	m_lblConcentrationMoy->setObjectName("lblGraphUnit");
	QLabel* lblInfo = new QLabel();
	lblInfo->setObjectName("lblGraphInfo");
	
	scene->addWidget(m_lblConcentrationMax)->setPos(SCENE_WIDTH-13,-10);
	scene->addWidget(m_lblConcentrationMoy)->setPos(SCENE_WIDTH-13,(SCENE_HEIGHT/2)-10);
	scene->addWidget(m_lblConcentrationMin)->setPos(SCENE_WIDTH-13,SCENE_HEIGHT-10);
	QGraphicsProxyWidget* proxyLblInfo= new QGraphicsProxyWidget();
	proxyLblInfo->setWidget(lblInfo);
	//proxyLblInfo = scene->addWidget(lblInfo)
	proxyLblInfo->resize(100, 60);
	proxyLblInfo->setPos(SCENE_WIDTH - 140, -20);
	proxyLblInfo->setVisible(false);
	
	int i;
	for(i=0; i<SCENE_WIDTH-20; i=i+10)
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
	scene->addLine(i,SCENE_HEIGHT+3, i,SCENE_HEIGHT-3, pen);
	pen.setColor(Qt::green);
	scene->addItem(proxyLblInfo);
	QGraphicsView* view= new QGraphicsView(scene);
	QHBoxLayout* graphLayout = new QHBoxLayout();
	graphLayout->addWidget(view);
	QWidget* widgetGraph = new QWidget();
	widgetGraph->setLayout(graphLayout);
	//FIN HISTGRAMME

	//***Partis des vois/mesure
	///*QByteArray encodedString = "磷酸盐";
	//QTextCodec *codec = QTextCodec::codecForName("Big5-HKSCS");
	//QString string = codec->toUnicode(encodedString);*/
	//QTextCodec::setCodecForCStrings(QTextCodec::codecForName("UTF-8"));
	//QApplication::setFont(QFont("GJJHuangCao-S09S"));
	////m_lblMesure = new QLabel("\xce\xd2\xca\xc7\xba\xba\xd7\xd6");
	//const char * str = "\xce\xd2\xca\xc7\xba\xba\xd7\xd6";
	//QString a= str;
    
	qDebug() << "#### CWinMainControler::init 0" << endl;
    
	QVBoxLayout* centralLayout = new QVBoxLayout();
	for(int i=0; i<m_pModel->getNbStream(); ++i)
	{
	qDebug() << "#### CWinMainControler::init 1 " << i <<endl;

		for(int j=0; j<m_pModel->getNbMeasure(i); ++j)
		{
			qDebug() << "#### CWinMainControler::init 2 " << j <<endl;
			QLabel* lblMesure = new QLabel(tr("MESURE"));
			lblMesure->setObjectName("lblMesure");
			m_listLblMesure.append(lblMesure);
			
			QLabel* lblValMesure = new QLabel("VAL MESURE");
			lblValMesure->setObjectName("lblValMesure");
			m_listLblValMesure.append(lblValMesure);
			
			CPushButton* btDetail = new CPushButton(i);
			btDetail->setObjectName("btDetail");
			m_listBtDetail.append(btDetail);
			
			QHBoxLayout* mesureLayout = new QHBoxLayout(); //Pas de parent, setLayout affect m_groupBoxCentral en parent
			mesureLayout->addWidget(btDetail,0, Qt::AlignLeft);
			mesureLayout->addWidget(lblMesure,0, Qt::AlignLeft);//m_lblValMesure);
			mesureLayout->addWidget(lblValMesure,50 , Qt::AlignLeft);
			centralLayout->addLayout(mesureLayout); 

		}
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
#ifndef RES_640_480
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
	
#ifdef RES_640_480
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
	//verticalLayout->addWidget(m_btNext);


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
	QGridLayout* gridLayout = new QGridLayout();
	gridLayout->addWidget(new QLabel(tr("Température Cuve")), 0,0);
	gridLayout->addWidget(m_btTemperatureCuve, 0, 1);
	gridLayout->addWidget(new QLabel(tr("°C")), 0,2);
	gridLayout->addWidget(new QLabel(tr("Pression d'eau")), 1,0);
	gridLayout->addWidget(m_btPressionEau, 1, 1);
	gridLayout->addWidget(new QLabel(tr("V")), 1,2);
	gridLayout->addWidget(new QLabel(tr("Mesure optique direct")), 2,0);
	gridLayout->addWidget(m_btMesureOptique, 2, 1);
	gridLayout->addWidget(new QLabel(tr("Pts")), 2,2);
	gridLayout->addWidget(new QLabel(m_pModel->getOpticalGainLbl()), 3,0);
	gridLayout->addWidget(m_btOpticalGain, 3, 1);
	gridLayout->addWidget(new QLabel(m_pModel->getOpticalGainUnit()), 3,2);
	gridLayout->addWidget(new QLabel(m_pModel->getOpticalMeasurementLbl()), 4,0);
	gridLayout->addWidget(m_btOpticalMeasurement, 4, 1);
	gridLayout->addWidget(new QLabel(m_pModel->getOpticalMeasurementUnit()), 4,2);
	gridLayout->addWidget(new QLabel(m_pModel->getZeroOpticalMeasurementLbl()), 5,0);
	gridLayout->addWidget(m_btZeroOpticalMeasurement, 5, 1);
	gridLayout->addWidget(new QLabel(m_pModel->getZeroOpticalMeasurementUnit()), 5,2);
	
	

	widgetDiag->setLayout(gridLayout);
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
	QLabel* lblSequenceur = new QLabel(tr("Séquenceur"));
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
#ifdef RES_640_480
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

#ifndef RES_640_480
	//*** Onglet HISTOGRAMME
	m_tabWidgetCentral->addTab(widgetGraph, tr("HISTOGRAMME"));
	
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
	qDebug() << "#### CWinMainView::dataUpdate()" ;

	//*** onglet Mesure
	/*m_pModel->getRun();
	m_pModel->getStop();
	m_pModel->getPause();*/

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

	if(m_pModel->getStatusWaterFailure())
		m_lblStatusWaterFailure->setText(tr("Défaut d'eau"));
	else
		m_lblStatusWaterFailure->setText("");
		
	if(m_pModel->getStatusSeuil())
		m_lblStatusSeuil->setText(tr("Seuil dépassé"));
	else
		m_lblStatusSeuil->setText("");

	//CStreamModel* pStream;
	//CMesureModel* pMesure;
	float fMesure=0;
	QString sMesureUnit=0;
	//foreach(pStream, m_pModel->getVectorStream())
	//{
	//	foreach(pMesure, pStream->getVectorMesure())
	//	{
	//		m_lblMesure->setText(QString(" ") +pMesure->getName());// + QString(" ") + QString::number(pMesure->getValeur(), 'g', 2) + pMesure->getUnite());
	//		m_lblMesureGraph->setText(" "+pMesure->getName()+tr(" en ")+ pMesure->getUnite());// + QString(" ") + QString::number(pMesure->getValeur(), 'g', 2) + pMesure->getUnite());
	//		m_lblValMesure->setText(QString::number(pMesure->getValeur(), 'f', 2) + pMesure->getUnite());
	//		fMesure=pMesure->getValeur();
	//		sMesureUnit=pMesure->getUnite();
	//	}
	//}
			qDebug() << QString::fromUtf16("è€");//磷酸盐") + "2";

	for(int i=0; i<m_pModel->getNbStream(); ++i)
	{
		for(int j=0; j<m_pModel->getNbMeasure(i); ++j)
		{
            m_listLblMesure[i+j]->setText(QString(" ") + QString::fromUtf8("磷酸盐"));//m_pModel->getMesureValueLbl(i, j));
			qDebug() << QString::fromUtf8("磷酸盐") + "1";
            m_listLblValMesure[i+j]->setText(QString::number(m_pModel->getMesureValue(i, j), 'f', 2) + m_pModel->getMesureValueUnit(i, j));
			fMesure = m_pModel->getMesureValue(i, j);
			sMesureUnit = m_pModel->getMesureValueUnit(i, j);
		}
	} 
	//if(!m_pModel->getEnPeriodic()) repaintGraph(fMesure+(double(rand())/RAND_MAX)*m_pModel->getBoutPlageMax(), sMesureUnit); //Pour tester le graph
	//if(!m_pModel->getEnPeriodic()) repaintGraph(fMesure, sMesureUnit);
	//if(!m_pModel->getEnPeriodic()) repaintGraph(150, sMesureUnit);
	//if(m_pModel->getEnPeriodic()) repaintGraph(200, sMesureUnit);
	repaintGraph(fMesure, sMesureUnit);
	//m_lblStatusAnalyseur;
	if(!m_pModel->getStatusPeriodic())
		m_lblCurrentStream->setText(QString(tr("Voie ")) + m_pModel->getCurrentStream());
	else
		m_lblCurrentStream->setText(m_pModel->getNbCycleAvantBlanc() + QString(tr(" cycle avant le blanc")) );

	m_lblCurrentStep->setText(QString::number(m_pModel->getCurrentStep()));
	m_lblTotalStep->setText(QString::number(m_pModel->getTotalStep()));
	m_lblNameStep->setText(m_pModel->getNameStep());
	m_lblStatusAnalyseur->setText(m_pModel->getEtatAnalyseur());
	
	
	//*** Onglet Diagnostic
	m_btTemperatureCuve->setText(QString::number(m_pModel->getTemperatureCuve(), 'f', 2));
	m_btPressionEau->setText(QString::number(m_pModel->getPressionEau(), 'f', 2));
	m_btMesureOptique->setText(QString::number(m_pModel->getMesureOptique(), 'f', 2));
	m_btOpticalGain->setText(QString::number(m_pModel->getOpticalGainValue(), 'f', 2));
	m_btOpticalMeasurement->setText(QString::number(m_pModel->getOpticalMeasurementValue(), 'f', 2));
	m_btZeroOpticalMeasurement->setText(QString::number(m_pModel->getZeroOpticalMeasurementValue(), 'f', 2));
	//qDebug() << "#### FIN CWinMainView::dataUpdate()" ;
	
}
void CWinMainView::repaintGraph(float arg_fMesure, QString arg_sMesureUnit)
{
	if(m_pModel->getFlagEndCycle())
	{
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
		if(arg_fMesure > m_pModel->getBoutPlageMax()) arg_fMesure = m_pModel->getBoutPlageMax();
		concentrationMax = m_pModel->getBoutPlageMax(); //(à commenter pour repasser ç=à une echel ajusté en auto)
		concentrationMax = concentrationMax + (concentrationMax* (0.25));
		concentrationMax = ceil(concentrationMax);
							
		
		m_lblConcentrationMax->setText(QString::number(concentrationMax));
		m_lblConcentrationMoy->setText(QString::number(ceil(concentrationMax/2)));
				
		a = (-SCENE_HEIGHT)/concentrationMax;
		qDebug() << a;
		yActuel = a*arg_fMesure+SCENE_HEIGHT;
		

		qDebug() << m_listGraphicsRectItem.count();
		for(int i=m_listGraphicsRectItem.count()-1; i>=0; --i)
		{
			
			if(i == m_listGraphicsRectItem.count()-1)
			{
				sDatePrecedente = m_listGraphicsRectItem.at(i)->getDate();
				sHeurePrecedente = m_listGraphicsRectItem.at(i)->getHeure();
				sMesurePrecedente = m_listGraphicsRectItem.at(i)->getMesure();
				m_listGraphicsRectItem.at(i)->setDate(QDate::currentDate().toString(Qt::ISODate));
				m_listGraphicsRectItem.at(i)->setHeure(QTime::currentTime().toString("hh:mm:ss"));
				m_listGraphicsRectItem.at(i)->setMesure(QString::number(arg_fMesure, 'f', 2)+ " " + arg_sMesureUnit);
				
				yPrecedent = m_listGraphicsRectItem.at(i)->rect().y();
				m_listGraphicsRectItem.at(i)->setRect(m_listGraphicsRectItem.at(i)->rect().x(), yActuel, m_listGraphicsRectItem.at(i)->rect().width(), SCENE_HEIGHT-yActuel);
				
			}
			else
			{
				sDateActuel = m_listGraphicsRectItem.at(i)->getDate();
				sHeureActuel = m_listGraphicsRectItem.at(i)->getHeure();
				sMesureActuel = m_listGraphicsRectItem.at(i)->getMesure();
				m_listGraphicsRectItem.at(i)->setDate(sDatePrecedente);
				m_listGraphicsRectItem.at(i)->setHeure(sHeurePrecedente);
				m_listGraphicsRectItem.at(i)->setMesure(sMesurePrecedente);
				
				yActuel = m_listGraphicsRectItem.at(i)->rect().y();
				yPrecedent = a* (yPrecedent-SCENE_HEIGHT)/m_fCoefAOld + SCENE_HEIGHT;
				m_listGraphicsRectItem.at(i)->setRect(m_listGraphicsRectItem.at(i)->rect().x()
													, yPrecedent
													, m_listGraphicsRectItem.at(i)->rect().width()
													, SCENE_HEIGHT-(yPrecedent));
				yPrecedent = yActuel;
				
				sMesurePrecedente = sMesureActuel;
				sDatePrecedente = sDateActuel;
				sHeurePrecedente = sHeureActuel;
			}
		}

		m_fCoefAOld = a;
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
	

	//Event des onglets
	connect(m_tabWidgetCentral, SIGNAL(currentChanged(int)), m_pControler, SLOT(tabChanged(int)));

}