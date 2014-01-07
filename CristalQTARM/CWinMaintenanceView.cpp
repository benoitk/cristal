#include "CWinMaintenanceView.h"
#include "CWinMaintenanceControler.h"
#include "CWinMaintenanceModel.h"

#include "header_qt.h"

CWinMaintenanceView::CWinMaintenanceView(CWinMaintenanceControler* argpControler, QWidget *parent, Qt::WindowFlags flags)
    :QWidget(parent, flags)
{
	m_pControler = argpControler;
}
void CWinMaintenanceView::init()
{
	/*int toto = 10;
	bCopyFile(szGetFullPathName(_T("ConfigAnalyseur.ini"),szText),SZ_FIC_TEMP,FALSE);
	while(toto-->0){Sleep(1000);}*/
	qDebug() << "#### CWinMaintenanceView::init" ;
	m_tabWidgetCentral = new QTabWidget(); //Pas de parent, setCentralWidget l'attribura à la fenêtre
	connect(m_tabWidgetCentral, SIGNAL(currentChanged(int)), m_pControler, SLOT(tabChanged(int)));
   
	QHBoxLayout* layoutGlobal = new QHBoxLayout(); 
    layoutGlobal->setContentsMargins ( 0, 0, 0, 0 );
    layoutGlobal->addWidget(m_tabWidgetCentral);
	this->setLayout(layoutGlobal);


	//***Tab Maintenance
#ifdef CALIBRATIONS_INDEPENDANTE
#ifdef CERIUM
	for(int i=0; i<m_pModel->getNbStream()-1; ++i) //pas de calib v4 sur le cerium 4V
#else
	for(int i=0; i<m_pModel->getNbStream(); ++i)
#endif
#endif
	{
		//Boutons d'exécution des cycles de maintenance
		QPushButton* btExecuteCalib = new QPushButton();
		connect(btExecuteCalib, SIGNAL(clicked()), m_pControler, SLOT(btExecuteCalibPressed()));
		btExecuteCalib->setObjectName("btExecuteMaintenance");
		m_listBtExecuteCalib.append(btExecuteCalib);

		QPushButton* btExecuteCalibInLine = new QPushButton();
		connect(btExecuteCalibInLine, SIGNAL(clicked()), m_pControler, SLOT(btExecuteCalibInLinePressed()));
		btExecuteCalibInLine->setObjectName("btExecuteMaintenance");
		m_listBtExecuteCalibInLine.append(btExecuteCalibInLine);

		QPushButton* btExecuteZero = new QPushButton();
		connect(btExecuteZero, SIGNAL(clicked()), m_pControler, SLOT(btExecuteZeroPressed()));
		btExecuteZero->setObjectName("btExecuteMaintenance");
		m_listBtExecuteZero.append(btExecuteZero);

		QPushButton* btExecuteCleanup = new QPushButton();
		connect(btExecuteCleanup, SIGNAL(clicked()), m_pControler, SLOT(btExecuteCleanupPressed()));
		btExecuteCleanup->setObjectName("btExecuteMaintenance");
		m_listBtExecuteCleanup.append(btExecuteCleanup);

		QLabel* lblCalib = new QLabel(tr("*Etalonnage")); 
		lblCalib->setObjectName("lblMaintenance");
		m_listLblCalib.append(lblCalib);

		QLabel* lblCalibInLine = new QLabel(tr("*Etalonnage en ligne"));
		lblCalibInLine->setObjectName("lblMaintenance");
		m_listLblCalibInLine.append(lblCalibInLine);

		QLabel* lblZero = new QLabel(tr("*Etalonnage zéro"));
		lblZero->setObjectName("lblMaintenance");
		m_listLblZero.append(lblZero);

		QLabel* lblCleanup = new QLabel(tr("*Mesure manuelle"));
		lblCleanup->setObjectName("lblMaintenance");
		m_listLblCleanup.append(lblCleanup);
		
		//Centre de la fen^tre
		QFormLayout* layoutCentral = new QFormLayout();
		{
			/*toto = 10;
			while(toto-->0){Sleep(1000);}*/
			TCHAR szText[260];

			bCopyFile(szGetFullPathName(_T("ConfigAnalyseur.ini"),szText),SZ_FIC_TEMP,FALSE);

			//Zero
			dwGetPrivateProfileString(_T("Config"), _T("ZeroCyclePresent"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
			QString sLigneIni = QString::fromUtf16 ((const ushort *)szText);
			QStringList sListLigneIni = sLigneIni.split("|");
			if (sListLigneIni.count() > 1 && sListLigneIni.at(2).toInt())
			{
				dwGetPrivateProfileString(_T("Config"), _T("ZeroCycleLabel"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
				sLigneIni = QString::fromUtf16 ((const ushort *)szText);
				sListLigneIni = sLigneIni.split("|");
				lblZero->setText(sListLigneIni.at(2));
				layoutCentral->addRow(lblZero, btExecuteZero);
     		}
			//Calibration
			dwGetPrivateProfileString(_T("Config"), _T("CalibrageCyclePresent"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
			sLigneIni = QString::fromUtf16 ((const ushort *)szText);
			sListLigneIni = sLigneIni.split("|");
			if (sListLigneIni.count() > 1 && sListLigneIni.at(2).toInt())
			{
				dwGetPrivateProfileString(_T("Config"), _T("CalibrageCycleLabel"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
				sLigneIni = QString::fromUtf16 ((const ushort *)szText);
				sListLigneIni = sLigneIni.split("|");
#ifdef CERIUM
				if(i == 0)
					lblCalib->setText("Calibration A1 et Cat");
				else
					lblCalib->setText("Calibration A" + QString::number(i+1));
#else
				lblCalib->setText(sListLigneIni.at(2));
#endif
				layoutCentral->addRow(lblCalib, btExecuteCalib);
			}
			//Calibration en ligne
			dwGetPrivateProfileString(_T("Config"), _T("CalibrageInLineCyclePresent"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
			sLigneIni = QString::fromUtf16 ((const ushort *)szText);
			sListLigneIni = sLigneIni.split("|");
			if (sListLigneIni.count() > 1 && sListLigneIni.at(2).toInt())
			{
				dwGetPrivateProfileString(_T("Config"), _T("CalibrageInLineCycleLabel"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
				sLigneIni = QString::fromUtf16 ((const ushort *)szText);
				sListLigneIni = sLigneIni.split("|");
				lblCalibInLine->setText(sListLigneIni.at(2));
				layoutCentral->addRow(lblCalibInLine, btExecuteCalibInLine);
			}
			//Mesure manuel
			dwGetPrivateProfileString(_T("Config"), _T("CleanupCyclePresent"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
			sLigneIni = QString::fromUtf16 ((const ushort *)szText);
			sListLigneIni = sLigneIni.split("|");
			if (sListLigneIni.count() > 1 && sListLigneIni.at(2).toInt())
			{
				dwGetPrivateProfileString(_T("Config"), _T("CleanupCycleLabel"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
				sLigneIni = QString::fromUtf16 ((const ushort *)szText);
				sListLigneIni = sLigneIni.split("|");
				lblCleanup->setText(sListLigneIni.at(2));
				layoutCentral->addRow(lblCleanup, btExecuteCleanup); //Mesure manuel
			}
		}

		//info du cycle
		QLabel* lblCurrentStep = new QLabel("");
		lblCurrentStep->setObjectName("lblCurrentStep");
		m_listLblCurrentStep.append(lblCurrentStep);
		
		QLabel* lblNameStep = new QLabel(tr("Pas de cycle en cours"));
		lblNameStep->setObjectName("lblNameStep");
		m_listLblNameStep.append(lblNameStep);

		QHBoxLayout* horizontalLayout = new QHBoxLayout();
		horizontalLayout->setObjectName("horizontalLayout");
		horizontalLayout->addWidget(lblNameStep, 85);
		horizontalLayout->addWidget(lblCurrentStep, 15); 
		//horizontalLayout->addWidget(m_lblTotalStep, 15); 

		QVBoxLayout* layoutGauche = new QVBoxLayout();
		layoutGauche->addStretch(0);
		layoutGauche->addLayout(layoutCentral); 
		layoutGauche->addStretch(0);
		layoutGauche->addLayout(horizontalLayout); 

		//Bouttons de droite
		QPushButton* btStop = new QPushButton();
		btStop->setObjectName("btStop");
		m_listBtStop.append(btStop);
		connect(btStop, SIGNAL(clicked()), m_pControler, SLOT(btStopPressed()));
		
		QVBoxLayout* layoutMenu = new QVBoxLayout();
		layoutMenu->addStretch(0);
		layoutMenu->addWidget(btStop, Qt::AlignBottom	);
#ifdef CALIBRATIONS_INDEPENDANTE
		if(i == 0) 
#endif
		{
			m_btBack = new QPushButton();
			m_btBack->setObjectName("btBack");
			connect(m_btBack, SIGNAL(clicked()), m_pControler, SLOT(btBackPressed()));
			layoutMenu->addWidget(m_btBack, Qt::AlignBottom	);
		}
		//Assemblage partis gauche et droite
		QHBoxLayout* layoutMain = new QHBoxLayout();
		layoutMain->addLayout(layoutGauche, 90); 
		layoutMain->addLayout(layoutMenu, 10); 
		
		QWidget* widgetMain = new QWidget();
		widgetMain->setLayout(layoutMain);
		//:Nom de l'onglet à laisser en maj pour toutes les trads
#ifdef CALIBRATIONS_INDEPENDANTE
		if(i == 0) 
#ifdef CERIUM
			m_tabWidgetCentral->addTab(widgetMain, tr("MAINTENANCE VOIE 1 et 4"));
#else
			m_tabWidgetCentral->addTab(widgetMain, tr("MAINTENANCE VOIE ") + QString::number(i+1));
#endif	
		else
			m_tabWidgetCentral->addTab(widgetMain, tr("VOIE ") + QString::number(i+1));
#else
		m_tabWidgetCentral->addTab(widgetMain, tr("MAINTENANCE"));
#endif
	}

	//*** Tab Diagnostique
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
    int row = 0;
#ifndef COULEUR
	gridLayout->addWidget(new QLabel(tr("Température Cuve")), row,0);
	gridLayout->addWidget(m_btTemperatureCuve, row, 1);
	gridLayout->addWidget(new QLabel(tr("°C")), row++,2);
#endif
	gridLayout->addWidget(new QLabel(tr("Préssion d'eau")), row,0);
	gridLayout->addWidget(m_btPressionEau, row, 1);
	gridLayout->addWidget(new QLabel(tr("V")), row++,2);
	gridLayout->addWidget(new QLabel(tr("Mesure optique")), row,0);
	gridLayout->addWidget(m_btMesureOptique, row, 1);
	gridLayout->addWidget(new QLabel(tr("pts")), row++,2);
	gridLayout->addWidget(new QLabel(m_pModel->getOpticalGainLbl()), row,0);
	gridLayout->addWidget(m_btOpticalGain, row, 1);
	gridLayout->addWidget(new QLabel(m_pModel->getOpticalGainUnit()), row++,2);
	gridLayout->addWidget(new QLabel(m_pModel->getOpticalMeasurementLbl()), row,0);
	gridLayout->addWidget(m_btOpticalMeasurement, row, 1);
	gridLayout->addWidget(new QLabel(m_pModel->getOpticalMeasurementUnit()), row++,2);
	gridLayout->addWidget(new QLabel(m_pModel->getZeroOpticalMeasurementLbl()), row,0);
	gridLayout->addWidget(m_btZeroOpticalMeasurement, row, 1);
	gridLayout->addWidget(new QLabel(m_pModel->getZeroOpticalMeasurementUnit()), row++,2);

    //info du cycle
	m_lblCurrentStepDiag = new QLabel("");
	m_lblCurrentStepDiag->setObjectName("lblCurrentStep");
	/*m_lblTotalStep = new QLabel("30");
	m_lblTotalStep->setObjectName("lblTotalStep");*/
	m_lblNameStepDiag = new QLabel(tr("Pas de cycle en cours"));
	m_lblNameStepDiag->setObjectName("lblNameStep");

	QHBoxLayout* horizontalLayoutDiag = new QHBoxLayout();
	horizontalLayoutDiag->setObjectName("horizontalLayout");
	horizontalLayoutDiag->addWidget(m_lblNameStepDiag, 85);
	horizontalLayoutDiag->addWidget(m_lblCurrentStepDiag, 15); 
    
    QVBoxLayout* verticalLayout = new QVBoxLayout();
    verticalLayout->addStretch();
    verticalLayout->addLayout(gridLayout);
    verticalLayout->addStretch();
#if defined(RES_640_480)
    verticalLayout->addLayout(horizontalLayoutDiag);
#endif
	widgetDiag->setLayout(verticalLayout);
	
	
//	widgetMain->setLayout(topLayout);
	//: Nom de l'onglet à laisser en maj pour toutes les trads
	m_tabWidgetCentral->addTab(widgetDiag, tr("DIAGNOSTIC"));

	setConnexion();
	qDebug() << "#### FIN CWinMaintenanceView::init" ;

}
void CWinMaintenanceView::setConnexion()
{
	//Menu
	//Exec calib
}

//SLOT
void CWinMaintenanceView::dataUpdate()
{
	qDebug() << "#### CWinMaintenanceView::dataUpdate()" << endl;
	if(m_pModel->getCycleMaintenanceEnCours())
	{
		QLabel* lblTmp;
		foreach(lblTmp, m_listLblCurrentStep)
				lblTmp->setText(m_pModel->getCurrentStep());
		//m_lblTotalStep->setText();
		QString sValue = m_pModel->getNameStep();
		if(sValue.size() > 30)
		{
			sValue.replace(sValue.indexOf(" ",15), 1, "\n");
		}
		foreach(lblTmp, m_listLblNameStep)
				lblTmp->setText(sValue);
	}
	else
	{
		QLabel* lblTmp;
		foreach(lblTmp, m_listLblCurrentStep)
				lblTmp->setText("0");
		//m_lblTotalStep->setText();
		foreach(lblTmp, m_listLblNameStep)
				lblTmp->setText(tr("Maintenance"));
		m_pControler->cycleMaintenanceFinished();
	}

	
	qDebug() << "#### FIN CWinMaintenanceView::dataUpdate()" << endl;

}

//SLOT 
void CWinMaintenanceView::dataUpdateDiag()
{
    qDebug()<< "CWinMaintenanceView::dataUpdateDiag()";
	//*** Onglet Diagnostic
	m_btTemperatureCuve->setText(m_pModel->getTemperatureCuve());
	m_btPressionEau->setText(m_pModel->getPressionEau());
	m_btMesureOptique->setText(m_pModel->getMesureOptique());
	m_btOpticalGain->setText(QString::number(m_pModel->getOpticalGainValue(), 'f', 2));
	m_btOpticalMeasurement->setText(QString::number(m_pModel->getOpticalMeasurementValue(), 'f', 2));
	m_btZeroOpticalMeasurement->setText(QString::number(m_pModel->getZeroOpticalMeasurementValue(), 'f', 2));

  
	if(m_pModel->getCycleMaintenanceEnCours())
	{
		m_lblCurrentStepDiag->setText(m_pModel->getCurrentStep());
		//m_lblTotalStep->setText();
		QString sValue = m_pModel->getNameStep();
		if(sValue.size() > 30)
		{
			sValue.replace(sValue.indexOf(" ",15), 1, "\n");
		}
		m_lblNameStepDiag->setText(sValue);
	}
	else
	{
		m_lblCurrentStepDiag->setText("0");
		//m_lblTotalStep->setText();
		m_lblNameStepDiag->setText(tr("Maintenance"));
		
	}

    qDebug()<< "FIN CWinMaintenanceView::dataUpdateDiag()";
	
	
}


