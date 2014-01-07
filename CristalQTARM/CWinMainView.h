#ifndef CWIN_MAIN_VIEW
#define CWIN_MAIN_VIEW

#include <QWidget>
#include <List>
#include <QPushButton>

#define NB_MESURE_GRAPH 20

class CWinMainControler;
class CWinMainModel;
class QLabel;
class CPushButton;
class CGraphicsRectItem;
class QTabWidget;
class QGridLayout;

class CWinMainView : public QWidget
{
	Q_OBJECT

public:
	CWinMainView(CWinMainControler* argoControler, QWidget *parent = 0, Qt::WFlags flags = 0);
	void setConnexion();
	void setModel(CWinMainModel* argoModel);
	void repaintGraph(int arg_numStream);
    void setEnabledBtNextGraph(bool bActive){m_btNextGraph->setEnabled(bActive);};
	void setEnabledBtPrevGraph(bool bActive){m_btPrevGraph->setEnabled(bActive);};
    
public slots:
	void dataUpdate();
	void updateDateTime();

private:
	void init();
	void addMeasureToGraph(int arg_numStream, float arg_fMesure, const QString& arg_sMesureUnit);
	CWinMainControler* m_pControler;
	CWinMainModel* m_pModel;

	//***Onglet principale
	//Fenêtre central voie/mesure
	QLabel* m_lblMesureGraph;
	/*QLabel* m_lblMesure;
	QLabel* m_lblValMesure;
	QPushButton* m_btDetail;*/
    QGridLayout* m_mesureLayout;

	QList<QList<QLabel*>> m_listLblMesure;
	QList<QLabel*> m_listLblStatusVoie;
	QList<QList<QLabel*>> m_listLblValMesure;
	QList<CPushButton*> m_listBtDetail;
	
	//Boutons de droite
	QPushButton* m_btAlarm;
	QPushButton* m_btPlayPause;
	QPushButton* m_btStop;
	QPushButton* m_btNext;
	QPushButton* m_btStopEndCycle;
	QPushButton* m_btTools;
	QPushButton* m_btNextGraph;
	QPushButton* m_btPrevGraph;
    QLabel* m_lblInfoGraph;
	
	//Info du cycle
	QLabel* m_lblStatusAnalyseur;
	QLabel* m_lblStatusWaterFailure;
	QLabel* m_lblStatusSeuil;
	QLabel* m_lblCurrentStream;
	QLabel* m_lblCurrentStep;
	QLabel* m_lblTotalStep;
	QLabel* m_lblNameStep;
	
	//Button/info du bas
	QLabel* m_lblDateHeure;
	QLabel* m_lblHeure;
	QPushButton* m_btDiagnostic;
	
	//QGroupBox* m_groupBoxCentral; //GroupBox contenant voie/mesure
	//QGroupBox* m_groupBoxRight; //GroupBox contenant les boutons de droite (m_hBoxLoyoutButtons)
	//QGroupBox* m_groupBoxInfo; //GroupBox sous le centralGroupBox contenant les infos du cycle en cours
	//QGroupBox* m_groupBoxBottom; //GroupBox contenant le btDiagnostic

	/*QGridLayout *m_gridLayoutMain; //contenant touts les m_gridLayoutTop + m_groupBoxBottom
	QGridLayout *m_gridLayoutTop; //contenant m_gridLayoutLeft + m_groupBoxRight
	QGridLayout *m_gridLayoutCentral; //contenant m_groupBoxCentral + m_groupBoxInfo*/

	//***Onglet outil
	QPushButton* m_btMaintenance;
	QPushButton* m_btSequenceur;
	QPushButton* m_btCopyLogFiles;
	QPushButton* m_btHelp;

	QPushButton* m_btMeasureCard;
	QPushButton* m_btSave;
	QPushButton* m_btInformation;

	QPushButton* m_btExternalCard;
	QPushButton* m_btParameter;
	QPushButton* m_btExplorer;

	QPushButton* m_btEvPump;
	QPushButton* m_btAnalyseur;
	QPushButton* m_btQuit;
	
	//*** Onglet Diagnostic
	QPushButton* m_btTemperatureCuve ;
	QPushButton* m_btPressionEau;
	QPushButton* m_btMesureOptique;
	QPushButton* m_btOpticalGain ;
	QPushButton* m_btOpticalMeasurement;
	QPushButton* m_btZeroOpticalMeasurement;
	QPushButton* m_btAbsorbanceValue;

    QLabel* m_lblCurrentStreamDiag;
	QLabel* m_lblCurrentStepDiag;
	QLabel* m_lblTotalStepDiag;
	QLabel* m_lblNameStepDiag;

	QTabWidget *m_tabWidgetCentral; //Contenant les 3 principaux layouts

	//***Onglet Graph
	QList<CGraphicsRectItem*> m_listGraphicsRectItem;
    QList<QList<CGraphicsRectItem*>> m_listDataGraph;
	float m_tabMesureMax[NB_MESURE_GRAPH];
	float m_fCoefAOld;
	QLabel* m_lblConcentrationMax;
	QLabel* m_lblConcentrationMin;
	QLabel* m_lblConcentrationMoy;


};

#endif