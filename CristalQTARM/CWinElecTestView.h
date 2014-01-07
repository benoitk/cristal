#ifndef CWIN_ELEC_TEST_VIEW
#define CWIN_ELEC_TEST_VIEW

#include <QWidget>
#include <List>
#include "CPushButton.h"
class CWinElecTestControler;
class CWinEVPompeModel;
class CWinStreamSelectorModel;
class CWinMainModel;
class CWinExternalCardModel;
class CWinMeasureCardModel;
class QPushButton;
class QRadioButton;
class QLabel;

#ifdef RES_640_480
    #define NB_RELAIS_MAX 8
#else
    #define NB_RELAIS_MAX 5
#endif

class CWinElecTestView : public QWidget
{
	Q_OBJECT
public:
	CWinElecTestView(CWinElecTestControler* argpControler, QWidget *parent = 0, Qt::WindowFlags flags = 0);
	
	void setConnexion();
	void setModel(CWinEVPompeModel* argpModelEVPompeModel,CWinExternalCardModel* argpModelExternalCard,CWinMeasureCardModel* argpModelMeasureCard, CWinStreamSelectorModel* argpModelStreamSelector, CWinMainModel* argpModelMain){m_pModelMain = argpModelMain;m_pModelStreamSelector=argpModelStreamSelector; m_pModelEVPompe = argpModelEVPompeModel;m_pModelExternalCard = argpModelExternalCard;m_pModelMeasureCard = argpModelMeasureCard; init();};
    void dataUpdated();

public slots:
    void loadPageExternalCard(int argnNumPage);
    void loadPageEntree(int argnNumPage);
    void loadPageSortieAna(int argnNumPage);
    void slotTemperatureUpdated();
private:
	void init();
public:
	//EV
	//void setEnabledBtOnEV1(bool bEnabled){m_btOnEV1->setEnabled(bEnabled);};
	//void setEnabledBtOffEV1(bool bEnabled){m_btOffEV1->setEnabled(bEnabled);};
	void setEnabledBtOnEV(bool bEnabled, int arg_numEV){m_listBtOnEV.at(arg_numEV)->setEnabled(bEnabled);};
	void setEnabledBtOffEV(bool bEnabled, int arg_numEV){m_listBtOffEV.at(arg_numEV)->setEnabled(bEnabled);};
	//Pompe
	void setEnabledBtOnPompe(bool bEnabled, int arg_numPompe){m_listBtOnPompe.at(arg_numPompe)->setEnabled(bEnabled);};
	void setEnabledBtOffPompe(bool bEnabled, int arg_numPompe){m_listBtOffPompe.at(arg_numPompe)->setEnabled(bEnabled);};
	//Carte mesure
	void setEnabledBtOnLocal(bool bEnabled, int arg_numLocal){m_listBtOnLocal.at(arg_numLocal)->setEnabled(bEnabled);};
	void setEnabledBtOffLocal(bool bEnabled, int arg_numLocal){m_listBtOffLocal.at(arg_numLocal)->setEnabled(bEnabled);};
	//relais
	void setEnabledBtOnRelais(int numRelais, bool bEnabled){m_listBtOnRelais[numRelais]->setEnabled(bEnabled);};
	void setEnabledBtOffRelais(int numRelais, bool bEnabled){m_listBtOffRelais[numRelais]->setEnabled(bEnabled);};
	void setEnabledBtNextPageRelais(bool bEnabled){m_btNextPageRelais->setEnabled(bEnabled);};
	void setEnabledBtPrevPageRelais(bool bEnabled){m_btPrevPageRelais->setEnabled(bEnabled);};
    //4-20
	void setValMaxConvertisseur(const QString& arg_sValue){m_btValMaxConvertisseur->setText(arg_sValue);};
	void setValMinConvertisseur(const QString& arg_sValue){m_btValMinConvertisseur->setText(arg_sValue);};
    void setEnabledBtNextPageSortieAna(bool bEnabled){m_btNextPageSortieAna->setEnabled(bEnabled);};
	void setEnabledBtPrevPageSortieAna(bool bEnabled){m_btPrevPageSortieAna->setEnabled(bEnabled);};
    //Selecteur de voie
    void setEnabledBtOnStreamSelector(int numVoie, bool bEnabled){m_listBtOnStreamSelector[numVoie]->setEnabled(bEnabled);};
	void setEnabledBtOffStreamSelector(int numVoie, bool bEnabled){m_listBtOffStreamSelector[numVoie]->setEnabled(bEnabled);};


	QList<CPushButton*> getListBtOnPompe()const{return m_listBtOnPompe;};
	QList<CPushButton*> getListBtOnRelais()const{return m_listBtOnRelais;};
	QList<CPushButton*> getListBtOnLocal()const{return m_listBtOnLocal;};
	

private:
	CWinEVPompeModel* m_pModelEVPompe;
	CWinExternalCardModel* m_pModelExternalCard;
	CWinMeasureCardModel* m_pModelMeasureCard;
	CWinElecTestControler* m_pControler;
	CWinStreamSelectorModel* m_pModelStreamSelector;
    CWinMainModel* m_pModelMain;

	QTabWidget* m_tabWidget;

	//Boutton du menu de droite
	QList<QPushButton*> m_listBtBack;

	//bouton de nav du coté
	QPushButton* m_btNextPageRelais;
	QPushButton* m_btPrevPageRelais;
    QPushButton* m_btNextPageEntree;
	QPushButton* m_btPrevPageEntree;
    QPushButton* m_btNextPageSortieAna;
    QPushButton* m_btPrevPageSortieAna;
	//Onglet EV
	//CPushButton* m_btOnEV1;
	//CPushButton* m_btOffEV1;

	//Onglet Pompe
	QList<CPushButton*> m_listBtOnPompe;
	QList<CPushButton*> m_listBtOffPompe;

	//onglet 4-20 
	QPushButton* m_btValAna;
	QLabel* m_lblValAna;
	QLabel* m_lblNumSortieAna;
    QLabel* m_lblTemperature;
	QPushButton* m_btValMaxConvertisseur;
	QLabel* m_lblValMaxConvertisseur;
	QPushButton* m_btValMaxConvertisseurPlus;
	QPushButton* m_btValMaxConvertisseurMoins;
	QPushButton* m_btValMinConvertisseur;
	QLabel* m_lblValMinConvertisseur;
	QPushButton* m_btValMinConvertisseurPlus;
	QPushButton* m_btValMinConvertisseurMoins;
	//QSlider* m_sliderValAna;
	QRadioButton* m_btRadioTest4mA;
	QRadioButton* m_btRadioTest12mA;
	QRadioButton* m_btRadioTest20mA;

   

	//Ongiet Relais
	QList<CPushButton*> m_listBtOnRelais;
	QList<CPushButton*> m_listBtOffRelais;
    QList<CPushButton*> m_listBtOnStreamSelector;
	QList<CPushButton*> m_listBtOffStreamSelector;
	QList<CPushButton*> m_listBtEtatLogiqueEntree;
	QList<CPushButton*> m_listBtEtatPhysiqueEntree;
	//QList<CPushButton*> m_listBtOffEntree;
    QFormLayout* m_layoutCentralRelais; 
    QFormLayout* m_layoutCentralEntree; 
	//Onglet Mesure
	QList<CPushButton*> m_listBtOnLocal;
	QList<CPushButton*> m_listBtOffLocal;
	//onglet EV
	QList<CPushButton*> m_listBtOnEV;
	QList<CPushButton*> m_listBtOffEV;


    
};

#endif
