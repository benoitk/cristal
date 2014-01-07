#ifndef CWIN_TEST_ELEC_CONTROLER
#define CWIN_TEST_ELEC_CONTROLER

#include "InterfaceUserSession.h"

class CWinEVPompeModel;
class CWinExternalCardModel;
class CWinMeasureCardModel;
class CWinStreamSelectorModel;
class CWinElecTestView;
class CSupervision;
class CWinMainControler;
class QTimer;


class CWinElecTestControler : public InterfaceUserSession
{

	Q_OBJECT
	
public:
	
	void execControler();
    bool getEtatRelais(int arg_numRelais){ return m_listEtatRelais.at(arg_numRelais);};

public slots:
	void btBackPressed();

	void btOnEVPressed(int arg_numEV);
	void btOffEVPressed(int arg_numEV);
    void btOffChauffe();
	void btOnPompePressed(int arg_numPompe);
	void btOffPompePressed(int arg_numPompe);

	void btOnRelaisPressed(int numRelais);
	void btOffRelaisPressed(int numRelais);
    void btOnStreamSelectorPressed(int numVoie);
	void btOffStreamSelector(int numVoie);
    void btNextPageRelaisPressed();
    void btPrevPageRelaisPressed();
    void btNextPageSortieAnaPressed();
    void btPrevPageSortieAnaPressed();

	void btOnLocalPressed(int arg_numLocal);
	void btOffLocalPressed(int arg_numLocal);

	void btValMaxConvertisseurPressed();
	void btValMinConvertisseurPressed();

	void btRadioTest4mAPressed();
	void btRadioTest12mAPressed();
	void btRadioTest20mAPressed();

	void tabChanged(int index);
	void userSessionClosed();

    void slotArretPompes();

private:
	CWinMainControler* m_pWinMainControler;
	CWinEVPompeModel* m_pModelEVPompe;
	CWinStreamSelectorModel* m_pModelStreamSelector;
	CWinExternalCardModel* m_pModelExternalCard;
	CWinMeasureCardModel* m_pModelMeasureCard;
	CWinElecTestView* m_pView;
	CSupervision* m_pSupervision;
	static CWinElecTestControler* singletonControler;

private:
	CWinElecTestControler(CWinMainControler* argpWinMainControler);

    int m_numPageRelais;
    int m_nombrePagesRelais;
    int m_numPageSortieAna;
    int m_nombrePagesSortieAna;
    int m_numPageEntree;
    int m_nombrePagesEntree;
    QList<bool> m_listEtatRelais; //On:true, Off:false
    QTimer* m_timerArretPompes;
    QTimer* m_timerTemperature;

public:
	static	CWinElecTestControler* getInstance(CWinMainControler* argpWinMainControler);

	
};

#endif