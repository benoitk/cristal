#ifndef CWIN_EV_POMPE_VIEW
#define CWIN_EV_POMPE_VIEW

#include "header_qt.h"

class CWinEVPompeControler;
class CWinEVPompeModel;

class CWinEVPompeView : public QMainWindow
{
	Q_OBJECT
public:
	CWinEVPompeView(CWinEVPompeControler* argpControler, QWidget *parent = 0, Qt::WindowFlags flags = 0);
	

	void setConnexion();
	void setModel(CWinEVPompeModel* argpModel){m_pModel = argpModel; init();};

public slots:

private:
	void init();
public:
//	void setEnabledBtOnEV1(bool bEnabled){m_btOnEV1->setEnabled(bEnabled);};
//	void setEnabledBtOffEV1(bool bEnabled){m_btOffEV1->setEnabled(bEnabled);};

	void setEnabledBtOnPompe1(bool bEnabled){m_vBtOnPompe.at(0)->setEnabled(bEnabled);};
	void setEnabledBtOffPompe1(bool bEnabled){m_vBtOffPompe.at(0)->setEnabled(bEnabled);};
	void setEnabledBtOnPompe2(bool bEnabled){m_vBtOnPompe.at(1)->setEnabled(bEnabled);};
	void setEnabledBtOffPompe2(bool bEnabled){m_vBtOffPompe.at(1)->setEnabled(bEnabled);};
	void setEnabledBtOnPompe3(bool bEnabled){m_vBtOnPompe.at(2)->setEnabled(bEnabled);};
	void setEnabledBtOffPompe3(bool bEnabled){m_vBtOffPompe.at(2)->setEnabled(bEnabled);};
	void setEnabledBtOnPompe4(bool bEnabled){m_vBtOnPompe.at(3)->setEnabled(bEnabled);};
	void setEnabledBtOffPompe4(bool bEnabled){m_vBtOffPompe.at(3)->setEnabled(bEnabled);};
	void setEnabledBtOnPompe5(bool bEnabled){m_vBtOnPompe.at(4)->setEnabled(bEnabled);};
	void setEnabledBtOffPompe5(bool bEnabled){m_vBtOffPompe.at(4)->setEnabled(bEnabled);};
	void setEnabledBtOnPompe6(bool bEnabled){m_vBtOnPompe.at(5)->setEnabled(bEnabled);};
	void setEnabledBtOffPompe6(bool bEnabled){m_vBtOffPompe.at(5)->setEnabled(bEnabled);};
	

private:
	CWinEVPompeModel* m_pModel;
	CWinEVPompeControler* m_pControler;

	QTabWidget* m_tabWidget;

	//Boutton du menu de droite
	QVector<QPushButton*> m_vectorBtBack;

	//bouton de nav du bas
	/*QPushButton* m_btNextPage;
	QPushButton* m_btPreviousPage;*/

	//Onglet EV
	//QPushButton* m_btOnEV1;
	//QPushButton* m_btOffEV1;

	//Onglet Pompe
	QVector<QPushButton*> m_vBtOnPompe;
	QVector<QPushButton*> m_vBtOffPompe;
	
	//QPushButton* m_btOnPompe1;
	//QPushButton* m_btOffPompe1;
	//QPushButton* m_btOnPompe2;
	//QPushButton* m_btOffPompe2;
	//QPushButton* m_btOnPompe3;
	//QPushButton* m_btOffPompe3;
	//QPushButton* m_btOnPompe4;
	//QPushButton* m_btOffPompe4;
	//QPushButton* m_btOnPompe5;
	//QPushButton* m_btOffPompe5;
	//QPushButton* m_btOnPompe6;
	//QPushButton* m_btOffPompe6;


    
};

#endif
