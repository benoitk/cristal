#ifndef CWIN_EV_POMPE_CONTROLER
#define CWIN_EV_POMPE_CONTROLER

#include "InterfaceUserSession.h"

class CWinEVPompeModel;
class CWinEVPompeView;
class CSupervision;
class CWinEVPompeControler;
class CWinMainControler;

class CWinEVPompeControler : public InterfaceUserSession
{

	Q_OBJECT
	
public:
	
	void execControler();

public slots:
	void btBackPressed();
	void btOnEV1Pressed();
	void btOffEV1Pressed();
	void btOnPompe1Pressed();
	void btOffPompe1Pressed();
	void btOnPompe2Pressed();
	void btOffPompe2Pressed();
	void btOnPompe3Pressed();
	void btOffPompe3Pressed();
	void btOnPompe4Pressed();
	void btOffPompe4Pressed();
	void btOnPompe5Pressed();
	void btOffPompe5Pressed();
	void btOnPompe6Pressed();
	void btOffPompe6Pressed();
	void tabChanged(int index);
	void userSessionClosed();

private:
	CWinMainControler* m_pWinMainControler;
	CWinEVPompeModel* m_pModel;
	CWinEVPompeView* m_pView;
	CSupervision* m_pSupervision;
	static CWinEVPompeControler* singletonControler;

private:
	CWinEVPompeControler(CWinMainControler* argpWinMainControler);

public:
	static	CWinEVPompeControler* getInstance(CWinMainControler* argpWinMainControler);

	
};

#endif
