#ifndef CWIN_SCHEDULER_CONTROLER
#define CWIN_SCHEDULER_CONTROLER

#include "InterfaceUserSession.h"

class CWinSchedulerModel;
class CWinSchedulerView;
class CSupervision;
class CWinMeasureCardControler;
class CWinMainControler;

class CWinSchedulerControler : public InterfaceUserSession
{

	Q_OBJECT

public:
	
	void execControler();

public slots:
	void btBackPressed();
	void btNbCyleAvantZeroPressed();
	void btRemoteCtrlPressed();
	void btConsigneTemperaturePressed();
	void btConsigneGainPressed();
	void btReglagePressionPressed();
	void btTempsVoieAttentePressed();
	void userSessionClosed();
    void btNumEscalveJBUSPressed();
    void btConfigSeuilPressed(int arg_numBt);

    void btNumVoiePressed(int arg_numBt);
    void btTempsSeqPressed(int arg_numBt);
    void btDeletePressed(int arg_numBt);

	void btYearPPressed();
	void btMonthPPressed();
	void btDayPPressed();
	void btHourPPressed();
	void btMinutePPressed();

	void btYearMPressed();
	void btMonthMPressed();
	void btDayMPressed();
	void btHourMPressed();
	void btMinuteMPressed();

private:
	CWinMainControler* m_pWinMainControler;
	CWinSchedulerModel* m_pModel;
	CWinSchedulerView* m_pView;
	CSupervision* m_pSupervision;
	static CWinSchedulerControler* singletonControler;

private:
	CWinSchedulerControler(CWinMainControler* argpWinMainControler);

public:
	static	CWinSchedulerControler* getInstance(CWinMainControler* argpWinMainControler);


};

#endif
