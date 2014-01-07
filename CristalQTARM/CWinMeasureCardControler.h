#ifndef CWIN_MEASURE_CARD_CONTROLER
#define CWIN_MEASURE_CARD_CONTROLER

#include "InterfaceUserSession.h"

class CWinMeasureCardModel;
class CWinMeasureCardView;
class CSupervision;
class CWinMeasureCardControler;
class CWinMainControler;

class CWinMeasureCardControler : public InterfaceUserSession
{

	Q_OBJECT

public:
	~CWinMeasureCardControler();
	
	void execControler();

public slots:
	void btBackPressed();
	void btOnLocal1Pressed();
	void btOffLocal1Pressed();
	void btOnLocal2Pressed();
	void btOffLocal2Pressed();
	void btOnLocal3Pressed();
	void btOffLocal3Pressed();
	void btOnLocal4Pressed();
	void btOffLocal4Pressed();
	void btOnLocal5Pressed();
	void btOffLocal5Pressed();
	void btOnLocal6Pressed();
	void btOffLocal6Pressed();
	void userSessionClosed();

private:
	CWinMainControler* m_pWinMainControler;
	CWinMeasureCardModel* m_pModel;
	CWinMeasureCardView* m_pView;
	CSupervision* m_pSupervision;
	static CWinMeasureCardControler* singletonControler;

private:
	CWinMeasureCardControler(CWinMainControler* argpWinMainControler);

public:
	static	CWinMeasureCardControler* getInstance(CWinMainControler* argpWinMainControler);


};

#endif
