#ifndef CWIN_EXTERNAL_CARD_CONTROLER
#define CWIN_EXTERNAL_CARD_CONTROLER

#include "InterfaceUserSession.h"

class CWinExternalCardModel;
class CWinExternalCardView;
class CSupervision;
class CWinExternalCardControler;
class CWinMainControler;

class CWinExternalCardControler : public InterfaceUserSession
{

	Q_OBJECT

public:
	void execControler();

public slots:
	void btBackPressed();
	void btOnRelaisPressed(int numRelais);
	void btOffRelaisPressed(int numRelais);
	void btValMaxConvertisseurPressed();
	void btValMinConvertisseurPressed();

	void btRadioTest4mAPressed();
	void btRadioTest12mAPressed();
	void btRadioTest20mAPressed();
	void userSessionClosed();

private:
	CWinMainControler* m_pWinMainControler;
	CWinExternalCardModel* m_pModel;
	CWinExternalCardView* m_pView;
	CSupervision* m_pSupervision;
	static CWinExternalCardControler* singletonControler;

private:
	CWinExternalCardControler(CWinMainControler* argpWinMainControler);

public:
	static	CWinExternalCardControler* getInstance(CWinMainControler* argpWinMainControler);

		

};

#endif
