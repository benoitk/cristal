#ifndef CWIN_MAIN_CONTROLER
#define CWIN_MAIN_CONTROLER

#include "InterfaceUserSession.h"

class CWinMainModel;
class CWinMainView;
class CSupervision;
//class CWinMeasureCardControler;
//class CWinExternalCardControler;
//class CWinEVPompeControler;
//class CWinElecTestControler;
//class CWinMaintenanceControler;
//class CWinStreamControler;
class CDialogAlarm;
//class CDialogStopCycle;


class CWinMainControler : public InterfaceUserSession
{
	Q_OBJECT

public:
	CWinMainControler(CListStream* argAnalyseur,CCarteIO* argCarteIO,CCarteMesure* argCarteMesure, CSocketIHM* argInterfaceIHM);
	
	void execControler();
	CSupervision* getpSupervision(){return m_pSupervision;};
    CWinMainModel* getMainModel();
    void askRepaintGraph(int arg_numStream);
	
public slots:
	void userSessionClosed();
	void btPlayPausePressed();
	void btStopPressed();
	void btStopEndCylePressed();
	void btNextPressed();
	void btDiagPressed();
	void btAlarmPressed();
	void btDetailPressed(int numStream);
	void btMeasureCardPressed();
	void btExternalCardPressed();
	void btEVPompePressed();
	void btMaintenancePressed();
	void btSequenceurPressed();
	void btCopyLogFilesPressed();
	void btInformationPressed();
	void btExplorerPressed();
	void btParameterPressed();
	void btSavePressed();
	void btQuitPressed();
    void btNextGraphPressed();
    void btPrevGraphPressed();
	void tabChanged(int index);

	//pour les erruer de com et de JBus
	void getErrorIOAndJBus();
	//Pour les screenshot
	void takeScreenshot();
	

private:
	
	//CDialogStopCycle* m_dialogStopCycle;
	/*CWinMeasureCardControler* m_pMeasureCardControler;
	CWinExternalCardControler* m_pExternalCardControler;
	CWinEVPompeControler* m_pEVPompeControler;*/
	/*CWinElecTestControler* m_pElecTestControler;
	CWinMaintenanceControler* m_pMaintenanceControler;
	CWinStreamControler* m_pStreamControler;*/
	CWinMainModel* m_pModel;
	CWinMainView* m_pView;
	CSupervision* m_pSupervision;
	
	CDialogAlarm* m_pDialogAlarm;

	bool m_bEnPause;
	bool m_bEnStop;

	int m_nbScreenshot;

    int m_CurrentGraphPage;

};


#endif