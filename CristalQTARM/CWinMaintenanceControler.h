#ifndef CWIN_MAINTENANCE_CONTROLER
#define CWIN_MAINTENANCE_CONTROLER


#include "InterfaceUserSession.h"
#include <QString>

class CWinMaintenanceModel;
class CWinMaintenanceView;
class CSupervision;
class CWinMainControler;
class CDialogValEtalon;
class CDialogResultatEtalon;

class CWinMaintenanceControler: public InterfaceUserSession
{

	Q_OBJECT
public:
	static	CWinMaintenanceControler* getInstance(CWinMainControler* argpWinMainControler);
	void execControler();
	
public slots:
	void btBackPressed();
	void btExecuteCalibPressed();
	void btExecuteCalibInLinePressed();
	void btExecuteCleanupPressed();
	void btExecuteZeroPressed();
	void btStopPressed();
	void executeCalibRejected();
	void executeCalibAccepted();
	void executeCalibInLineAccepted();
	void executeCleanupAccepted();
	void executeZeroAccepted();
	void cycleMaintenanceFinished();
	void cycleCalibFinishedAccepted();
	void cycleCalibFinishedRejected();
	void tabChanged(int index);
	void userSessionClosed();
private:
	CWinMaintenanceControler(CWinMainControler* argpWinMainControler);

private:
	CWinMainControler* m_pWinMainControler;
	CWinMaintenanceModel* m_pModel;
	CWinMaintenanceView* m_pView;
	CSupervision* m_pSupervision;
	static CWinMaintenanceControler* singletonControler;

	CDialogValEtalon* m_pDialogValEtalon;
	CDialogResultatEtalon* m_pDialogResultatEtalon;

	//Variable temporaire pour avoir garder certaine ancienne valeur pour les résultats des cycles de maintenance
	QString m_sAncienCoefActuel;
	QString m_sAncienCoefActuel2; //mesure 2
	QString m_sAncienOffsetActuel;
	QString m_sAncienMesureManuelle;

	bool m_bCycleCalibEnCours;
	bool m_bCycleCalibInLineEnCours;
	bool m_bCycleZeroEnCours;
	bool m_bCycleCleanupEnCours;

	int m_numTabIndex;
	int m_numStream;
};

#endif
