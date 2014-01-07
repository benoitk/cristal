#ifndef CDIALOG_STOP_CYCLE
#define CDIALOG_STOP_CYCLE

#include <QDialog>

//class CWinMainModel;
class QPushButton;


class CDialogStopCycle:public QDialog
{
	Q_OBJECT
public:
	static CDialogStopCycle* getInstance();
	bool cycleStoped();
public slots:
	void stopCycle();

private:
	void setConnexion();
	//CDialogStopCycle(CWinMainModel* arg_WinMainModel);
	CDialogStopCycle();
	QPushButton* m_btApply;
	QPushButton* m_btBack;
	static CDialogStopCycle* singleton;

//	CWinMainModel* m_winMainModel;
};

#endif CDIALOG_STOP_CYCLE