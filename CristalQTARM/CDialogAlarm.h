#ifndef CDIALOG_ALARM
#define CDIALOG_ALARM

#include "header.h"
#include <QDialog>

class CSupervision;
class QPushButton;
class CAlarmSortedView;
class QStringListModel;

class CDialogAlarm: public QDialog
{
	Q_OBJECT
public:
	CDialogAlarm(CSupervision* argpSupervision);
	
	bool updateAlarms();
	void setConnexion();
    void setEnabledBtNext(const bool& arg_state);
    void setEnabledBtPrev(const bool& arg_state);

public slots:
	
	void acquiter();

private:
	
	QPushButton* m_btBack;
	QPushButton* m_btApply;
	QPushButton* m_btNext;
	QPushButton* m_btPrev;
	//QStringList m_listAlarm;
	//QGridLayout* m_gridLayout;
	CSupervision* m_pSupervision;
	QStringListModel *m_listModel;
    CAlarmSortedView* m_listView;
};
#endif CDIALOG_ALARM
