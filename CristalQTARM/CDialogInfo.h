#ifndef CDIALOG_INFO
#define CDIALOG_INFO

#include <QDialog>

class QPushButton;

class CDialogInfo: public QDialog
{
	Q_OBJECT
public:
	static CDialogInfo* getInstance();
	void setConnexion();

public slots:
	
private:
	CDialogInfo();
	QPushButton* m_btBack;
	static CDialogInfo* singleton;

};
#endif CDIALOG_INFO