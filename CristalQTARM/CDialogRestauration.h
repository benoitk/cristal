#ifndef CDIALOG_RESTAURATION
#define CDIALOG_RESTAURATION

#include <QDialog>

class CSupervision;
class QPushButton;

class CDialogRestauration: public QDialog
{
	Q_OBJECT
public:
	static CDialogRestauration* getInstance();
	void setConnexion();

public slots:
	void saveConfig();
	void restaurerConfig();
private:
	CDialogRestauration();
	QPushButton* m_btBack;
	QPushButton* m_btApply;
	QPushButton* m_btSave;
	static CDialogRestauration* singleton;

};
#endif CDIALOG_RESTAURATION