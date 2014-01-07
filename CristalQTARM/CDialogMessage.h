#ifndef CDIALOG_MESSAGE
#define CDIALOG_MESSAGE

#include <QDialog>
class QLabel;
class QPushButton;

class CDialogMessage: public QDialog
{
	Q_OBJECT
public:
	static CDialogMessage* getInstance();
	
	void setConnexion();
	void setLblMsg(const QString& arg_sMsg,const bool& arg_BtApplyVisible = true);

    void buttonVisible(bool arg_visible);
public slots:
	
private:
	CDialogMessage();
	QPushButton* m_btBack;
	QPushButton* m_btApply;
	QLabel* m_lblMsg;
	static CDialogMessage* singleton;

};
#endif CDIALOG_MESSAGE