#ifndef CDIALOG_PASSWORD
#define CDIALOG_PASSWORD

#include <QDialog>
#include <QString>
class QPushButton;
class QLineEdit;

class CDialogPassword :
	public QDialog
{
	Q_OBJECT
public:
	static CDialogPassword* getInstance();
	
	void setPassordToCheck(const QString& sPwd,const QString& sPwd2 = "");
	QString getPasswordChecked(){return m_pwdToCheck;};
public slots:
	void btZeroPressed();
	void btOnePressed();
	void btTwoPressed();
	void btThreePressed();
	void btFourPressed();
	void btFivePressed();
	void btSixPressed();
	void btSevenPressed();
	void btEightPressed();
	void btNinePressed();
	void btDeletePressed();
private:
	void setConnexion();
	CDialogPassword(void);
	void addDigit(QString sDigit);

	static CDialogPassword* singleton;
	QLineEdit *m_lblValue;
	QPushButton *m_btComma;
	QPushButton *m_btPlusMinus;
	QPushButton *m_btZero;
	QPushButton *m_btOne;
	QPushButton *m_btTwo;
	QPushButton *m_btThree;
	QPushButton *m_btFour;
	QPushButton *m_btFive;
	QPushButton *m_btSix;
	QPushButton *m_btSeven;
	QPushButton *m_btEight;
	QPushButton *m_btNine;

	QPushButton *m_btApply;
	QPushButton *m_btBack;
	QPushButton *m_btDelete;

	QString m_pwdToCheck;
	QString m_pwdToCheck2;
	
};

#endif CDIALOG_PASSWORD
