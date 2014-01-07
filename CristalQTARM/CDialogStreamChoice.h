#ifndef CDIALOG_STREAMCHOICE_H
#define CDIALOG_STREAMCHOICE_H

#include <QDialog>
#include <QString>
class QLabel;
class QLineEdit;
class QPushButton;
class QTabWidget;

class CDialogStreamChoice : public QDialog
{
	Q_OBJECT

public:
	static CDialogStreamChoice* getInstance();

	void setValueName(const QString& sNameValue);
	void setValue(const QString& sValue);
	QString getValue();

    void setNbStreamEnabled(int arg_nbStream);
public slots:
	
	void btOnePressed();
	void btTwoPressed();
	void btThreePressed();
	void btFourPressed();
	void btFivePressed();
	void btSixPressed();
	void btPausePressed();
	
private:
	CDialogStreamChoice();
	void setConnexion();
	void addCharToValue(const QString& sChar);
public:
	
private:
	static CDialogStreamChoice* singleton;
	QString m_sNameValue;
	QString m_sValue;
	QString m_sValueMax;
	QString m_sValueMin;
	QString m_sValueUnit;

	float m_fValue;

	QLabel* m_lblNameValue;
	QLineEdit* m_lblValue;
	QLabel* m_lblNameSeuil1;
	QLabel* m_lblValueSeuil1;
	QLabel* m_lblNameSeuil2;
	QLabel* m_lblValueSeuil2;

	QPushButton* m_btOne;
	QPushButton* m_btTwo;
	QPushButton* m_btThree;
	QPushButton* m_btFour;
	QPushButton* m_btFive;
	QPushButton* m_btSix;
	QPushButton* m_btPause;
	

	QPushButton* m_btBack;
	QPushButton* m_btApply;
	QPushButton* m_btCorection;
	
	QTabWidget* m_tabWidget;



};

#endif // CDIALOGPAVENUM_H
