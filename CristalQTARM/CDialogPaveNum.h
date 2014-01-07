#ifndef CDIALOGPAVENUM_H
#define CDIALOGPAVENUM_H

#include <QDialog>
#include <QString>
class QLabel;
class QLineEdit;
class QPushButton;
class QTabWidget;

class CDialogPaveNum : public QDialog
{
	Q_OBJECT

public:
	static CDialogPaveNum* getInstance();

	void setValueName(const QString& sNameValue);
	void setValue(const QString& sValue);
	/*void setValueMax(QString sValueMax);
	void setValueMin(QString sValueMin);
	void setValueUnit(QString sUnit);*/
	QString getValue();
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
	void btCommaPressed();
	void btPlusMinusPressed();
	void btDeletePressed();
private:
	CDialogPaveNum();
	void setConnexion();
	void addCharToValue(const QString& sChar);
public:
	
private:
	static CDialogPaveNum* singleton;
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

	QPushButton* m_btZero;
	QPushButton* m_btOne;
	QPushButton* m_btTwo;
	QPushButton* m_btThree;
	QPushButton* m_btFour;
	QPushButton* m_btFive;
	QPushButton* m_btSix;
	QPushButton* m_btSeven;
	QPushButton* m_btEight;
	QPushButton* m_btNine;
	QPushButton* m_btPlusMinus;
	QPushButton* m_btComma;

	QPushButton* m_btBack;
	QPushButton* m_btApply;
	QPushButton* m_btCorection;
	QPushButton* m_btDelete;

	QTabWidget* m_tabWidget;



};

#endif // CDIALOGPAVENUM_H
