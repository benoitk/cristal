#ifndef CDIALOGRESULTATETALON_H
#define CDIALOGRESULTATETALON_H

#include <QDialog>
#include <QString>

class CDialogPaveNum;
class QPushButton;
class QTabWidget;
class QLabel;
class CDialogResultatEtalon : public QDialog
{
	Q_OBJECT

public:
	static CDialogResultatEtalon* getInstance();
	void setTittle(const QString& sTitre);
	void setLblMessageErreur(const QString& arg_sMsg);
	void setLine(const QString& sLblTittle, const QString& sValue);
	void setLine2(const QString& sLblTittle, const QString& sValue);
	void setLine3(const QString& sLblTittle, const QString& sValue);
	void setLine4(const QString& sLblTittle, const QString& sValue);
	void disabledBtApply();
	void init();
	QString getReturnValue(); 
	QString getReturnValue2(); 
	QString getReturnValue3(); 
	QString getReturnValue4(); 

public slots:
	void btValuePressed();
	void btValue2Pressed();
	void btValue3Pressed();
	void valueChanged();
	void value2Changed();
	void value3Changed();
private:
	CDialogResultatEtalon(void);
	void setConnexion();
private:

	static CDialogResultatEtalon* singleton;
	CDialogPaveNum* m_pPaveNum;
	QString m_sDialogTittle;
	QString m_sTittle;
	QString m_sValue;
	QTabWidget* m_tabWidget;
	QPushButton* m_btValue;
	QLabel* m_lblValue;
	QPushButton* m_btValue2;
	QLabel* m_lblValue2;
	QPushButton* m_btValue3;
	QPushButton* m_btValue4;
	QLabel* m_lblMessageErreur;
	QLabel* m_lblValue3;
	QLabel* m_lblValue4;
	//QVBoxLayout* m_layoutMenu;
	QPushButton* m_btBack;
	QPushButton* m_btApply;
	
};

#endif // CDIALOGRESULTATETALON_H
