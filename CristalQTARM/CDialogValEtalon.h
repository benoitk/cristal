#ifndef CDIALOG_VAL_ETALON
#define CDIALOG_VAL_ETALON

#include <QDialog>
#include <QString>
class CDialogPaveNum;
class QTabWidget;
class QPushButton;
class QLabel;
class CDialogValEtalon: public QDialog
{
		Q_OBJECT

public:
	static CDialogValEtalon* getInstance();
	void setTittle(const QString& sTitre);
	void setLine(const QString& sLblTittle, const QString& sValue);
	void setLine2(const QString& sLblTittle, const QString& sValue);
	void init();
	QString getReturnValue(); 
	QString getReturnValue2(); 

public slots:
	void btValuePressed();
	void valueChanged();
    void btValuePressed2();
	void valueChanged2();
private:
	CDialogValEtalon(void);
	void setConnexion();
private:

	static CDialogValEtalon* singleton;
	CDialogPaveNum* m_pPaveNum;
	QString m_sDialogTittle;
	QString m_sTittle;
	QString m_sValue;
	QTabWidget* m_tabWidget;
	QPushButton* m_btValue;
	QPushButton* m_btValue2;
	QLabel* m_lblValue;
	QLabel* m_lblValue2;
	//QVBoxLayout* m_layoutMenu;
	QPushButton* m_btBack;
	QPushButton* m_btApply;
};

#endif
