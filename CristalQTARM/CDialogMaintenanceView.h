#ifndef CDIALOG_MAINTENANCE_VIEW
#define CDIALOG_MAINTENANCE_VIEW

#include <QDialog>
#include <QVector>
#include <QString>

class QPushButton;


class CDialogMaintenanceView: public QDialog
{
	Q_OBJECT
public:
	CDialogMaintenanceView(void);
	
public:
	void setTittle(const QString& sTitre);
	void addLine(const QString& sLblTittle, const QString& sValue);
	void init();
	QString getNextValue(); //dépilage dans le même ordre que addLine

private:
	QString m_sDialogTittle;
	QVector<QString> m_vTittle;
	QVector<QString> m_vValue;
	int m_iIndexLine;

	//QVBoxLayout* m_layoutMenu;
	QPushButton* m_btBack;

};

#endif
