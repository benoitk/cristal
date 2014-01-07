#ifndef CPUSHBUTTON
#define CPUSHBUTTON
#include "header_qt.h"

class CPushButton: public QPushButton
{
	Q_OBJECT
public:
	CPushButton();
	CPushButton(const QString& arg_Text);
	CPushButton(int id);
	CPushButton(int id, const QString& arg_Text);
	int getId()const {return m_nId;};

public slots:
	void objectClicked();

signals:
	void clicked(int id);

private:
	int m_nId;
};

#endif
