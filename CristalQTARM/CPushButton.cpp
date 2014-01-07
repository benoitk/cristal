#include "CPushButton.h"

CPushButton::CPushButton()
{
	m_nId = -1;
	connect(this, SIGNAL(clicked()), this, SLOT(objectClicked()));
}
CPushButton::CPushButton(int id)
{
	m_nId = id;
	connect(this, SIGNAL(clicked()), this, SLOT(objectClicked()));
}
CPushButton::CPushButton(const QString& arg_Text):QPushButton(arg_Text)
{
	m_nId = -1;
	connect(this, SIGNAL(clicked()), this, SLOT(objectClicked()));
}
CPushButton::CPushButton(int id, const QString& arg_Text):QPushButton(arg_Text)
{
	m_nId = id;
	connect(this, SIGNAL(clicked()), this, SLOT(objectClicked()));
}

void CPushButton::objectClicked()
{
//	qDebug() << "### CPushButton::objectClicked()";
	emit clicked(m_nId);
}