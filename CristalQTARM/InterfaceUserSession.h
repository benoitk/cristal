#ifndef INTERFACE_USER_SESSION
#define INTERFACE_USER_SESSION
#include "header_qt.h"
#include "header.h"

class InterfaceUserSession : public QObject
{
	Q_OBJECT
public slots:
	virtual void userSessionClosed()=0;

};

#endif INTERFACE_USER_SESSION
