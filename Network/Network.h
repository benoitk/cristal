	
// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the NETWORK_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// NETWORK_API functions as being imported from a DLL, wheras this DLL sees symbols
// defined with this macro as being exported.
#ifdef NETWORK_EXPORTS
#define NETWORK_API __declspec(dllexport)

#else
#define NETWORK_API __declspec(dllimport)
#endif

#include <winsock.h>
#include "tracedebug.h"
#include "FichierIni.h"
#include "thread.h"
#include "threadInterface.h"
#include "sockbase.h"
#include "sockTcpServeur.h"
#include "sockTcpClient.h"
#include "serial.h"

#include "elem.h"
#include "trameJBUS.h"
#include "mesure.h"
#include "cycle.h"
#include "stream.h"

