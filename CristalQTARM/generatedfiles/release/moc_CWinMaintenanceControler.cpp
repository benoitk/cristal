/****************************************************************************
** Meta object code from reading C++ file 'CWinMaintenanceControler.h'
**
** Created: Thu 19. Dec 09:22:05 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.4)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../CWinMaintenanceControler.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'CWinMaintenanceControler.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CWinMaintenanceControler[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
      16,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      26,   25,   25,   25, 0x0a,
      42,   25,   25,   25, 0x0a,
      66,   25,   25,   25, 0x0a,
      96,   25,   25,   25, 0x0a,
     122,   25,   25,   25, 0x0a,
     145,   25,   25,   25, 0x0a,
     161,   25,   25,   25, 0x0a,
     184,   25,   25,   25, 0x0a,
     207,   25,   25,   25, 0x0a,
     236,   25,   25,   25, 0x0a,
     261,   25,   25,   25, 0x0a,
     283,   25,   25,   25, 0x0a,
     310,   25,   25,   25, 0x0a,
     339,   25,   25,   25, 0x0a,
     374,  368,   25,   25, 0x0a,
     390,   25,   25,   25, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_CWinMaintenanceControler[] = {
    "CWinMaintenanceControler\0\0btBackPressed()\0"
    "btExecuteCalibPressed()\0"
    "btExecuteCalibInLinePressed()\0"
    "btExecuteCleanupPressed()\0"
    "btExecuteZeroPressed()\0btStopPressed()\0"
    "executeCalibRejected()\0executeCalibAccepted()\0"
    "executeCalibInLineAccepted()\0"
    "executeCleanupAccepted()\0executeZeroAccepted()\0"
    "cycleMaintenanceFinished()\0"
    "cycleCalibFinishedAccepted()\0"
    "cycleCalibFinishedRejected()\0index\0"
    "tabChanged(int)\0userSessionClosed()\0"
};

void CWinMaintenanceControler::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        CWinMaintenanceControler *_t = static_cast<CWinMaintenanceControler *>(_o);
        switch (_id) {
        case 0: _t->btBackPressed(); break;
        case 1: _t->btExecuteCalibPressed(); break;
        case 2: _t->btExecuteCalibInLinePressed(); break;
        case 3: _t->btExecuteCleanupPressed(); break;
        case 4: _t->btExecuteZeroPressed(); break;
        case 5: _t->btStopPressed(); break;
        case 6: _t->executeCalibRejected(); break;
        case 7: _t->executeCalibAccepted(); break;
        case 8: _t->executeCalibInLineAccepted(); break;
        case 9: _t->executeCleanupAccepted(); break;
        case 10: _t->executeZeroAccepted(); break;
        case 11: _t->cycleMaintenanceFinished(); break;
        case 12: _t->cycleCalibFinishedAccepted(); break;
        case 13: _t->cycleCalibFinishedRejected(); break;
        case 14: _t->tabChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 15: _t->userSessionClosed(); break;
        default: ;
        }
    }
}

const QMetaObjectExtraData CWinMaintenanceControler::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject CWinMaintenanceControler::staticMetaObject = {
    { &InterfaceUserSession::staticMetaObject, qt_meta_stringdata_CWinMaintenanceControler,
      qt_meta_data_CWinMaintenanceControler, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CWinMaintenanceControler::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CWinMaintenanceControler::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CWinMaintenanceControler::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CWinMaintenanceControler))
        return static_cast<void*>(const_cast< CWinMaintenanceControler*>(this));
    return InterfaceUserSession::qt_metacast(_clname);
}

int CWinMaintenanceControler::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = InterfaceUserSession::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 16)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 16;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
