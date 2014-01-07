/****************************************************************************
** Meta object code from reading C++ file 'CWinMainControler.h'
**
** Created: Thu 19. Dec 09:22:05 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.4)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../CWinMainControler.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'CWinMainControler.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CWinMainControler[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
      24,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      19,   18,   18,   18, 0x0a,
      39,   18,   18,   18, 0x0a,
      60,   18,   18,   18, 0x0a,
      76,   18,   18,   18, 0x0a,
      99,   18,   18,   18, 0x0a,
     115,   18,   18,   18, 0x0a,
     131,   18,   18,   18, 0x0a,
     158,  148,   18,   18, 0x0a,
     179,   18,   18,   18, 0x0a,
     202,   18,   18,   18, 0x0a,
     226,   18,   18,   18, 0x0a,
     245,   18,   18,   18, 0x0a,
     268,   18,   18,   18, 0x0a,
     290,   18,   18,   18, 0x0a,
     314,   18,   18,   18, 0x0a,
     337,   18,   18,   18, 0x0a,
     357,   18,   18,   18, 0x0a,
     378,   18,   18,   18, 0x0a,
     394,   18,   18,   18, 0x0a,
     410,   18,   18,   18, 0x0a,
     431,   18,   18,   18, 0x0a,
     458,  452,   18,   18, 0x0a,
     474,   18,   18,   18, 0x0a,
     494,   18,   18,   18, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_CWinMainControler[] = {
    "CWinMainControler\0\0userSessionClosed()\0"
    "btPlayPausePressed()\0btStopPressed()\0"
    "btStopEndCylePressed()\0btNextPressed()\0"
    "btDiagPressed()\0btAlarmPressed()\0"
    "numStream\0btDetailPressed(int)\0"
    "btMeasureCardPressed()\0btExternalCardPressed()\0"
    "btEVPompePressed()\0btMaintenancePressed()\0"
    "btSequenceurPressed()\0btCopyLogFilesPressed()\0"
    "btInformationPressed()\0btExplorerPressed()\0"
    "btParameterPressed()\0btSavePressed()\0"
    "btQuitPressed()\0btNextGraphPressed()\0"
    "btPrevGraphPressed()\0index\0tabChanged(int)\0"
    "getErrorIOAndJBus()\0takeScreenshot()\0"
};

void CWinMainControler::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        CWinMainControler *_t = static_cast<CWinMainControler *>(_o);
        switch (_id) {
        case 0: _t->userSessionClosed(); break;
        case 1: _t->btPlayPausePressed(); break;
        case 2: _t->btStopPressed(); break;
        case 3: _t->btStopEndCylePressed(); break;
        case 4: _t->btNextPressed(); break;
        case 5: _t->btDiagPressed(); break;
        case 6: _t->btAlarmPressed(); break;
        case 7: _t->btDetailPressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 8: _t->btMeasureCardPressed(); break;
        case 9: _t->btExternalCardPressed(); break;
        case 10: _t->btEVPompePressed(); break;
        case 11: _t->btMaintenancePressed(); break;
        case 12: _t->btSequenceurPressed(); break;
        case 13: _t->btCopyLogFilesPressed(); break;
        case 14: _t->btInformationPressed(); break;
        case 15: _t->btExplorerPressed(); break;
        case 16: _t->btParameterPressed(); break;
        case 17: _t->btSavePressed(); break;
        case 18: _t->btQuitPressed(); break;
        case 19: _t->btNextGraphPressed(); break;
        case 20: _t->btPrevGraphPressed(); break;
        case 21: _t->tabChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 22: _t->getErrorIOAndJBus(); break;
        case 23: _t->takeScreenshot(); break;
        default: ;
        }
    }
}

const QMetaObjectExtraData CWinMainControler::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject CWinMainControler::staticMetaObject = {
    { &InterfaceUserSession::staticMetaObject, qt_meta_stringdata_CWinMainControler,
      qt_meta_data_CWinMainControler, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CWinMainControler::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CWinMainControler::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CWinMainControler::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CWinMainControler))
        return static_cast<void*>(const_cast< CWinMainControler*>(this));
    return InterfaceUserSession::qt_metacast(_clname);
}

int CWinMainControler::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = InterfaceUserSession::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 24)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 24;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
