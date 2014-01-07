/****************************************************************************
** Meta object code from reading C++ file 'CWinSchedulerControler.h'
**
** Created: Thu 19. Dec 09:22:04 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.4)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../CWinSchedulerControler.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'CWinSchedulerControler.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CWinSchedulerControler[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
      23,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      24,   23,   23,   23, 0x0a,
      40,   23,   23,   23, 0x0a,
      67,   23,   23,   23, 0x0a,
      89,   23,   23,   23, 0x0a,
     120,   23,   23,   23, 0x0a,
     144,   23,   23,   23, 0x0a,
     171,   23,   23,   23, 0x0a,
     199,   23,   23,   23, 0x0a,
     219,   23,   23,   23, 0x0a,
     255,  245,   23,   23, 0x0a,
     281,  245,   23,   23, 0x0a,
     303,  245,   23,   23, 0x0a,
     326,  245,   23,   23, 0x0a,
     347,   23,   23,   23, 0x0a,
     364,   23,   23,   23, 0x0a,
     382,   23,   23,   23, 0x0a,
     398,   23,   23,   23, 0x0a,
     415,   23,   23,   23, 0x0a,
     434,   23,   23,   23, 0x0a,
     451,   23,   23,   23, 0x0a,
     469,   23,   23,   23, 0x0a,
     485,   23,   23,   23, 0x0a,
     502,   23,   23,   23, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_CWinSchedulerControler[] = {
    "CWinSchedulerControler\0\0btBackPressed()\0"
    "btNbCyleAvantZeroPressed()\0"
    "btRemoteCtrlPressed()\0"
    "btConsigneTemperaturePressed()\0"
    "btConsigneGainPressed()\0"
    "btReglagePressionPressed()\0"
    "btTempsVoieAttentePressed()\0"
    "userSessionClosed()\0btNumEscalveJBUSPressed()\0"
    "arg_numBt\0btConfigSeuilPressed(int)\0"
    "btNumVoiePressed(int)\0btTempsSeqPressed(int)\0"
    "btDeletePressed(int)\0btYearPPressed()\0"
    "btMonthPPressed()\0btDayPPressed()\0"
    "btHourPPressed()\0btMinutePPressed()\0"
    "btYearMPressed()\0btMonthMPressed()\0"
    "btDayMPressed()\0btHourMPressed()\0"
    "btMinuteMPressed()\0"
};

void CWinSchedulerControler::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        CWinSchedulerControler *_t = static_cast<CWinSchedulerControler *>(_o);
        switch (_id) {
        case 0: _t->btBackPressed(); break;
        case 1: _t->btNbCyleAvantZeroPressed(); break;
        case 2: _t->btRemoteCtrlPressed(); break;
        case 3: _t->btConsigneTemperaturePressed(); break;
        case 4: _t->btConsigneGainPressed(); break;
        case 5: _t->btReglagePressionPressed(); break;
        case 6: _t->btTempsVoieAttentePressed(); break;
        case 7: _t->userSessionClosed(); break;
        case 8: _t->btNumEscalveJBUSPressed(); break;
        case 9: _t->btConfigSeuilPressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 10: _t->btNumVoiePressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 11: _t->btTempsSeqPressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 12: _t->btDeletePressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 13: _t->btYearPPressed(); break;
        case 14: _t->btMonthPPressed(); break;
        case 15: _t->btDayPPressed(); break;
        case 16: _t->btHourPPressed(); break;
        case 17: _t->btMinutePPressed(); break;
        case 18: _t->btYearMPressed(); break;
        case 19: _t->btMonthMPressed(); break;
        case 20: _t->btDayMPressed(); break;
        case 21: _t->btHourMPressed(); break;
        case 22: _t->btMinuteMPressed(); break;
        default: ;
        }
    }
}

const QMetaObjectExtraData CWinSchedulerControler::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject CWinSchedulerControler::staticMetaObject = {
    { &InterfaceUserSession::staticMetaObject, qt_meta_stringdata_CWinSchedulerControler,
      qt_meta_data_CWinSchedulerControler, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CWinSchedulerControler::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CWinSchedulerControler::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CWinSchedulerControler::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CWinSchedulerControler))
        return static_cast<void*>(const_cast< CWinSchedulerControler*>(this));
    return InterfaceUserSession::qt_metacast(_clname);
}

int CWinSchedulerControler::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = InterfaceUserSession::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 23)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 23;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
