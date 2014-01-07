/****************************************************************************
** Meta object code from reading C++ file 'CWinEVPompeControler.h'
**
** Created: Thu 19. Dec 09:22:06 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.4)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../CWinEVPompeControler.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'CWinEVPompeControler.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CWinEVPompeControler[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
      17,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      22,   21,   21,   21, 0x0a,
      38,   21,   21,   21, 0x0a,
      55,   21,   21,   21, 0x0a,
      73,   21,   21,   21, 0x0a,
      93,   21,   21,   21, 0x0a,
     114,   21,   21,   21, 0x0a,
     134,   21,   21,   21, 0x0a,
     155,   21,   21,   21, 0x0a,
     175,   21,   21,   21, 0x0a,
     196,   21,   21,   21, 0x0a,
     216,   21,   21,   21, 0x0a,
     237,   21,   21,   21, 0x0a,
     257,   21,   21,   21, 0x0a,
     278,   21,   21,   21, 0x0a,
     298,   21,   21,   21, 0x0a,
     325,  319,   21,   21, 0x0a,
     341,   21,   21,   21, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_CWinEVPompeControler[] = {
    "CWinEVPompeControler\0\0btBackPressed()\0"
    "btOnEV1Pressed()\0btOffEV1Pressed()\0"
    "btOnPompe1Pressed()\0btOffPompe1Pressed()\0"
    "btOnPompe2Pressed()\0btOffPompe2Pressed()\0"
    "btOnPompe3Pressed()\0btOffPompe3Pressed()\0"
    "btOnPompe4Pressed()\0btOffPompe4Pressed()\0"
    "btOnPompe5Pressed()\0btOffPompe5Pressed()\0"
    "btOnPompe6Pressed()\0btOffPompe6Pressed()\0"
    "index\0tabChanged(int)\0userSessionClosed()\0"
};

void CWinEVPompeControler::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        CWinEVPompeControler *_t = static_cast<CWinEVPompeControler *>(_o);
        switch (_id) {
        case 0: _t->btBackPressed(); break;
        case 1: _t->btOnEV1Pressed(); break;
        case 2: _t->btOffEV1Pressed(); break;
        case 3: _t->btOnPompe1Pressed(); break;
        case 4: _t->btOffPompe1Pressed(); break;
        case 5: _t->btOnPompe2Pressed(); break;
        case 6: _t->btOffPompe2Pressed(); break;
        case 7: _t->btOnPompe3Pressed(); break;
        case 8: _t->btOffPompe3Pressed(); break;
        case 9: _t->btOnPompe4Pressed(); break;
        case 10: _t->btOffPompe4Pressed(); break;
        case 11: _t->btOnPompe5Pressed(); break;
        case 12: _t->btOffPompe5Pressed(); break;
        case 13: _t->btOnPompe6Pressed(); break;
        case 14: _t->btOffPompe6Pressed(); break;
        case 15: _t->tabChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 16: _t->userSessionClosed(); break;
        default: ;
        }
    }
}

const QMetaObjectExtraData CWinEVPompeControler::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject CWinEVPompeControler::staticMetaObject = {
    { &InterfaceUserSession::staticMetaObject, qt_meta_stringdata_CWinEVPompeControler,
      qt_meta_data_CWinEVPompeControler, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CWinEVPompeControler::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CWinEVPompeControler::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CWinEVPompeControler::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CWinEVPompeControler))
        return static_cast<void*>(const_cast< CWinEVPompeControler*>(this));
    return InterfaceUserSession::qt_metacast(_clname);
}

int CWinEVPompeControler::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = InterfaceUserSession::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 17)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 17;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
