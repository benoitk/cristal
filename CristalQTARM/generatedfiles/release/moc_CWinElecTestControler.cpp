/****************************************************************************
** Meta object code from reading C++ file 'CWinElecTestControler.h'
**
** Created: Thu 19. Dec 09:22:07 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.4)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../CWinElecTestControler.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'CWinElecTestControler.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CWinElecTestControler[] = {

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
      23,   22,   22,   22, 0x0a,
      49,   39,   22,   22, 0x0a,
      68,   39,   22,   22, 0x0a,
      88,   22,   22,   22, 0x0a,
     116,  103,   22,   22, 0x0a,
     138,  103,   22,   22, 0x0a,
     171,  161,   22,   22, 0x0a,
     194,  161,   22,   22, 0x0a,
     226,  218,   22,   22, 0x0a,
     257,  218,   22,   22, 0x0a,
     282,   22,   22,   22, 0x0a,
     308,   22,   22,   22, 0x0a,
     334,   22,   22,   22, 0x0a,
     363,   22,   22,   22, 0x0a,
     405,  392,   22,   22, 0x0a,
     427,  392,   22,   22, 0x0a,
     450,   22,   22,   22, 0x0a,
     481,   22,   22,   22, 0x0a,
     512,   22,   22,   22, 0x0a,
     536,   22,   22,   22, 0x0a,
     561,   22,   22,   22, 0x0a,
     592,  586,   22,   22, 0x0a,
     608,   22,   22,   22, 0x0a,
     628,   22,   22,   22, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_CWinElecTestControler[] = {
    "CWinElecTestControler\0\0btBackPressed()\0"
    "arg_numEV\0btOnEVPressed(int)\0"
    "btOffEVPressed(int)\0btOffChauffe()\0"
    "arg_numPompe\0btOnPompePressed(int)\0"
    "btOffPompePressed(int)\0numRelais\0"
    "btOnRelaisPressed(int)\0btOffRelaisPressed(int)\0"
    "numVoie\0btOnStreamSelectorPressed(int)\0"
    "btOffStreamSelector(int)\0"
    "btNextPageRelaisPressed()\0"
    "btPrevPageRelaisPressed()\0"
    "btNextPageSortieAnaPressed()\0"
    "btPrevPageSortieAnaPressed()\0arg_numLocal\0"
    "btOnLocalPressed(int)\0btOffLocalPressed(int)\0"
    "btValMaxConvertisseurPressed()\0"
    "btValMinConvertisseurPressed()\0"
    "btRadioTest4mAPressed()\0"
    "btRadioTest12mAPressed()\0"
    "btRadioTest20mAPressed()\0index\0"
    "tabChanged(int)\0userSessionClosed()\0"
    "slotArretPompes()\0"
};

void CWinElecTestControler::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        CWinElecTestControler *_t = static_cast<CWinElecTestControler *>(_o);
        switch (_id) {
        case 0: _t->btBackPressed(); break;
        case 1: _t->btOnEVPressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 2: _t->btOffEVPressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 3: _t->btOffChauffe(); break;
        case 4: _t->btOnPompePressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 5: _t->btOffPompePressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 6: _t->btOnRelaisPressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 7: _t->btOffRelaisPressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 8: _t->btOnStreamSelectorPressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 9: _t->btOffStreamSelector((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 10: _t->btNextPageRelaisPressed(); break;
        case 11: _t->btPrevPageRelaisPressed(); break;
        case 12: _t->btNextPageSortieAnaPressed(); break;
        case 13: _t->btPrevPageSortieAnaPressed(); break;
        case 14: _t->btOnLocalPressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 15: _t->btOffLocalPressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 16: _t->btValMaxConvertisseurPressed(); break;
        case 17: _t->btValMinConvertisseurPressed(); break;
        case 18: _t->btRadioTest4mAPressed(); break;
        case 19: _t->btRadioTest12mAPressed(); break;
        case 20: _t->btRadioTest20mAPressed(); break;
        case 21: _t->tabChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 22: _t->userSessionClosed(); break;
        case 23: _t->slotArretPompes(); break;
        default: ;
        }
    }
}

const QMetaObjectExtraData CWinElecTestControler::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject CWinElecTestControler::staticMetaObject = {
    { &InterfaceUserSession::staticMetaObject, qt_meta_stringdata_CWinElecTestControler,
      qt_meta_data_CWinElecTestControler, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CWinElecTestControler::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CWinElecTestControler::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CWinElecTestControler::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CWinElecTestControler))
        return static_cast<void*>(const_cast< CWinElecTestControler*>(this));
    return InterfaceUserSession::qt_metacast(_clname);
}

int CWinElecTestControler::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
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
