/****************************************************************************
** Meta object code from reading C++ file 'CWinExternalCardControler.h'
**
** Created: Thu 19. Dec 09:22:06 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.4)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../CWinExternalCardControler.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'CWinExternalCardControler.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CWinExternalCardControler[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
       9,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      27,   26,   26,   26, 0x0a,
      53,   43,   26,   26, 0x0a,
      76,   43,   26,   26, 0x0a,
     100,   26,   26,   26, 0x0a,
     131,   26,   26,   26, 0x0a,
     162,   26,   26,   26, 0x0a,
     186,   26,   26,   26, 0x0a,
     211,   26,   26,   26, 0x0a,
     236,   26,   26,   26, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_CWinExternalCardControler[] = {
    "CWinExternalCardControler\0\0btBackPressed()\0"
    "numRelais\0btOnRelaisPressed(int)\0"
    "btOffRelaisPressed(int)\0"
    "btValMaxConvertisseurPressed()\0"
    "btValMinConvertisseurPressed()\0"
    "btRadioTest4mAPressed()\0"
    "btRadioTest12mAPressed()\0"
    "btRadioTest20mAPressed()\0userSessionClosed()\0"
};

void CWinExternalCardControler::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        CWinExternalCardControler *_t = static_cast<CWinExternalCardControler *>(_o);
        switch (_id) {
        case 0: _t->btBackPressed(); break;
        case 1: _t->btOnRelaisPressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 2: _t->btOffRelaisPressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 3: _t->btValMaxConvertisseurPressed(); break;
        case 4: _t->btValMinConvertisseurPressed(); break;
        case 5: _t->btRadioTest4mAPressed(); break;
        case 6: _t->btRadioTest12mAPressed(); break;
        case 7: _t->btRadioTest20mAPressed(); break;
        case 8: _t->userSessionClosed(); break;
        default: ;
        }
    }
}

const QMetaObjectExtraData CWinExternalCardControler::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject CWinExternalCardControler::staticMetaObject = {
    { &InterfaceUserSession::staticMetaObject, qt_meta_stringdata_CWinExternalCardControler,
      qt_meta_data_CWinExternalCardControler, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CWinExternalCardControler::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CWinExternalCardControler::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CWinExternalCardControler::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CWinExternalCardControler))
        return static_cast<void*>(const_cast< CWinExternalCardControler*>(this));
    return InterfaceUserSession::qt_metacast(_clname);
}

int CWinExternalCardControler::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = InterfaceUserSession::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 9)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 9;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
