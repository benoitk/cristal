/****************************************************************************
** Meta object code from reading C++ file 'CWinMeasureCardControler.h'
**
** Created: Thu 19. Dec 09:22:05 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.4)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../CWinMeasureCardControler.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'CWinMeasureCardControler.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CWinMeasureCardControler[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
      14,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      26,   25,   25,   25, 0x0a,
      42,   25,   25,   25, 0x0a,
      62,   25,   25,   25, 0x0a,
      83,   25,   25,   25, 0x0a,
     103,   25,   25,   25, 0x0a,
     124,   25,   25,   25, 0x0a,
     144,   25,   25,   25, 0x0a,
     165,   25,   25,   25, 0x0a,
     185,   25,   25,   25, 0x0a,
     206,   25,   25,   25, 0x0a,
     226,   25,   25,   25, 0x0a,
     247,   25,   25,   25, 0x0a,
     267,   25,   25,   25, 0x0a,
     288,   25,   25,   25, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_CWinMeasureCardControler[] = {
    "CWinMeasureCardControler\0\0btBackPressed()\0"
    "btOnLocal1Pressed()\0btOffLocal1Pressed()\0"
    "btOnLocal2Pressed()\0btOffLocal2Pressed()\0"
    "btOnLocal3Pressed()\0btOffLocal3Pressed()\0"
    "btOnLocal4Pressed()\0btOffLocal4Pressed()\0"
    "btOnLocal5Pressed()\0btOffLocal5Pressed()\0"
    "btOnLocal6Pressed()\0btOffLocal6Pressed()\0"
    "userSessionClosed()\0"
};

void CWinMeasureCardControler::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        CWinMeasureCardControler *_t = static_cast<CWinMeasureCardControler *>(_o);
        switch (_id) {
        case 0: _t->btBackPressed(); break;
        case 1: _t->btOnLocal1Pressed(); break;
        case 2: _t->btOffLocal1Pressed(); break;
        case 3: _t->btOnLocal2Pressed(); break;
        case 4: _t->btOffLocal2Pressed(); break;
        case 5: _t->btOnLocal3Pressed(); break;
        case 6: _t->btOffLocal3Pressed(); break;
        case 7: _t->btOnLocal4Pressed(); break;
        case 8: _t->btOffLocal4Pressed(); break;
        case 9: _t->btOnLocal5Pressed(); break;
        case 10: _t->btOffLocal5Pressed(); break;
        case 11: _t->btOnLocal6Pressed(); break;
        case 12: _t->btOffLocal6Pressed(); break;
        case 13: _t->userSessionClosed(); break;
        default: ;
        }
    }
    Q_UNUSED(_a);
}

const QMetaObjectExtraData CWinMeasureCardControler::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject CWinMeasureCardControler::staticMetaObject = {
    { &InterfaceUserSession::staticMetaObject, qt_meta_stringdata_CWinMeasureCardControler,
      qt_meta_data_CWinMeasureCardControler, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CWinMeasureCardControler::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CWinMeasureCardControler::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CWinMeasureCardControler::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CWinMeasureCardControler))
        return static_cast<void*>(const_cast< CWinMeasureCardControler*>(this));
    return InterfaceUserSession::qt_metacast(_clname);
}

int CWinMeasureCardControler::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = InterfaceUserSession::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 14)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 14;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
