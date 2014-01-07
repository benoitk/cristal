/****************************************************************************
** Meta object code from reading C++ file 'CWinStreamControler.h'
**
** Created: Thu 19. Dec 09:22:04 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.4)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../CWinStreamControler.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'CWinStreamControler.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CWinStreamControler[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
       7,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      21,   20,   20,   20, 0x0a,
      37,   20,   20,   20, 0x0a,
      61,   20,   20,   20, 0x0a,
     100,   86,   20,   20, 0x0a,
     123,   86,   20,   20, 0x0a,
     160,  150,   20,   20, 0x0a,
     190,  179,   20,   20, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_CWinStreamControler[] = {
    "CWinStreamControler\0\0btBackPressed()\0"
    "btOnVoieActivePressed()\0"
    "btOffVoieActivePressed()\0arg_numMesure\0"
    "btNextPagePressed(int)\0"
    "btPreviousPagePressed(int)\0arg_index\0"
    "btEditPressed(int)\0arg_numTab\0"
    "slotTabChanged(int)\0"
};

void CWinStreamControler::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        CWinStreamControler *_t = static_cast<CWinStreamControler *>(_o);
        switch (_id) {
        case 0: _t->btBackPressed(); break;
        case 1: _t->btOnVoieActivePressed(); break;
        case 2: _t->btOffVoieActivePressed(); break;
        case 3: _t->btNextPagePressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 4: _t->btPreviousPagePressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 5: _t->btEditPressed((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 6: _t->slotTabChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        default: ;
        }
    }
}

const QMetaObjectExtraData CWinStreamControler::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject CWinStreamControler::staticMetaObject = {
    { &QObject::staticMetaObject, qt_meta_stringdata_CWinStreamControler,
      qt_meta_data_CWinStreamControler, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CWinStreamControler::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CWinStreamControler::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CWinStreamControler::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CWinStreamControler))
        return static_cast<void*>(const_cast< CWinStreamControler*>(this));
    return QObject::qt_metacast(_clname);
}

int CWinStreamControler::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 7)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 7;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
