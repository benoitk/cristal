/****************************************************************************
** Meta object code from reading C++ file 'CDialogPaveNum.h'
**
** Created: Thu 19. Dec 09:22:08 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.4)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../CDialogPaveNum.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'CDialogPaveNum.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CDialogPaveNum[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
      13,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      16,   15,   15,   15, 0x0a,
      32,   15,   15,   15, 0x0a,
      47,   15,   15,   15, 0x0a,
      62,   15,   15,   15, 0x0a,
      79,   15,   15,   15, 0x0a,
      95,   15,   15,   15, 0x0a,
     111,   15,   15,   15, 0x0a,
     126,   15,   15,   15, 0x0a,
     143,   15,   15,   15, 0x0a,
     160,   15,   15,   15, 0x0a,
     176,   15,   15,   15, 0x0a,
     193,   15,   15,   15, 0x0a,
     214,   15,   15,   15, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_CDialogPaveNum[] = {
    "CDialogPaveNum\0\0btZeroPressed()\0"
    "btOnePressed()\0btTwoPressed()\0"
    "btThreePressed()\0btFourPressed()\0"
    "btFivePressed()\0btSixPressed()\0"
    "btSevenPressed()\0btEightPressed()\0"
    "btNinePressed()\0btCommaPressed()\0"
    "btPlusMinusPressed()\0btDeletePressed()\0"
};

void CDialogPaveNum::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        CDialogPaveNum *_t = static_cast<CDialogPaveNum *>(_o);
        switch (_id) {
        case 0: _t->btZeroPressed(); break;
        case 1: _t->btOnePressed(); break;
        case 2: _t->btTwoPressed(); break;
        case 3: _t->btThreePressed(); break;
        case 4: _t->btFourPressed(); break;
        case 5: _t->btFivePressed(); break;
        case 6: _t->btSixPressed(); break;
        case 7: _t->btSevenPressed(); break;
        case 8: _t->btEightPressed(); break;
        case 9: _t->btNinePressed(); break;
        case 10: _t->btCommaPressed(); break;
        case 11: _t->btPlusMinusPressed(); break;
        case 12: _t->btDeletePressed(); break;
        default: ;
        }
    }
    Q_UNUSED(_a);
}

const QMetaObjectExtraData CDialogPaveNum::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject CDialogPaveNum::staticMetaObject = {
    { &QDialog::staticMetaObject, qt_meta_stringdata_CDialogPaveNum,
      qt_meta_data_CDialogPaveNum, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CDialogPaveNum::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CDialogPaveNum::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CDialogPaveNum::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CDialogPaveNum))
        return static_cast<void*>(const_cast< CDialogPaveNum*>(this));
    return QDialog::qt_metacast(_clname);
}

int CDialogPaveNum::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 13)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 13;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
