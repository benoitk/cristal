/********************************************************************************
** Form generated from reading UI file 'cristalqtarm.ui'
**
** Created: Thu 19. Dec 09:22:03 2013
**      by: Qt User Interface Compiler version 4.8.4
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CRISTALQTARM_H
#define UI_CRISTALQTARM_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QHeaderView>
#include <QtGui/QMainWindow>
#include <QtGui/QMenu>
#include <QtGui/QMenuBar>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_CristalQTARMClass
{
public:
    QAction *actionExit;
    QWidget *centralWidget;
    QMenuBar *menuBar;
    QMenu *menu_File;

    void setupUi(QMainWindow *CristalQTARMClass)
    {
        if (CristalQTARMClass->objectName().isEmpty())
            CristalQTARMClass->setObjectName(QString::fromUtf8("CristalQTARMClass"));
        CristalQTARMClass->resize(600, 400);
        actionExit = new QAction(CristalQTARMClass);
        actionExit->setObjectName(QString::fromUtf8("actionExit"));
        centralWidget = new QWidget(CristalQTARMClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        CristalQTARMClass->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(CristalQTARMClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menu_File = new QMenu(menuBar);
        menu_File->setObjectName(QString::fromUtf8("menu_File"));
        CristalQTARMClass->setMenuBar(menuBar);

        menuBar->addAction(menu_File->menuAction());
        menu_File->addAction(actionExit);

        retranslateUi(CristalQTARMClass);
        QObject::connect(actionExit, SIGNAL(triggered()), CristalQTARMClass, SLOT(close()));

        QMetaObject::connectSlotsByName(CristalQTARMClass);
    } // setupUi

    void retranslateUi(QMainWindow *CristalQTARMClass)
    {
        CristalQTARMClass->setWindowTitle(QApplication::translate("CristalQTARMClass", "CristalQTARM", 0, QApplication::UnicodeUTF8));
        actionExit->setText(QApplication::translate("CristalQTARMClass", "E&xit", 0, QApplication::UnicodeUTF8));
        menu_File->setTitle(QApplication::translate("CristalQTARMClass", "&File", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class CristalQTARMClass: public Ui_CristalQTARMClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CRISTALQTARM_H
