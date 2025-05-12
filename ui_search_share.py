# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'search_share.ui'
##
## Created by: Qt User Interface Compiler version 6.9.0
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QApplication, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QMainWindow, QMenuBar, QPushButton,
    QSizePolicy, QStatusBar, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget)

class Ui_SearchWindow(object):
    def setupUi(self, SearchWindow):
        if not SearchWindow.objectName():
            SearchWindow.setObjectName(u"SearchWindow")
        SearchWindow.resize(800, 600)
        self.centralwidget = QWidget(SearchWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.verticalLayout = QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.label = QLabel(self.centralwidget)
        self.label.setObjectName(u"label")

        self.horizontalLayout.addWidget(self.label)

        self.lineEdit_ip = QLineEdit(self.centralwidget)
        self.lineEdit_ip.setObjectName(u"lineEdit_ip")
        self.lineEdit_ip.setReadOnly(True)

        self.horizontalLayout.addWidget(self.lineEdit_ip)

        self.label_2 = QLabel(self.centralwidget)
        self.label_2.setObjectName(u"label_2")

        self.horizontalLayout.addWidget(self.label_2)

        self.lineEdit_subnet = QLineEdit(self.centralwidget)
        self.lineEdit_subnet.setObjectName(u"lineEdit_subnet")

        self.horizontalLayout.addWidget(self.lineEdit_subnet)

        self.pushButton_search = QPushButton(self.centralwidget)
        self.pushButton_search.setObjectName(u"pushButton_search")

        self.horizontalLayout.addWidget(self.pushButton_search)


        self.verticalLayout.addLayout(self.horizontalLayout)

        self.treeWidget_sharelist = QTreeWidget(self.centralwidget)
        __qtreewidgetitem = QTreeWidgetItem()
        __qtreewidgetitem.setText(0, u"1");
        self.treeWidget_sharelist.setHeaderItem(__qtreewidgetitem)
        self.treeWidget_sharelist.setObjectName(u"treeWidget_sharelist")

        self.verticalLayout.addWidget(self.treeWidget_sharelist)

        SearchWindow.setCentralWidget(self.centralwidget)
        self.menubar = QMenuBar(SearchWindow)
        self.menubar.setObjectName(u"menubar")
        self.menubar.setGeometry(QRect(0, 0, 800, 21))
        SearchWindow.setMenuBar(self.menubar)
        self.statusbar = QStatusBar(SearchWindow)
        self.statusbar.setObjectName(u"statusbar")
        SearchWindow.setStatusBar(self.statusbar)

        self.retranslateUi(SearchWindow)

        QMetaObject.connectSlotsByName(SearchWindow)
    # setupUi

    def retranslateUi(self, SearchWindow):
        SearchWindow.setWindowTitle(QCoreApplication.translate("SearchWindow", u"SearchWindow", None))
        self.label.setText(QCoreApplication.translate("SearchWindow", u"IP", None))
        self.lineEdit_ip.setText(QCoreApplication.translate("SearchWindow", u"IP", None))
        self.label_2.setText(QCoreApplication.translate("SearchWindow", u"SUBNET", None))
        self.pushButton_search.setText(QCoreApplication.translate("SearchWindow", u"Search", None))
    # retranslateUi

