from ui.ui_ifacedialog import Ui_Dialog
from PyQt5.QtWidgets import *

class IfaceDialog(QDialog):

    def __init__(self, parent):
        super(IfaceDialog, self).__init__(parent)

        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.parent = parent
        self.ifaceList = parent.getIfaceList()
        self.initIface = parent.getCurrentIface()
        self.currentIface = self.initIface
        self.addIfaceItem()
        self.ui.comboBox.currentIndexChanged.connect(self.handleComboIndexChanged)
        self.ui.pushButtonOK.clicked.connect(self.handleOkClicked)
        self.ui.pushButtonCancel.clicked.connect(self.handleCancelClicked)
    
    def addIfaceItem(self):
        for i in self.ifaceList:
            self.ui.comboBox.addItem(i)
        currentIndex = self.ifaceList.index(self.currentIface)
        self.ui.comboBox.setCurrentIndex(currentIndex)

    def handleComboIndexChanged(self):
        inputIndex = self.ui.comboBox.currentIndex()
        self.currentIface = self.ifaceList[inputIndex]

    def handleOkClicked(self):
        self.parent.setCurrentIface(self.currentIface)
        self.accept()
    
    def handleCancelClicked(self):
        self.parent.setCurrentIface(self.initIface)
        self.reject()