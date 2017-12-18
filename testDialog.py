import sys
from PyQt5.QtWidgets import QApplication, QDialog
from ui.ui_tcpDialog import Ui_Dialog

class TCPFlagsDialog(QDialog):
    flagsValue = 0
    initFlagsValue = 0
    def __init__(self, initFlagsValue):
        super(TCPFlagsDialog, self).__init__()

        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.flagsValue = initFlagsValue
        self.initFlagsValue = initFlagsValue
        self.initCheckBox()
        self.doConnect()
    
    def doConnect(self):
        self.ui.checkBoxURG.stateChanged.connect(self.handleURGChanged)
        self.ui.checkBoxACK.stateChanged.connect(self.handleACKChanged)
        self.ui.checkBoxPSH.stateChanged.connect(self.handlePSHChanged)
        self.ui.checkBoxRST.stateChanged.connect(self.handleRSTChanged)
        self.ui.checkBoxSYN.stateChanged.connect(self.handleSYNChanged)
        self.ui.checkBoxFIN.stateChanged.connect(self.handleFINChanged)
        self.ui.pushButtonOK.clicked.connect(self.handleOKClicked)
        self.ui.pushButtonCancel.clicked.connect(self.handleCancelClicked)

    def initCheckBox(self):
        flagsValue = self.flagsValue
        if flagsValue >= 32:
            self.ui.checkBoxURG.setChecked(True)
            flagsValue -= 32
        if flagsValue >= 16:
            self.ui.checkBoxACK.setChecked(True)
            flagsValue -= 16
        if flagsValue >= 8:
            self.ui.checkBoxPSH.setChecked(True)
            flagsValue -= 8
        if flagsValue >= 4:
            self.ui.checkBoxRST.setChecked(True)
            flagsValue -= 4
        if flagsValue >= 2:
            self.ui.checkBoxSYN.setChecked(True)
            flagsValue -= 2
        if flagsValue >= 1:
            self.ui.checkBoxFIN.setChecked(True)
            flagsValue -= 1
    
    def handleURGChanged(self):
        if self.ui.checkBoxURG.checkState() > 0:
            self.flagsValue += 32
        else:
            self.flagsValue -= 32
    
    def handleACKChanged(self):
        if self.ui.checkBoxACK.checkState() > 0:
            self.flagsValue += 16
        else:
            self.flagsValue -= 16
    
    def handlePSHChanged(self):
        if self.ui.checkBoxPSH.checkState() > 0:
            self.flagsValue += 8
        else:
            self.flagsValue -= 8
    
    def handleRSTChanged(self):
        if self.ui.checkBoxRST.checkState() > 0:
            self.flagsValue += 4
        else:
            self.flagsValue -= 4
    
    def handleSYNChanged(self):
        if self.ui.checkBoxSYN.checkState() > 0:
            self.flagsValue += 2
        else:
            self.flagsValue -= 2
    
    def handleFINChanged(self):
        if self.ui.checkBoxFIN.checkState() > 0:
            self.flagsValue += 1
        else:
            self.flagsValue -= 1
    
    def handleOKClicked(self):
        print(self.flagsValue)
        self.accept()
    
    def handleCancelClicked(self):
        self.flagsValue = self.initFlagsValue
        print(self.flagsValue)
        self.reject()



def main():
    app = QApplication(sys.argv)
    diag = TCPFlagsDialog(24)
    diag.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()