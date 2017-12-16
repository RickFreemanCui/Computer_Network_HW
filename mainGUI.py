from PyQt5.QtWidgets import *
from scapy.all import *
from ui.ui_prototype import Ui_MainWindow
import sys, os

class PacketInjector(QMainWindow):
    packetList = []
    currentIndex = -1 # no packet in the list

    # {Protocol}Line2Combo: get the combo box index
    # according to the content in the lineedit
    # {Protocol}Combo2Line: get the content in lineedit
    # by the index of combo box
    EtherLine2Combo = {'src': {'local': 0, 'custom': 1},
                    'dst': {'ff:ff:ff:ff:ff:ff': 0, 'custom': 1},
                    'type': {0x800: 0, 0x806: 1, 'custom': 2}}
    EtherCombo2Line = {'src': {0: 'local'},
                    'dst': {0: 'ff:ff:ff:ff:ff:ff'},
                    'type': {0: '0x800', 1:'0x806'}}
    ARPLine2Combo = {'hwtype': {0x1: 0, 'custom': 1},
                    'ptype': {0x800: 0, 'custom': 1},
                    'hwlen': {6: 0, 'custom': 1},
                    'plen': {4: 0, 'custom': 1},
                    'op': {1: 0, 2: 1, 'custom': 2},
                    'hwsrc': {'local': 0, 'custom': 1},
                    'psrc': {'local': 0, 'custom': 1},
                    'hwdst': {'ff:ff:ff:ff:ff:ff': 0, 'custom': 1},
                    'pdst': {'255.255.255.255': 0, 'custom': 1}}
    ARPCombo2Line = {'hwtype': {0: '0x1'},
                    'ptype': {0: '0x800'},
                    'hwlen': {0: '6'},
                    'plen': {0: '4'},
                    'op': {0: '1', 1: '2'},
                    'hwsrc': {0: 'local'},
                    'psrc': {0: 'local'},
                    'hwdst': {0: 'ff:ff:ff:ff:ff:ff'},
                    'pdst': {0: '255.255.255.255'}}
    IPLine2Combo = {'version': {4: 0, 'custom': 1},
                    'ihl': {5: 0, 'custom': 1},
                    'tos': {0: 0, 'custom': 1},
                    'len': {'auto': 0, 'custom': 1},
                    'frags': {'None': 3, 'DF': 0, 'MF': 1, 'DF+MF': 2, 'MF+DF': 2},
                    'ttl': {64: 0, 'custom': 1},
                    'proto': {0: 0, 6: 1, 17: 2, 1: 3, 'custom': 4},
                    'chksum': {'auto': 0, 'custom': 1},
                    'src': {'local': 0}, 'custom': 1,
                    'dst': {'255.255.255.255': 0, 'custom': 1}}
    IPCombo2Line = {'version': {0: '4'},
                    'ihl': {0: '5'},
                    'tos': {0: '0'},
                    'len': {0: 'auto'},
                    'frags': {3: 'None', 0: 'DF', 1: 'MF', 2: 'DF+MF'},
                    'ttl': {0: '64'},
                    'proto': {0: '0', 1: '6', 2: '17', 3: '1'},
                    'chksum': {0: 'auto'},
                    'src': {0: 'local'},
                    'dst': {0: '255.255.255.255'}}
    UDPLine2Combo = {'len': {'auto': 0, 'custom': 1},
                    'chksum': {'auto': 0, 'custom': 1}}
    UDPCombo2Line = {'len': {0: 'auto'},
                    'chksum': {0: 'auto'}}
    TCPLine2Combo = {'dataofs': {'auto': 0, 'custom': 1},
                    'chksum': {'auto': 0, 'custom': 1}}
    TCPCombo2Line = {'dataofs': {0: 'auto'},
                    'chksum': {0: 'auto'}}
    # Leave ICMP alone for a moment

    # x is a numeral string
    def to_int(self, x):
        if x[0:2] == '0x' or x[0:2] == '0X':
            return int(x, 16)
        else:
            return int(x)


    def __init__(self):
        super(PacketInjector, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.addTCPPort()
        self.addUDPPort()
        self.setupInitValue()
        self.doConnect()
        
    def addUDPPort(self):
        pass
    def addTCPPort(self):
        pass

    def setupInitValue(self):
        self.setupEtherInitValue()
        self.setupARPInitValue()
        self.setupIPInitValue()
        self.setupICMPInitValue()
        self.setupTCPInitValue()
        self.setupUDPInitValue()

    def setupEtherInitValue(self):
        self.ui.lineEditEtherSrc.setText('local')
        self.ui.comboBoxEtherSrc.setCurrentIndex(self.EtherLine2Combo['src']['local'])
        self.ui.lineEditEtherDst.setText('ff:ff:ff:ff:ff:ff')
        self.ui.comboBoxEtherDst.setCurrentIndex(self.EtherLine2Combo['dst']['ff:ff:ff:ff:ff:ff'])
        self.ui.lineEditEtherType.setText('0x800')
        self.ui.comboBoxEtherType.setCurrentIndex(self.EtherLine2Combo['type'][0x800])
    def setupIPInitValue(self):
        pass
    def setupUDPInitValue(self):
        pass
    def setupARPInitValue(self):
        pass
    def setupICMPInitValue(self):
        pass
    def setupTCPInitValue(self):
        pass

    def doConnect(self):
        self.ui.lineEditEtherSrc.editingFinished.connect(self.handleEtherSrcEditingFinish)
        self.ui.lineEditEtherDst.editingFinished.connect(self.handleEtherDstEditingFinish)
        self.ui.lineEditEtherType.editingFinished.connect(self.handleEtherTypeEditingFinish)
        self.ui.comboBoxEtherSrc.currentIndexChanged.connect(self.handleEtherSrcComboIndexChanged)
        self.ui.comboBoxEtherDst.currentIndexChanged.connect(self.handleEtherDstComboIndexChanged)
        self.ui.comboBoxEtherType.currentIndexChanged.connect(self.handleEtherTypeComboIndexChanged)
        self.ui.pushButtonAddPacket.clicked.connect(self.handleAddPacketClicked)
        self.ui.pushButtonDeletePacket.clicked.connect(self.handleDeleteClicked)
        self.ui.pushButtonSend.clicked.connect(self.handleSendClicked)
        self.ui.listWidgetPacketList.currentItemChanged.connect(self.handleListItemClicked)

    def handleAddPacketClicked(self):
        self.currentIndex = len(self.packetList)
        self.packetList.append(Ether())
        newItem = QListWidgetItem('Packet #%d' % (self.currentIndex + 1), self.ui.listWidgetPacketList)
        self.ui.listWidgetPacketList.setCurrentRow(self.currentIndex)
    
    def handleListItemClicked(self, item):
        self.currentIndex = self.ui.listWidgetPacketList.currentRow()
        print(self.currentIndex)
    
    def handleDeleteClicked(self):
        self.packetList.pop(self.currentIndex)
        self.ui.listWidgetPacketList.takeItem(self.currentIndex)
        self.currentIndex = 0
        self.ui.listWidgetPacketList.setCurrentRow(0)

    def handleSendClicked(self):
        sendp(self.packetList[self.currentIndex])
        self.handleDeleteClicked()
    
    def handleTabWidget(self): # slot to re-construct a packet every once a tab is clicked
        protoSwitch = {'l1': {0: Ether},
                    'l2': {0: ARP, 1: IP},
                    'l3': {0: ICMP, 1: TCP, 2: UDP}}
        # Ethernet
        p = Ether()
        p.src = self.ui.lineEditEtherSrc.text()
        p.dst = self.ui.lineEditEtherDst.text()
        p.type = self.ui.lineEditEtherType.text()
        # ARP or IP
        # ARP
        if self.ui.tabWidgetARPIP.currentIndex() == 0:
            p /= ARP()
            p[ARP].hwtype = self.ui.lineEditARPHwtype.text()
            p[ARP].ptype = self.ui.lineEditARPPtype.text()
            p[ARP].hwlen = self.ui.lineEditARPHwlen.text()
            p[ARP].plen = self.ui.lineEditARPPlen.text()
            p[ARP].op = self.ui.lineEditARPOp.text()
            p[ARP].hwsrc = self.ui.lineEditARPHwsrc.text()
            p[ARP].psrc = self.ui.lineEditARPPsrc.text()
            p[ARP].hwdst = self.ui.lineEditARPHwdst.text()
            p[ARP].pdst = self.ui.lineEditARPPdst.text()
        elif self.ui.tabWidgetARPIP.currentIndex() == 1:
            p /= IP()
            p[IP].version = self.ui.lineEditIPVersion.text()
            p[IP].ihl = self.ui.lineEditIPIhl.text()
            p[IP].tos = self.ui.lineEditIPTos.text()
            p[IP].id = self.ui.lineEditIPId.text()
            p[IP].flags = self.ui.lineEditIPFlags.text()
            
    def handleEtherSrcEditingFinish(self):
        p = self.packetList[self.currentIndex][Ether]
        inputSrc = self.ui.lineEditEtherSrc.text()
        p.src = inputSrc
        if inputSrc in self.EtherLine2Combo['src'].keys():
            ind = self.EtherLine2Combo['src'][inputSrc]
        else:
            ind = self.EtherLine2Combo['src']['custom']
        self.ui.comboBoxEtherSrc.setCurrentIndex(ind)

    def handleEtherDstEditingFinish(self):
        p = self.packetList[self.currentIndex][Ether]
        inputDst = self.ui.lineEditEtherDst.text()
        p.dst = inputDst
        if inputDst in self.EtherLine2Combo['dst'].keys():
            ind = self.EtherLine2Combo['dst'][inputDst]
        else:
            ind = self.EtherLine2Combo['dst']['custom']
        self.ui.comboBoxEtherDst.setCurrentIndex(ind)

    def handleEtherTypeEditingFinish(self):
        p = self.packetList[self.currentIndex][Ether]
        inputType = self.to_int(self.ui.lineEditEtherType.text())
        p.type = inputType
        if inputType in self.EtherLine2Combo['type'].keys():
            ind = self.EtherLine2Combo['type'][inputType]
        else:
            ind = self.EtherLine2Combo['type']['custom']
        self.ui.comboBoxEtherType.setCurrentIndex(ind)

    def handleEtherSrcComboIndexChanged(self):
        p = self.packetList[self.currentIndex][Ether]
        inputIndex = self.ui.comboBoxEtherSrc.currentIndex()
        if inputIndex not in self.EtherCombo2Line['src'].keys():
            # custom selected
            pass
        else:
            inputSrc = self.EtherCombo2Line['src'][inputIndex]
            self.ui.lineEditEtherSrc.setText(inputSrc)
            if inputSrc == 'local':
                p.src = None
            else:
                p.src = inputSrc
    
    def handleEtherDstComboIndexChanged(self):
        p = self.packetList[self.currentIndex][Ether]
        inputIndex = self.ui.comboBoxEtherDst.currentIndex()
        if inputIndex not in self.EtherCombo2Line['dst'].keys():
            pass
        else:
            inputDst = self.EtherCombo2Line['dst'][inputIndex]
            self.ui.lineEditEtherDst.setText(inputDst)
            p.dst = inputDst
    
    def handleEtherTypeComboIndexChanged(self):
        p = self.packetList[self.currentIndex][Ether]
        inputIndex = self.ui.comboBoxEtherType.currentIndex()
        if inputIndex not in self.EtherCombo2Line['type'].keys():
            pass
        else:
            inputType = self.EtherCombo2Line['type'][inputIndex]
            self.ui.lineEditEtherType.setText(inputType)
            p.type = self.to_int(inputType, base=16)
    
    def handleARPHwtypeEditingFinish(self):
        p = self.packetList[self.currentIndex][ARP]
        inputHwtype = self.to_int(self.ui.lineEditARPHwtype.text())
        p.hwtype = inputHwtype
        if inputHwtype not in self.ARPLine2Combo['hwtype'].keys()():
            ind = self.ARPLine2Combo['hwtype']['custom']
        else:
            ind = self.ARPLine2Combo['hwtype'][inputHwtype]
        self.ui.comboBoxARPHwtype.setCurrentIndex(ind)

    def handleARPPtypeEditingFinish(self):
        p = self.packetList[self.currentIndex][ARP]
        inputPtype = self.to_int(self.ui.lineEditARPPtype.text())
        p.ptype = inputPtype
        if inputPtype not in self.ARPLine2Combo['ptype'].keys():
            ind = self.ARPLine2Combo['ptype']['custom']
        else:
            ind = self.ARPLine2Combo['ptype'][inputPtype]
        self.ui.comboBoxARPPtype.setCurrentIndex(ind)

    def handleARPHwlenEditingFinish(self):
        p = self.packetList[self.currentIndex][ARP]
        inputHwlen = self.to_int(self.ui.lineEditARPHwlen.text())
        p.hwlen = inputHwlen
        if inputHwlen not in self.ARPLine2Combo['hwlen'].keys():
            ind = self.ARPLine2Combo['hwlen']['custom']
        else:
            ind = self.ARPLine2Combo['hwlen'][inputHwlen]
        self.ui.comboBoxARPHwlen.setCurrentIndex(ind)
    
    def handleARPPlenEditingFinish(self):
        p = self.packetList[self.currentIndex][ARP]
        inputPlen = self.to_int(self.ui.lineEditARPPlen.text())
        p.plen = inputPlen
        if inputPlen not in self.ARPLine2Combo['plen'].keys():
            ind = self.ARPLine2Combo['plen']['custom']
        else:
            ind = self.ARPLine2Combo['plen'][inputPlen]
        self.ui.comboBoxARPPlen.setCurrentIndex(ind)
    
    def handleARPOpEditingFinish(self):
        p = self.packetList[self.currentIndex][ARP]
        inputOp = self.to_int(self.ui.lineEditARPOp.text())
        p.op = inputOp
        if inputOp not in self.ARPLine2Combo['op'].keys():
            ind = self.ARPLine2Combo['op']['custom']
        else:
            ind = self.ARPLine2Combo['op'][inputOp]
        self.ui.comboBoxARPOp.setCurrentIndex(ind)
    
    def handleARPHwsrcEditingFinish(self):
        p = self.packetList[self.currentIndex][ARP]
        inputHwsrc = self.ui.lineEditARPHwsrc.text()
        if inputHwsrc == 'local':
            p.hwsrc = None
        else:
            p.hwsrc = inputHwsrc
        if inputHwsrc not in self.ARPLine2Combo['hwsrc'].keys():
            ind = self.ARPLine2Combo['hwsrc']['custom']
        else:
            ind = self.ARPLine2Combo['hwsrc'][inputHwsrc]
        self.ui.comboBoxARPHwsrc.setCurrentIndex(ind)
    
    def handleARPPsrcEditingFinish(self):
        p = self.packetList[self.currentIndex][ARP]
        inputPsrc = self.ui.lineEditARPPsrc.text()
        if inputPsrc == 'local':
            p.psrc = None
        else:
            p.psrc = inputPsrc
        if inputPsrc not in self.ARPLine2Combo['psrc'].keys():
            ind = self.ARPLine2Combo['psrc']['custom']
        else:
            ind = self.ARPLine2Combo['psrc'][inputPsrc]
        self.ui.comboBoxARPPsrc.setCurrentIndex(ind)
    
    def handleARPHwdstEditingFinish(self):
        p = self.packetList[self.currentIndex][ARP]
        inputHwdst = self.ui.lineEditARPHwdst.text()
        p.hwdst = inputHwdst
        if inputHwdst not in self.ARPLine2Combo['hwdst'].keys():
            ind = self.ARPLine2Combo['hwdst']['custom']
        else:
            ind = self.ARPLine2Combo['hwdst'][inputHwdst]
        self.ui.comboBoxARPHwdst.setCurrentIndex(ind)

    def handleARPPdstEditingFinish(self):
        p = self.packetList[self.currentIndex][ARP]
        inputPdst = self.ui.lineEditARPPdst.text()
        p.pdst = inputPdst
        if inputPdst not in self.ARPLine2Combo['pdst'].keys():
            ind = self.ARPLine2Combo['pdst']['custom']
        else:
            ind = self.ARPLine2Combo['pdst'][inputPdst]
        self.ui.comboBoxARPPdst.setCurrentIndex(ind)
    
    def handleARPHwtypeComboIndexChanged(self):
        p = self.packetList[self.currentIndex][ARP]
        inputIndex = self.ui.comboBoxARPHwtype.currentIndex()
        if inputIndex not in self.ARPCombo2Line['hwtype'].keys():
            pass
        else:
            inputHwtype = self.ARPCombo2Line['hwtype'][inputIndex]
            self.ui.lineEditARPHwtype.setText(inputHwtype)
            p.hwtype = self.to_int(inputHwtype)
    
    def handleARPPtypeComboIndexChanged(self):
        p = self.packetList[self.currentIndex][ARP]
        inputIndex = self.ui.comboBoxARPPtype.currentIndex()
        if inputIndex not in self.ARPCombo2Line['ptype'].keys():
            pass
        else:
            inputPtype = self.ARPCombo2Line['hwtype'][inputIndex]
            self.ui.lineEditARPPtype.setText(inputPtype)
            p.ptype = self.to_int(inputPtype)

    def handleARPHwlenComboIndexChanged(self):
        p = self.packetList[self.currentIndex][ARP]
        inputIndex = self.ui.comboBoxARPHwlen.currentIndex()
        if inputIndex not in self.ARPCombo2Line['hwlen'].keys():
            pass
        else:
            inputHwlen = self.ARPCombo2Line['hwlen'][inputIndex]
            self.ui.lineEditARPHwlen.setText(inputHwlen)
            p.hwtype = self.to_int(inputHwlen)

    def handleARPPlenComboIndexChanged(self):
        p = self.packetList[self.currentIndex][ARP]
        inputIndex = self.ui.comboBoxARPPlen.currentIndex()
        if inputIndex not in self.ARPCombo2Line['plen'].keys():
            pass
        else:
            inputPlen = self.ARPCombo2Line['plen'][inputIndex]
            self.ui.lineEditARPPlen.setText(inputPlen)
            p.plen = self.to_int(inputPlen)

    def handleARPOpComboIndexChanged(self):
        p = self.packetList[self.currentIndex][ARP]
        inputIndex = self.ui.comboBoxARPOp.currentIndex()
        if inputIndex not in self.ARPCombo2Line['op'].keys():
            pass
        else:
            inputOp = self.ARPCombo2Line['op'][inputIndex]
            self.ui.lineEditARPOp.setText(inputOp)
            p.op = self.to_int(inputOp)

    def handleARPHwsrcComboIndexChanged(self):
        p = self.packetList[self.currentIndex][ARP]
        inputIndex = self.ui.comboBoxARPHwsrc.currentIndex()
        if inputIndex not in self.ARPCombo2Line['hwsrc'].keys():
            pass
        else:
            inputHwsrc = self.ARPCombo2Line['hwsrc'].keys()
            self.ui.lineEditARPHwsrc.setText(inputHwsrc)
            p.hwsrc = inputHwsrc
        
    def handleARPPsrcComboIndexChanged(self):
        p = self.packetList[self.currentIndex][ARP]
        inputIndex = self.ui.comboBoxARPPsrc.currentIndex()
        if inputIndex not in self.ARPCombo2Line['psrc'].keys():
            pass
        else:
            inputPsrc = self.ARPCombo2Line['psrc'][inputIndex]
            self.ui.lineEditARPPsrc.setText(inputPsrc)
            p.psrc = inputPsrc
    
    def handleARPPdstComboIndexChanged(self):
        p = self.packetList[self.currentIndex][ARP]
        inputIndex = self.ui.comboBoxARPPdst.currentIndex()
        if inputIndex not in self.ARPCombo2Line['pdst'].keys():
            pass
        else:
            inputPdst = self.ARPCombo2Line['pdst'][inputIndex]
            self.ui.lineEditARPPdst.setText(inputPdst)
            p.pdst = inputPdst
        
    def handleARPHwdstComboIndexChanged(self):
        p = self.packetList[self.currentIndex][ARP]
        inputIndex = self.ui.comboBoxARPHwdst.currentIndex()
        if inputIndex not in self.ARPCombo2Line['hwdst'].keys():
            pass
        else:
            inputHwdst = self.ARPCombo2Line['hwdst'][inputIndex]
            self.ui.lineEditARPHwdst.setText(inputHwdst)
            p.hwdst = inputHwdst


def main():
    app = QApplication(sys.argv)
    inj = PacketInjector()

    inj.show()
    sys.exit(app.exec_())
    

if __name__ == '__main__':
    main()