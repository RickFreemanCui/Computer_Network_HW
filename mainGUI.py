from PyQt5.QtWidgets import *
from PyQt5.QtGui import QIcon
from scapy.all import *
from ui.ui_prototype import Ui_MainWindow
from TCPDialog import TCPFlagsDialog
from IfaceDialog import IfaceDialog
from engine.BaseN import int2base, base2int
from engine.TimeConvert import timeConvert
from hexdump import hexdump as dump
import sys, os

# TODO: HANDLE invalid input

class PacketInjector(QMainWindow):
    packetList = []
    currentIndex = -1 # no packet in the list
    packetCtr = 1

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
                    'flags': {0: 3, 2: 0, 1: 1, 3: 2},
                    'ttl': {64: 0, 'custom': 1},
                    'proto': {0: 0, 6: 1, 17: 2, 1: 3, 'custom': 4},
                    'chksum': {'auto': 0, 'custom': 1},
                    'src': {'local': 0, 'custom': 1},
                    'dst': {'255.255.255.255': 0, 'custom': 1}}
    IPCombo2Line = {'version': {0: '4'},
                    'ihl': {0: '5'},
                    'tos': {0: '0'},
                    'len': {0: 'auto'},
                    'flags': {3: '0', 0: '2', 1: '1', 2: '3'},
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
                    'chksum': {'auto': 0, 'custom': 1},
                    'reserved': {'none': 0, 'custom': 1, 0: 0}}
    TCPCombo2Line = {'dataofs': {0: 'auto'},
                    'chksum': {0: 'auto'},
                    'reserved': {0: 'none'}}
    ICMPLine2Combo = {'type': {0: 0, 3: 1, 4: 2, 5: 3, 8: 4, 9: 5, 10: 6, 11: 7, 12: 8, 13: 9, 14: 10, 'custom': 11}}
    ICMPCombo2Line = {'type': {0: '0', 1: '3', 2: '4', 3: '5', 4: '8', 5: '9', 6: '10', 7: '11', 8: '12', 9: '13', 10: '14'}}

    def __init__(self):
        super(PacketInjector, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle('Packet Injector')
        self.center()
        self.addMenuBar()
        self.addTip()
        self.doConnect()
        self.addInitPacket()

    def addTip(self):
        self.ui.pushButtonAddPacket.setStatusTip('Add a link-layer packet to packet list')
        self.ui.pushButtonDeletePacket.setStatusTip('Delete the current packet')
        self.ui.pushButtonSend.setStatusTip('Send the current packet from selected interface (%s)' % self.getCurrentIface())
        self.ui.pushButtonWritePCAP.setStatusTip('Write current packet list to a pcap file')
        self.ui.textBrowserHexdump.setStatusTip('Hexdump of current packet')
        self.ui.listWidgetPacketList.setStatusTip('Current packet list')
        self.ui.tabWidgetEther.setStatusTip('Link layer options')
        self.ui.tabWidgetARPIP.setStatusTip('ARP or IP options, None means no payload')
        self.ui.tabWidgetICMPTCPUDP.setStatusTip('ICMP, TCP, or UDP options, None means no payload')

    def center(self):
        fg = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        fg.moveCenter(cp)
        self.move(fg.topLeft())
    
    def addMenuBar(self):
        mainMenu = self.menuBar()
        fileMenu = mainMenu.addMenu('file')
        configMenu = mainMenu.addMenu('config')

        saveButton = QAction(QIcon('save.png'), 'Save', self)
        saveButton.setStatusTip('Save current packet list to a pcap file')
        saveButton.triggered.connect(self.handleWritePCAPClicked)
        fileMenu.addAction(saveButton)
        
        exitButton = QAction(QIcon('exit.png'), 'Exit', self)
        exitButton.setStatusTip('Exit application')
        exitButton.triggered.connect(self.close)
        fileMenu.addAction(exitButton)

        ifaceSelectButton = QAction(QIcon(''), 'Select Interface', self)
        ifaceSelectButton.setStatusTip('Select a network interface to send packet from')
        ifaceSelectButton.triggered.connect(self.handleIfaceSelect)
        configMenu.addAction(ifaceSelectButton)
    
    def handleIfaceSelect(self):
        diag = IfaceDialog(self)
        diag.show()
        diag.exec_()
    
    def getIfaceList(self):
        l = []
        for i in ifaces.keys():
            l.append(i)
        return l

    def setCurrentIface(self, ifaceName):
        conf.iface = ifaceName

    def getCurrentIface(self):
        return conf.iface

    def addInitPacket(self):
        self.handleAddPacketClicked()

    def doConnect(self):
        self.ui.pushButtonAddPacket.clicked.connect(self.handleAddPacketClicked)
        self.ui.pushButtonDeletePacket.clicked.connect(self.handleDeleteClicked)
        self.ui.pushButtonSend.clicked.connect(self.handleSendClicked)
        self.ui.listWidgetPacketList.itemClicked.connect(self.handleListItemClicked)
        self.ui.pushButtonWritePCAP.clicked.connect(self.handleWritePCAPClicked)
        EtherConnectList = [(self.ui.lineEditEtherSrc.returnPressed, self.handleEtherSrcEditingFinish),
                (self.ui.lineEditEtherDst.returnPressed, self.handleEtherDstEditingFinish),
                (self.ui.lineEditEtherType.returnPressed, self.handleEtherTypeEditingFinish),
                (self.ui.comboBoxEtherSrc.currentIndexChanged, self.handleEtherSrcComboIndexChanged),
                (self.ui.comboBoxEtherDst.currentIndexChanged, self.handleEtherDstComboIndexChanged),
                (self.ui.comboBoxEtherType.currentIndexChanged, self.handleEtherTypeComboIndexChanged)]
        for EtherConnectPair in EtherConnectList:
            EtherConnectPair[0].connect(EtherConnectPair[1])
            EtherConnectPair[0].connect(self.displayHexdump)


        ARPConnectList = [(self.ui.lineEditARPHwlen.returnPressed, self.handleARPHwlenEditingFinish),
                (self.ui.lineEditARPPlen.returnPressed, self.handleARPPlenEditingFinish),
                (self.ui.lineEditARPHwtype.returnPressed, self.handleARPHwtypeEditingFinish),
                (self.ui.lineEditARPPlen.returnPressed, self.handleARPPtypeEditingFinish),
                (self.ui.lineEditARPOp.returnPressed, self.handleARPOpEditingFinish),
                (self.ui.lineEditARPHwsrc.returnPressed, self.handleARPHwsrcEditingFinish),
                (self.ui.lineEditARPPsrc.returnPressed, self.handleARPPsrcEditingFinish),
                (self.ui.lineEditARPHwdst.returnPressed, self.handleARPHwdstEditingFinish),
                (self.ui.lineEditARPPdst.returnPressed, self.handleARPPdstEditingFinish),
                (self.ui.comboBoxARPHwtype.currentIndexChanged, self.handleARPHwtypeComboIndexChanged),
                (self.ui.comboBoxARPPtype.currentIndexChanged, self.handleARPPtypeComboIndexChanged),
                (self.ui.comboBoxARPHwlen.currentIndexChanged, self.handleARPHwlenComboIndexChanged),
                (self.ui.comboBoxARPPlen.currentIndexChanged, self.handleARPPlenComboIndexChanged),
                (self.ui.comboBoxARPOp.currentIndexChanged, self.handleARPOpComboIndexChanged),
                (self.ui.comboBoxARPHwsrc.currentIndexChanged, self.handleARPHwsrcComboIndexChanged),
                (self.ui.comboBoxARPPsrc.currentIndexChanged, self.handleARPPsrcComboIndexChanged),
                (self.ui.comboBoxARPHwdst.currentIndexChanged, self.handleARPHwdstComboIndexChanged),
                (self.ui.comboBoxARPPdst.currentIndexChanged, self.handleARPPdstComboIndexChanged)]
        for ARPConnectPair in ARPConnectList:
            ARPConnectPair[0].connect(ARPConnectPair[1])
            ARPConnectPair[0].connect(self.displayHexdump)

        IPConnectList = [(self.ui.lineEditIPVersion.returnPressed, self.handleIPVersionEditingFinish),
                (self.ui.lineEditIPIhl.returnPressed, self.handleIPIhlEditingFinish),
                (self.ui.lineEditIPTos.returnPressed, self.handleIPTosEditingFinish),
                (self.ui.lineEditIPLength.returnPressed, self.handleIPLenEditingFinish),
                (self.ui.lineEditIPId.returnPressed, self.handleIPIdEditingFinish),
                (self.ui.lineEditIPFlags.returnPressed, self.handleIPFlagsEditingFinish),
                (self.ui.lineEditIPFragment.returnPressed, self.handleIPFragEditingFinish),
                (self.ui.lineEditIPTtl.returnPressed, self.handleIPTtlEditingFinish),
                (self.ui.lineEditIPProto.returnPressed, self.handleIPProtoEditingFinish),
                (self.ui.lineEditIPChecksum.returnPressed, self.handleIPChksumEditingFinish),
                (self.ui.lineEditIPSrc.returnPressed, self.handleIPSrcEditingFinish),
                (self.ui.lineEditIPDst.returnPressed, self.handleIPDstEditingFinish),
                (self.ui.comboBoxIPVersion.currentIndexChanged, self.handleIPVersionComboIndexChanged),
                (self.ui.comboBoxIPIhl.currentIndexChanged, self.handleIPIhlComboIndexChanged),
                (self.ui.comboBoxIPTos.currentIndexChanged, self.handleIPTosComboIndexChanged),
                (self.ui.comboBoxIPLength.currentIndexChanged, self.handleIPLenComboIndexChanged),
                (self.ui.comboBoxIPId.currentIndexChanged, self.handleIPIdComboIndexChanged),
                (self.ui.comboBoxIPFlags.currentIndexChanged, self.handleIPFlagsComboIndexChanged),
                (self.ui.comboBoxIPFragment.currentIndexChanged, self.handleIPFragComboIndexChanged),
                (self.ui.comboBoxIPTtl.currentIndexChanged, self.handleIPTtlComboIndexChanged),
                (self.ui.comboBoxIPProto.currentIndexChanged, self.handleIPProtoComboIndexChanged),
                (self.ui.comboBoxIPChecksum.currentIndexChanged, self.handleIPChksumComboIndexChanged),
                (self.ui.comboBoxIPSrc.currentIndexChanged, self.handleIPSrcComboIndexChanged),
                (self.ui.comboBoxIPDst.currentIndexChanged, self.handleIPDstComboIndexChanged)]
        for IPConnectPair in IPConnectList:
            IPConnectPair[0].connect(IPConnectPair[1])
            IPConnectPair[0].connect(self.displayHexdump)

        ICMPConnectList = [(self.ui.lineEditICMPType.returnPressed, self.handleICMPTypeEditingFinish),
                (self.ui.lineEditICMPCode.returnPressed, self.handleICMPCodeEditingFinish),
                (self.ui.lineEditICMPChksum.returnPressed, self.handleICMPChksumEditingFinish),
                (self.ui.lineEditICMPId.returnPressed, self.handleICMPIdEditingFinish),
                (self.ui.lineEditICMPSeq.returnPressed, self.handleICMPSeqEditingFinish),
                (self.ui.lineEditICMPTs_ori.returnPressed, self.handleICMPTs_oriEditingFinish),
                (self.ui.lineEditICMPTs_rx.returnPressed, self.handleICMPTs_rxEditingFinish),
                (self.ui.lineEditICMPTs_tx.returnPressed, self.handleICMPTs_txEditingFinish),
                (self.ui.lineEditICMPGw.returnPressed, self.handleICMPGwEditingFinish),
                (self.ui.lineEditICMPPtr.returnPressed, self.handleICMPPtrEditingFinish),
                (self.ui.lineEditICMPReserved.returnPressed, self.handleICMPReservedEditingFinish),
                (self.ui.lineEditICMPAddr_mask.returnPressed, self.handleICMPAddr_maskEditingFinish),
                (self.ui.lineEditICMPUnused.returnPressed, self.handleICMPUnusedEditingFinish),
                (self.ui.comboBoxICMPChksum.currentIndexChanged, self.handleICMPChksumComboIndexChanged),
                (self.ui.comboBoxICMPType.currentIndexChanged, self.handleICMPTypeComboIndexChanged)]
        for ICMPConnectPair in ICMPConnectList:
            ICMPConnectPair[0].connect(ICMPConnectPair[1])
            ICMPConnectPair[0].connect(self.displayHexdump)
        
        TCPConnectList = [(self.ui.lineEditTCPSport.returnPressed, self.handleTCPSportEditingFinish),
                (self.ui.lineEditTCPDport.returnPressed, self.handleTCPDportEditingFinish),
                (self.ui.lineEditTCPSeq.returnPressed, self.handleTCPSeqEditingFinish),
                (self.ui.lineEditTCPAck.returnPressed, self.handleTCPAckEditingFinish),
                (self.ui.lineEditTCPDataofs.returnPressed, self.handleTCPDataofsEditingFinish),
                (self.ui.lineEditTCPReserved.returnPressed, self.handleTCPReservedEditingFinish),
                (self.ui.pushButtonEditTCPFlag.clicked, self.handleTCPFlagsEdit),
                (self.ui.lineEditTCPWindow.returnPressed, self.handleTCPWindowEditingFinish),
                (self.ui.lineEditTCPChksum.returnPressed, self.handleTCPChksumEditingFinish),
                (self.ui.lineEditTCPUrgptr.returnPressed, self.handleTCPUrgptrEditingFinish),
                (self.ui.comboBoxTCPDataofs.currentIndexChanged, self.handleTCPDataofsComboIndexChanged),
                (self.ui.comboBoxTCPChksum.currentIndexChanged, self.handleTCPChksumComboIndexChanged),
                (self.ui.comboBoxTCPReserved.currentIndexChanged, self.handleTCPReservedComboIndexChanged)]
        for TCPConnectPair in TCPConnectList:
            TCPConnectPair[0].connect(TCPConnectPair[1])
            TCPConnectPair[0].connect(self.displayHexdump)
        
        UDPConnectList = [(self.ui.lineEditUDPSport.returnPressed, self.handleUDPSportEditingFinish),
                (self.ui.lineEditUDPDport.returnPressed, self.handleUDPDportEditingFinish),
                (self.ui.lineEditUDPLen.returnPressed, self.handleUDPLenEditingFinish),
                (self.ui.lineEditUDPChksum.returnPressed, self.handleUDPChksumEditingFinish),
                (self.ui.comboBoxUDPLen.currentIndexChanged, self.handleUDPLenComboIndexChanged),
                (self.ui.comboBoxUDPChksum.currentIndexChanged, self.handleUDPChksumComboIndexChanged)]
        for UDPConnectPair in UDPConnectList:
            UDPConnectPair[0].connect(UDPConnectPair[1])
            UDPConnectPair[0].connect(self.displayHexdump)
        
        self.ui.tabWidgetARPIP.tabBarClicked.connect(self.handleARPIPTabClicked)
        self.ui.tabWidgetARPIP.tabBarClicked.connect(self.displayHexdump)
        self.ui.tabWidgetICMPTCPUDP.tabBarClicked.connect(self.handleICMPTCPUDPTabClicked)
        self.ui.tabWidgetICMPTCPUDP.tabBarClicked.connect(self.displayHexdump)
        


    def displayHexdump(self):
        p = self.packetList[self.currentIndex]
        s = bytes(p)
        self.ui.textBrowserHexdump.setText(dump(s, result='return'))
    
    # A method to display the various fields of a select packet. This is needed
    # when a different packet is selected or a different tab is selected
    def handlePacketDisplay(self):
        self.displayHexdump()
        p = self.packetList[self.currentIndex]
        EtherSrc = p[Ether].src
        EtherDst = p[Ether].dst
        EtherType = p[Ether].type
        self.ui.lineEditEtherSrc.setText(EtherSrc)
        self.handleEtherSrcEditingFinish()
        self.ui.lineEditEtherDst.setText(EtherDst)
        self.handleEtherDstEditingFinish()
        self.ui.lineEditEtherType.setText('0x' + int2base(EtherType, 16))
        self.handleEtherTypeEditingFinish()

        hasARP, hasIP = True, True
        hasTCP, hasICMP, hasUDP = True, True, True
        try:
            pARP = p[ARP]
        except IndexError:
            hasARP = False
        try:
            pIP = p[IP]
        except IndexError:
            hasIP = False
        if not hasIP and not hasARP:
            self.ui.tabWidgetARPIP.setCurrentIndex(2) # Set to none page
            self.ui.tabWidgetICMPTCPUDP.setCurrentIndex(3) # also set to none page
            return

        if hasARP:
            self.ui.tabWidgetARPIP.setCurrentIndex(0)
            self.ui.lineEditARPHwtype.setText('0x' + int2base(pARP.hwtype, 16))
            self.handleARPHwtypeEditingFinish()
            self.ui.lineEditARPPtype.setText('0x' + int2base(pARP.ptype, 16))
            self.handleARPPtypeEditingFinish()
            self.ui.lineEditARPHwlen.setText(int2base(pARP.hwlen, 10))
            self.handleARPHwlenEditingFinish()
            self.ui.lineEditARPPlen.setText(int2base(pARP.plen, 10))
            self.handleARPPlenEditingFinish()
            self.ui.lineEditARPOp.setText(int2base(pARP.op, 10))
            self.handleARPOpEditingFinish()
            self.ui.lineEditARPHwsrc.setText(pARP.hwsrc)
            self.handleARPHwsrcEditingFinish()
            self.ui.lineEditARPPsrc.setText(pARP.psrc)
            self.handleARPPsrcEditingFinish()
            self.ui.lineEditARPHwdst.setText(pARP.hwdst)
            self.handleARPHwdstEditingFinish()
            self.ui.lineEditARPPdst.setText(pARP.pdst)
            self.handleARPPdstEditingFinish()

        elif hasIP:
            self.ui.tabWidgetARPIP.setCurrentIndex(1)
            self.ui.lineEditIPVersion.setText(int2base(pIP.version, 10))
            self.handleIPVersionEditingFinish()
            if pIP.ihl is None:
                self.ui.lineEditIPIhl.setText('5')
            else:
                self.ui.lineEditIPIhl.setText(int2base(pIP.ihl, 10))
            self.handleIPIhlEditingFinish()
            self.ui.lineEditIPTos.setText(int2base(pIP.tos, 10))
            self.handleIPTosEditingFinish()
            if pIP.len is None:
                self.ui.lineEditIPLength.setText('auto')
            else:
                self.ui.lineEditIPLength.setText(int2base(pIP.len, 10))
            self.handleIPLenEditingFinish()
            self.ui.lineEditIPId.setText(int2base(pIP.id, 10))
            self.handleIPIdEditingFinish()
            if pIP.flags == 1:
                self.ui.lineEditIPFlags.setText('1')
            elif pIP.flags == 2:
                self.ui.lineEditIPFlags.setText('2')
            elif pIP.flags == 3:
                self.ui.lineEditIPFlags.setText('3')
            else:
                # excluding 'evil' flag
                self.ui.lineEditIPFlags.setText('0')
            self.handleIPFlagsEditingFinish()
            self.ui.lineEditIPFragment.setText(int2base(pIP.frag, 10))
            self.handleIPFragEditingFinish()
            self.ui.lineEditIPTtl.setText(int2base(pIP.ttl, 10))
            self.handleIPTtlEditingFinish()
            self.ui.lineEditIPProto.setText(int2base(pIP.proto, 10))
            self.handleIPProtoEditingFinish()
            if pIP.chksum is None:
                self.ui.lineEditIPChecksum.setText('auto')
            else:
                self.ui.lineEditIPChecksum.setText('0x' + int2base(pIP.chksum, 16))
            self.handleIPChksumEditingFinish()
            self.ui.lineEditIPSrc.setText(pIP.src)
            self.handleIPSrcEditingFinish()
            self.ui.lineEditIPDst.setText(pIP.dst)
            self.handleIPDstEditingFinish()
    
        try:
            pICMP = p[ICMP]
        except IndexError:
            hasICMP = False
        try:
            pTCP = p[TCP]
        except IndexError:
            hasTCP = False
        try:
            pUDP = p[UDP]
        except IndexError:
            hasUDP = False
        if not hasICMP and not hasTCP and not hasUDP:
            self.ui.tabWidgetICMPTCPUDP.setCurrentIndex(3) # none page
            return
        if hasICMP:
            self.ui.tabWidgetICMPTCPUDP.setCurrentIndex(0)
            self.ui.lineEditICMPType.setText(int2base(pICMP.type, 10))
            self.handleICMPTypeEditingFinish()
            self.ui.lineEditICMPCode.setText(int2base(pICMP.code, 10))
            self.handleICMPCodeEditingFinish()
            if pICMP.chksum is None:
                self.ui.lineEditICMPChksum.setText('auto')
            else:
                self.ui.lineEditICMPChksum.setText('0x' + int2base(pICMP.chksum, 16))
            self.handleICMPChksumEditingFinish()
            self.ui.lineEditICMPId.setText(int2base(pICMP.id, 10))
            self.handleICMPIdEditingFinish()
            self.ui.lineEditICMPSeq.setText(int2base(pICMP.seq, 10))
            self.handleICMPSeqEditingFinish()
            self.ui.lineEditICMPTs_ori.setText(timeConvert(pICMP.ts_ori))
            self.handleICMPTs_oriEditingFinish()
            self.ui.lineEditICMPTs_rx.setText(timeConvert(pICMP.ts_rx))
            self.handleICMPTs_rxEditingFinish()
            self.ui.lineEditICMPTs_tx.setText(timeConvert(pICMP.ts_tx))
            self.handleICMPTs_txEditingFinish()
            self.ui.lineEditICMPGw.setText(pICMP.gw)
            self.handleICMPGwEditingFinish()
            self.ui.lineEditICMPPtr.setText(int2base(pICMP.ptr, 10))
            self.handleICMPPtrEditingFinish()
            self.ui.lineEditICMPReserved.setText(int2base(pICMP.reserved, 10))
            self.handleICMPReservedEditingFinish()
            self.ui.lineEditICMPAddr_mask.setText(pICMP.addr_mask)
            self.handleICMPAddr_maskEditingFinish()
            self.ui.lineEditICMPUnused.setText(int2base(pICMP.unused, 10))
            self.handleICMPUnusedEditingFinish()
        elif hasTCP:
            self.ui.tabWidgetICMPTCPUDP.setCurrentIndex(1)
            self.ui.lineEditTCPSport.setText(int2base(pTCP.sport, 10))
            self.handleTCPSportEditingFinish()
            self.ui.lineEditTCPDport.setText(int2base(pTCP.dport, 10))
            self.handleTCPDportEditingFinish()
            self.ui.lineEditTCPSeq.setText(int2base(pTCP.seq, 10))
            self.handleTCPSeqEditingFinish()
            self.ui.lineEditTCPAck.setText(int2base(pTCP.ack, 10))
            self.handleTCPAckEditingFinish()
            if pTCP.dataofs is None:
                self.ui.lineEditTCPDataofs.setText('auto')
            else:
                self.ui.lineEditTCPDataofs.setText(int2base(pTCP.dataofs, 10))
            self.handleTCPDataofsEditingFinish()
            if pTCP.reserved == 0:
                self.ui.lineEditTCPReserved.setText('none')
            else:
                self.ui.lineEditTCPReserved.setText(int2base(pTCP.reserved, 10))
            self.handleTCPReservedEditingFinish()
            self.showTCPFlags()
            self.ui.lineEditTCPWindow.setText(int2base(pTCP.window, 10))
            self.handleTCPWindowEditingFinish()
            if pTCP.chksum is None:
                self.ui.lineEditTCPChksum.setText('auto')
            else:
                self.ui.lineEditTCPChksum.setText('0x' + int2base(pTCP.chksum, 16))
            self.handleTCPChksumEditingFinish()
            self.ui.lineEditTCPUrgptr.setText(int2base(pTCP.urgptr, 10))
            self.handleTCPUrgptrEditingFinish()
        elif hasUDP:
            self.ui.tabWidgetICMPTCPUDP.setCurrentIndex(2)
            self.ui.lineEditUDPSport.setText(int2base(pUDP.sport, 10))
            self.handleUDPSportEditingFinish()
            self.ui.lineEditUDPDport.setText(int2base(pUDP.dport, 10))
            self.handleUDPDportEditingFinish()
            if pUDP.len is None:
                self.ui.lineEditUDPLen.setText('auto')
            else:
                self.ui.lineEditUDPLen.setText(int2base(pUDP.len, 10))
            self.handleUDPLenEditingFinish()
            if pUDP.chksum is None:
                self.ui.lineEditUDPChksum.setText('auto')
            else:
                self.ui.lineEditUDPChksum.setText('0x' + int2base(pUDP.chksum, 16))
            self.handleUDPChksumEditingFinish()

    def showTCPFlags(self):
        pTCP = self.packetList[self.currentIndex][TCP]
        flags = pTCP.flags
        resultStr = ''
        if flags >= 32:
            resultStr += 'URG+'
            flags -= 32
        if flags >= 16:
            resultStr += 'ACK+'
            flags -= 16
        if flags >= 8:
            resultStr += 'PSH+'
            flags -= 8
        if flags >= 4:
            resultStr += 'RST+'
            flags -= 4
        if flags >= 2:
            resultStr += 'SYN+'
            flags -= 2
        if flags >= 1:
            resultStr += 'FIN+'
            flags -= 1
        if len(resultStr) > 0:
            resultStr = resultStr[: -1]
        self.ui.lineEditTCPFlags.setText(resultStr)

    def handleAddPacketClicked(self):
        self.currentIndex = len(self.packetList)
        self.packetList.append(Ether())
        newItem = QListWidgetItem('Packet #%d' % (self.packetCtr), self.ui.listWidgetPacketList)
        self.packetCtr += 1
        self.ui.listWidgetPacketList.setCurrentRow(self.currentIndex)
        self.handlePacketDisplay()
    
    def handleListItemClicked(self, item):
        self.currentIndex = self.ui.listWidgetPacketList.currentRow()
        self.handlePacketDisplay()
    
    def handleDeleteClicked(self):
        self.packetList.pop(self.currentIndex)
        self.ui.listWidgetPacketList.takeItem(self.currentIndex)
        if len(self.packetList) == 0:
            self.handleAddPacketClicked()
        else:
            self.currentIndex = 0
            self.ui.listWidgetPacketList.setCurrentRow(0)
            self.handlePacketDisplay()


    def handleSendClicked(self):
        sendp(self.packetList[self.currentIndex])
        self.handleDeleteClicked()

    def handleWritePCAPClicked(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getSaveFileName(self,"Specify a Save file (add extension)","","All Files (*);;pcap Files (*.pcap)", options=options)
        if fileName:
            wrpcap(fileName, self.packetList)
            for i in range(len(self.packetList)):
                self.handleDeleteClicked()

    def handleARPIPTabClicked(self, index):
        currentPacket = self.packetList[self.currentIndex]
        inputTab = self.ui.tabWidgetARPIP.currentIndex()
        if inputTab == index:
            # clicked on the same content
            return
        # Content is changed
        # ARP
        if index == 0:
            currentPacket[Ether].payload = ARP()
        # IP
        elif index == 1:
            currentPacket[Ether].payload = IP()
        # None
        else:
            currentPacket[Ether].payload = None
        self.handlePacketDisplay()
    
    def handleICMPTCPUDPTabClicked(self, index):
        currentPacket = self.packetList[self.currentIndex]
        inputTab = self.ui.tabWidgetICMPTCPUDP.currentIndex()
        if inputTab == index:
            # clicked on the same tab
            return
        # content changed
        if index == 3:
            # None is selected
            if currentPacket[Ether].payload is scapy.packet.NoPayload:
                return
            else:
                currentPacket[Ether].payload.payload = None
                self.handlePacketDisplay()
                return
        
        if type(currentPacket[Ether].payload) is scapy.packet.NoPayload:
            self.ui.tabWidgetARPIP.setCurrentIndex(1)
            currentPacket[Ether].payload = IP()
        elif type(currentPacket[Ether].payload) is type(ARP()):
            self.ui.tabWidgetARPIP.setCurrentIndex(1)
            currentPacket[Ether].payload = IP()
        elif type(currentPacket[Ether].payload) is type(IP()):
            pass
        else:
            pass # not gonna happen
        # ICMP
        if index == 0:
            currentPacket[IP].payload = ICMP()
        # TCP
        elif index == 1:
            currentPacket[IP].payload = TCP()
        # UDP
        elif index == 2:
            currentPacket[IP].payload = UDP()
        # not gonna happen
        else:
            pass
        self.handlePacketDisplay()
            
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
        inputType = base2int(self.ui.lineEditEtherType.text())
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
            p.type = base2int(inputType)
    
    def handleARPHwtypeEditingFinish(self):
        p = self.packetList[self.currentIndex][ARP]
        inputHwtype = base2int(self.ui.lineEditARPHwtype.text())
        p.hwtype = inputHwtype
        if inputHwtype not in self.ARPLine2Combo['hwtype'].keys():
            ind = self.ARPLine2Combo['hwtype']['custom']
        else:
            ind = self.ARPLine2Combo['hwtype'][inputHwtype]
        self.ui.comboBoxARPHwtype.setCurrentIndex(ind)

    def handleARPPtypeEditingFinish(self):
        p = self.packetList[self.currentIndex][ARP]
        inputPtype = base2int(self.ui.lineEditARPPtype.text())
        p.ptype = inputPtype
        if inputPtype not in self.ARPLine2Combo['ptype'].keys():
            ind = self.ARPLine2Combo['ptype']['custom']
        else:
            ind = self.ARPLine2Combo['ptype'][inputPtype]
        self.ui.comboBoxARPPtype.setCurrentIndex(ind)

    def handleARPHwlenEditingFinish(self):
        p = self.packetList[self.currentIndex][ARP]
        inputHwlen = base2int(self.ui.lineEditARPHwlen.text())
        p.hwlen = inputHwlen
        if inputHwlen not in self.ARPLine2Combo['hwlen'].keys():
            ind = self.ARPLine2Combo['hwlen']['custom']
        else:
            ind = self.ARPLine2Combo['hwlen'][inputHwlen]
        self.ui.comboBoxARPHwlen.setCurrentIndex(ind)
    
    def handleARPPlenEditingFinish(self):
        p = self.packetList[self.currentIndex][ARP]
        inputPlen = base2int(self.ui.lineEditARPPlen.text())
        p.plen = inputPlen
        if inputPlen not in self.ARPLine2Combo['plen'].keys():
            ind = self.ARPLine2Combo['plen']['custom']
        else:
            ind = self.ARPLine2Combo['plen'][inputPlen]
        self.ui.comboBoxARPPlen.setCurrentIndex(ind)
    
    def handleARPOpEditingFinish(self):
        p = self.packetList[self.currentIndex][ARP]
        inputOp = base2int(self.ui.lineEditARPOp.text())
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
            p.hwtype = base2int(inputHwtype)
    
    def handleARPPtypeComboIndexChanged(self):
        p = self.packetList[self.currentIndex][ARP]
        inputIndex = self.ui.comboBoxARPPtype.currentIndex()
        if inputIndex not in self.ARPCombo2Line['ptype'].keys():
            pass
        else:
            inputPtype = self.ARPCombo2Line['hwtype'][inputIndex]
            self.ui.lineEditARPPtype.setText(inputPtype)
            p.ptype = base2int(inputPtype)

    def handleARPHwlenComboIndexChanged(self):
        p = self.packetList[self.currentIndex][ARP]
        inputIndex = self.ui.comboBoxARPHwlen.currentIndex()
        if inputIndex not in self.ARPCombo2Line['hwlen'].keys():
            pass
        else:
            inputHwlen = self.ARPCombo2Line['hwlen'][inputIndex]
            self.ui.lineEditARPHwlen.setText(inputHwlen)
            p.hwtype = base2int(inputHwlen)

    def handleARPPlenComboIndexChanged(self):
        p = self.packetList[self.currentIndex][ARP]
        inputIndex = self.ui.comboBoxARPPlen.currentIndex()
        if inputIndex not in self.ARPCombo2Line['plen'].keys():
            pass
        else:
            inputPlen = self.ARPCombo2Line['plen'][inputIndex]
            self.ui.lineEditARPPlen.setText(inputPlen)
            p.plen = base2int(inputPlen)

    def handleARPOpComboIndexChanged(self):
        p = self.packetList[self.currentIndex][ARP]
        inputIndex = self.ui.comboBoxARPOp.currentIndex()
        if inputIndex not in self.ARPCombo2Line['op'].keys():
            pass
        else:
            inputOp = self.ARPCombo2Line['op'][inputIndex]
            self.ui.lineEditARPOp.setText(inputOp)
            p.op = base2int(inputOp)

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
    
    def handleIPVersionEditingFinish(self):
        p = self.packetList[self.currentIndex][IP]
        inputVersion = self.ui.lineEditIPVersion.text()
        p.version = base2int(inputVersion)
        if p.version not in self.IPLine2Combo['version'].keys():
            ind = self.IPLine2Combo['version']['custom']
        else:
            ind = self.IPLine2Combo['version'][p.version]
        self.ui.comboBoxIPVersion.setCurrentIndex(ind)
    
    def handleIPIhlEditingFinish(self):
        p = self.packetList[self.currentIndex][IP]
        inputIhl = self.ui.lineEditIPIhl.text()
        p.ihl = base2int(inputIhl)
        if p.ihl not in self.IPLine2Combo['ihl'].keys():
            ind = self.IPLine2Combo['ihl']['custom']
        else:
            ind = self.IPLine2Combo['ihl'][p.ihl]
        self.ui.comboBoxIPIhl.setCurrentIndex(ind)
    
    def handleIPTosEditingFinish(self):
        p = self.packetList[self.currentIndex][IP]
        inputTos = self.ui.lineEditIPTos.text()
        p.tos = base2int(inputTos)
        if p.tos not in self.IPLine2Combo['tos'].keys():
            ind = self.IPLine2Combo['tos']['custom']
        else:
            ind = self.IPLine2Combo['tos'][p.tos]
        self.ui.comboBoxIPTos.setCurrentIndex(ind)    

    def handleIPLenEditingFinish(self):
        p = self.packetList[self.currentIndex][IP]
        inputLen = self.ui.lineEditIPLength.text()
        if inputLen == 'auto':
            p.len = None
            ind = self.IPLine2Combo['len']['auto']
        else:
            p.len = base2int(inputLen)
            ind = self.IPLine2Combo['len']['custom']
        self.ui.comboBoxIPLength.setCurrentIndex(ind)

    def handleIPIdEditingFinish(self):
        p = self.packetList[self.currentIndex][IP]
        inputId = self.ui.lineEditIPId.text()
        p.id = base2int(inputId)
        self.ui.comboBoxIPId.setCurrentIndex(0)

    def handleIPFlagsEditingFinish(self):
        p = self.packetList[self.currentIndex][IP]
        inputFlags = self.ui.lineEditIPFlags.text()
        if base2int(inputFlags) not in self.IPLine2Combo['flags'].keys():
            msg = QMessageBox(self)
            ret = QMessageBox.warning(self, 'Invalid IP flag', 
                'Valid value is 0-3, leaving that field unchanged.',
                QMessageBox.Ok,
                QMessageBox.Ok)
            self.ui.lineEditIPFlags.setText(int2base(p.flags, 10))
            self.handleIPFlagsEditingFinish()
            return
        else:
            p.flags = base2int(inputFlags)
            ind = self.IPLine2Combo['flags'][p.flags]
            self.ui.comboBoxIPFlags.setCurrentIndex(ind)

    def handleIPFragEditingFinish(self):
        p = self.packetList[self.currentIndex][IP]
        inputFrag = self.ui.lineEditIPFragment.text()
        p.frag = base2int(inputFrag)
        self.ui.comboBoxIPFragment.setCurrentIndex(0)

    def handleIPTtlEditingFinish(self):
        p = self.packetList[self.currentIndex][IP]
        inputTtl = self.ui.lineEditIPTtl.text()
        p.ttl = base2int(inputTtl)
        if p.ttl not in self.IPLine2Combo['ttl'].keys():
            ind = self.IPLine2Combo['ttl']['custom']
        else:
            ind = self.IPLine2Combo['ttl'][p.ttl]
        self.ui.comboBoxIPTtl.setCurrentIndex(ind)
    
    def handleIPProtoEditingFinish(self):
        p = self.packetList[self.currentIndex][IP]
        inputProto = self.ui.lineEditIPProto.text()
        p.proto = base2int(inputProto)
        if p.proto not in self.IPLine2Combo['proto'].keys():
            ind = self.IPLine2Combo['proto']['custom']
        else:
            ind = self.IPLine2Combo['proto'][p.proto]
        self.ui.comboBoxIPProto.setCurrentIndex(ind)
    
    def handleIPChksumEditingFinish(self):
        p = self.packetList[self.currentIndex][IP]
        inputChksum = self.ui.lineEditIPChecksum.text()
        if inputChksum == 'auto':
            p.chksum = None
            ind = self.IPLine2Combo['chksum']['auto']
        else:
            p.chksum = base2int(inputChksum)
            ind = self.IPLine2Combo['chksum']['custom']
        self.ui.comboBoxIPChecksum.setCurrentIndex(ind)
    
    def handleIPSrcEditingFinish(self):
        p = self.packetList[self.currentIndex][IP]
        inputSrc = self.ui.lineEditIPSrc.text()
        if inputSrc == 'local':
            p.src = None
            ind = self.IPLine2Combo['src']['local']
        else:
            p.src = inputSrc
            ind = self.IPLine2Combo['src']['custom']
        self.ui.comboBoxIPSrc.setCurrentIndex(ind)
    
    def handleIPDstEditingFinish(self):
        p = self.packetList[self.currentIndex][IP]
        inputDst = self.ui.lineEditIPDst.text()
        p.dst = inputDst
        if p.dst not in self.IPLine2Combo['dst'].keys():
            ind = self.IPLine2Combo['dst']['custom']
        else:
            ind = self.IPLine2Combo['dst'][p.dst]
        self.ui.comboBoxIPDst.setCurrentIndex(ind)
    
    def handleIPVersionComboIndexChanged(self):
        p = self.packetList[self.currentIndex][IP]
        inputIndex = self.ui.comboBoxIPVersion.currentIndex()
        if inputIndex not in self.IPCombo2Line['version'].keys():
            pass
        else:
            inputVersion = self.IPCombo2Line['version'][inputIndex]
            p.version = base2int(inputVersion)
            self.ui.lineEditIPVersion.setText(inputVersion)

    def handleIPIhlComboIndexChanged(self):
        p = self.packetList[self.currentIndex][IP]
        inputIndex = self.ui.comboBoxIPIhl.currentIndex()
        if inputIndex not in self.IPCombo2Line['ihl'].keys():
            pass
        else:
            inputIhl = self.IPCombo2Line['ihl'][inputIndex]
            p.version = base2int(inputIhl)
            self.ui.lineEditIPIhl.setText(inputIhl)
    
    def handleIPTosComboIndexChanged(self):
        p = self.packetList[self.currentIndex][IP]
        inputIndex = self.ui.comboBoxIPTos.currentIndex()
        if inputIndex not in self.IPCombo2Line['tos'].keys():
            pass
        else:
            inputTos = self.IPCombo2Line['tos'][inputIndex]
            p.tos = base2int(inputTos)
            self.ui.lineEditIPTos.setText(inputTos)
    
    def handleIPLenComboIndexChanged(self):
        p = self.packetList[self.currentIndex][IP]
        inputIndex = self.ui.comboBoxIPLength.currentIndex()
        if inputIndex not in self.IPCombo2Line['len'].keys():
            pass
        else:
            inputLen = self.IPCombo2Line['len'][inputIndex]
            self.ui.lineEditIPLength.setText(inputLen)
            if inputLen == 'auto':
                p.len = None
            else:
                p.len = base2int(inputLen)
    
    def handleIPIdComboIndexChanged(self):
        # only one custom option, nothing to do here
        pass
    
    def handleIPFlagsComboIndexChanged(self):
        p = self.packetList[self.currentIndex][IP]
        inputIndex = self.ui.comboBoxIPFlags.currentIndex()
        if inputIndex not in self.IPCombo2Line['flags'].keys():
            pass
        else:
            p.flags = base2int(self.IPCombo2Line['flags'][inputIndex])
            self.ui.lineEditIPFlags.setText(self.IPCombo2Line['flags'][inputIndex])
    
    def handleIPFragComboIndexChanged(self):
        # only one custom option, nothing to do here
        pass

    def handleIPTtlComboIndexChanged(self):
        p = self.packetList[self.currentIndex][IP]
        inputIndex = self.ui.comboBoxIPTtl.currentIndex()
        if inputIndex not in self.IPCombo2Line['ttl'].keys():
            pass
        else:
            p.ttl = base2int(self.IPCombo2Line['ttl'][inputIndex])
            self.ui.lineEditIPTtl.setText(self.IPCombo2Line['ttl'][inputIndex])
    
    def handleIPProtoComboIndexChanged(self):
        p = self.packetList[self.currentIndex][IP]
        inputIndex = self.ui.comboBoxIPProto.currentIndex()
        if inputIndex not in self.IPCombo2Line['proto'].keys():
            pass
        else:
            p.proto = base2int(self.IPCombo2Line['proto'][inputIndex])
            self.ui.lineEditIPProto.setText(self.IPCombo2Line['proto'][inputIndex])
    
    def handleIPChksumComboIndexChanged(self):
        p = self.packetList[self.currentIndex][IP]
        inputIndex = self.ui.comboBoxIPChecksum.currentIndex()
        if inputIndex not in self.IPCombo2Line['chksum'].keys():
            pass
        else:
            self.ui.lineEditIPChecksum.setText(self.IPCombo2Line['chksum'][inputIndex])
            if self.IPCombo2Line['chksum'][inputIndex] == 'auto':
                p.chksum = None
                self.ui.lineEditIPChksum.setText('auto')
            else:
                # no other option here
                pass

    def handleIPSrcComboIndexChanged(self):
        p = self.packetList[self.currentIndex][IP]
        inputIndex = self.ui.comboBoxIPSrc.currentIndex()
        if inputIndex not in self.IPCombo2Line['src'].keys():
            pass
        else:
            self.ui.lineEditIPSrc.setText(self.IPCombo2Line['src'][inputIndex])
            if self.IPCombo2Line['src'][inputIndex] == 'local':
                p.src = None
            else:
                # no other option
                pass

    def handleIPDstComboIndexChanged(self):
        p = self.packetList[self.currentIndex][IP]
        inputIndex = self.ui.comboBoxIPDst.currentIndex()
        if inputIndex not in self.IPCombo2Line['dst'].keys():
            pass
        else:
            self.ui.lineEditIPDst.setText(self.IPCombo2Line['dst'][inputIndex])
            p.dst = self.IPCombo2Line['dst'][inputIndex]
    
    def handleUDPSportEditingFinish(self):
        p = self.packetList[self.currentIndex][UDP]
        inputSport = self.ui.lineEditUDPSport.text()
        p.sport = base2int(inputSport)
        self.ui.comboBoxUDPSport.setCurrentIndex(0)
    
    def handleUDPDportEditingFinish(self):
        p = self.packetList[self.currentIndex][UDP]
        inputDport = self.ui.lineEditUDPDport.text()
        p.dport = base2int(inputDport)
        self.ui.comboBoxUDPDport.setCurrentIndex(0)

    def handleUDPChksumEditingFinish(self):
        p = self.packetList[self.currentIndex][UDP]
        inputChksum = self.ui.lineEditUDPChksum.text()
        if inputChksum != 'auto':
            p.chksum = base2int(inputChksum)
            self.ui.comboBoxUDPChksum.setCurrentIndex(1)
        else:
            p.chksum = None
            self.ui.comboBoxUDPChksum.setCurrentIndex(0)
    
    def handleUDPLenEditingFinish(self):
        p = self.packetList[self.currentIndex][UDP]
        inputLen = self.ui.lineEditUDPLen.text()
        if inputLen != 'auto':
            p.len = base2int(inputLen)
            self.ui.comboBoxUDPLen.setCurrentIndex(1)
        else:
            p.len = None
            self.ui.comboBoxUDPLen.setCurrentIndex(0)
    
    def handleUDPChksumComboIndexChanged(self):
        p = self.packetList[self.currentIndex][UDP]
        inputIndex = self.ui.comboBoxUDPChksum.currentIndex()
        if inputIndex not in self.UDPCombo2Line['chksum'].keys():
            pass
        else:
            if self.UDPCombo2Line['chksum'][inputIndex] == 'auto':
                p.chksum = None
                self.ui.lineEditUDPChksum.setText('auto')
    
    def handleUDPLenComboIndexChanged(self):
        p = self.packetList[self.currentIndex][UDP]
        inputIndex = self.ui.comboBoxUDPLen.currentIndex()
        if inputIndex not in self.UDPCombo2Line['len'].keys():
            pass
        else:
            if self.UDPCombo2Line['len'][inputIndex] == 'auto':
                p.len = None
                self.ui.lineEditUDPLen.setText('auto')
    
    def handleTCPSportEditingFinish(self):
        p = self.packetList[self.currentIndex][TCP]
        inputSport = self.ui.lineEditTCPSport.text()
        p.sport = base2int(inputSport)
        self.ui.comboBoxTCPSport.setCurrentIndex(0)
    
    def handleTCPDportEditingFinish(self):
        p = self.packetList[self.currentIndex][TCP]
        inputDport = self.ui.lineEditTCPDport.text()
        p.dport = base2int(inputDport)
        self.ui.comboBoxTCPDport.setCurrentIndex(0)
    
    def handleTCPSeqEditingFinish(self):
        p = self.packetList[self.currentIndex][TCP]
        inputSeq = self.ui.lineEditTCPSeq.text()
        p.seq = base2int(inputSeq)
        self.ui.comboBoxTCPSeq.setCurrentIndex(0)

    def handleTCPAckEditingFinish(self):
        p = self.packetList[self.currentIndex][TCP]
        inputAck = self.ui.lineEditTCPAck.text()
        p.ack = base2int(inputAck)
        self.ui.comboBoxTCPAck.setCurrentIndex(0)
    
    def handleTCPDataofsEditingFinish(self):
        p = self.packetList[self.currentIndex][TCP]
        inputDataofs = self.ui.lineEditTCPDataofs.text()
        if inputDataofs not in self.TCPLine2Combo['dataofs'].keys():
            p.dataofs = base2int(inputDataofs)
            self.ui.comboBoxTCPDataofs.setCurrentIndex(self.TCPLine2Combo['dataofs']['custom'])
        else:
            p.dataofs = None
            self.ui.comboBoxTCPDataofs.setCurrentIndex(self.TCPLine2Combo['dataofs']['auto'])
    
    def handleTCPReservedEditingFinish(self):
        p = self.packetList[self.currentIndex][TCP]
        inputReserved = self.ui.lineEditTCPReserved.text()
        if inputReserved != 'none' and inputReserved != '0':
            self.ui.comboBoxTCPReserved.setCurrentIndex(self.TCPLine2Combo['reserved']['custom'])
            p.reserved = base2int(inputReserved)
        else:
            p.reserved = 0
            self.ui.comboBoxTCPReserved.setCurrentIndex(self.TCPLine2Combo['reserved']['none'])
    
    def handleTCPFlagsEdit(self):
        p = self.packetList[self.currentIndex][TCP]
        returnFlagsValueList = [2]
        diag = TCPFlagsDialog(returnFlagsValueList, self, p.flags)
        diag.show()
        diag.exec_()
        p.flags = returnFlagsValueList[0]
        self.showTCPFlags()

    def handleTCPWindowEditingFinish(self):
        p = self.packetList[self.currentIndex][TCP]
        p.window = base2int(self.ui.lineEditTCPWindow.text())
        self.ui.comboBoxTCPWindow.setCurrentIndex(0)

    def handleTCPChksumEditingFinish(self):
        p = self.packetList[self.currentIndex][TCP]
        inputChksum = self.ui.lineEditTCPChksum.text()
        if inputChksum not in self.TCPLine2Combo['chksum'].keys():
            self.ui.comboBoxTCPChksum.setCurrentIndex(self.TCPLine2Combo['chksum']['custom'])
            p.chksum = base2int(inputChksum)
        else:
            self.ui.comboBoxTCPChksum.setCurrentIndex(self.TCPLine2Combo['chksum']['auto'])
            p.chksum = None
    
    def handleTCPUrgptrEditingFinish(self):
        p = self.packetList[self.currentIndex][TCP]
        inputUrgptr = self.ui.lineEditTCPUrgptr.text()
        p.urgptr = base2int(inputUrgptr)
        self.ui.comboBoxTCPUrgptr.setCurrentIndex(0)
    
    def handleTCPDataofsComboIndexChanged(self):
        p = self.packetList[self.currentIndex][TCP]
        inputIndex = self.ui.comboBoxTCPDataofs.currentIndex()
        if inputIndex not in self.TCPCombo2Line['dataofs'].keys():
            pass
        else:
            p.dataofs = None
            self.ui.lineEditTCPDataofs.setText('auto')
    
    def handleTCPReservedComboIndexChanged(self):
        p = self.packetList[self.currentIndex][TCP]
        inputIndex = self.ui.comboBoxTCPReserved.currentIndex()
        if inputIndex not in self.TCPCombo2Line['reserved'].keys():
            pass
        else:
            p.reserved = 0
            self.ui.lineEditTCPReserved.setText('none')
    
    def handleTCPChksumComboIndexChanged(self):
        p = self.packetList[self.currentIndex][TCP]
        inputIndex = self.ui.comboBoxTCPChksum.currentIndex()
        if inputIndex not in self.TCPCombo2Line['chksum'].keys():
            pass
        else:
            p.chksum = None
            self.ui.lineEditTCPChksum.setText('auto')
    
    def handleICMPTypeEditingFinish(self):
        p = self.packetList[self.currentIndex][ICMP]
        p.type = base2int(self.ui.lineEditICMPType.text())
        
        if p.type not in self.ICMPLine2Combo['type'].keys():
            ind = self.ICMPLine2Combo['type']['custom']
        else:
            ind = self.ICMPLine2Combo['type'][p.type]
        self.ui.comboBoxICMPType.setCurrentIndex(ind)
    
    def handleICMPTypeComboIndexChanged(self):
        p = self.packetList[self.currentIndex][ICMP]
        inputIndex = self.ui.comboBoxICMPType.currentIndex()
        if inputIndex not in self.ICMPCombo2Line['type'].keys():
            pass
        else:
            self.ui.lineEditICMPType.setText(self.ICMPCombo2Line['type'][inputIndex])
            p.type = base2int(self.ICMPCombo2Line['type'][inputIndex])

    def handleICMPCodeEditingFinish(self):
        p = self.packetList[self.currentIndex][ICMP]
        p.code = base2int(self.ui.lineEditICMPCode.text())
    
    def handleICMPChksumEditingFinish(self):
        p = self.packetList[self.currentIndex][ICMP]
        inputChksum = self.ui.lineEditICMPChksum.text()
        if inputChksum == 'auto':
            self.ui.comboBoxICMPChksum.setCurrentIndex(0)
            p.chksum = None
        else:
            self.ui.comboBoxICMPChksum.setCurrentIndex(1)
            p.chksum = base2int(inputChksum)
    
    def handleICMPIdEditingFinish(self):
        p = self.packetList[self.currentIndex][ICMP]
        p.id = base2int(self.ui.lineEditICMPId.text())

    def handleICMPSeqEditingFinish(self):
        p = self.packetList[self.currentIndex][ICMP]
        p.seq = base2int(self.ui.lineEditICMPSeq.text())
    
    def handleICMPTs_oriEditingFinish(self):
        p = self.packetList[self.currentIndex][ICMP]
        p.ts_ori = self.ui.lineEditICMPTs_ori.text()

    def handleICMPTs_rxEditingFinish(self):
        p = self.packetList[self.currentIndex][ICMP]
        p.ts_rx = self.ui.lineEditICMPTs_rx.text()

    def handleICMPTs_txEditingFinish(self):
        p = self.packetList[self.currentIndex][ICMP]
        p.ts_tx = self.ui.lineEditICMPTs_tx.text()

    def handleICMPGwEditingFinish(self):
        p = self.packetList[self.currentIndex][ICMP]
        p.gw = self.ui.lineEditICMPGw.text()

    def handleICMPPtrEditingFinish(self):
        p = self.packetList[self.currentIndex][ICMP]
        p.ptr = self.ui.lineEditICMPPtr.text()

    def handleICMPAddr_maskEditingFinish(self):
        p = self.packetList[self.currentIndex][ICMP]
        p.addr_mask = self.ui.lineEditICMPAddr_mask.text()
    
    def handleICMPUnusedEditingFinish(self):
        p = self.packetList[self.currentIndex][ICMP]
        p.unused = base2int(self.ui.lineEditICMPUnused.text())
    
    def handleICMPReservedEditingFinish(self):
        p = self.packetList[self.currentIndex][ICMP]
        p.reserved = base2int(self.ui.lineEditICMPReserved.text())
    
    def handleICMPChksumComboIndexChanged(self):
        p = self.packetList[self.currentIndex][ICMP]
        inputIndex = self.ui.comboBoxICMPChksum.currentIndex()
        if inputIndex != 0:
            pass
        else:
            p.chksum = None
            self.ui.lineEditICMPChksum.setText('auto')

def main():
    app = QApplication(sys.argv)
    inj = PacketInjector()

    inj.show()
    sys.exit(app.exec_())
    

if __name__ == '__main__':
    main()