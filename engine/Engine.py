from scapy.all import *

class Engine(object):
    def __init__(self):
        self.initPacket()

    def updateConfig(self, config):
        try:
            conf.iface = config['iface']
        except KeyError:
            pass
        

    def updateInfo(self, info):
        for layer in info:
            # layer should be a dict {'type': Type of layer protocol, should be a scapy layer type,
            #                         'info': dict containing key: value pairs of info
            # }
            # first detect whether our packet has this layer. if not, make a stack
            try:
                if layer['type'] not in self.packet:
                    self.packet /= layer['type']()
                    self.updateLayerInfo(layer)
                else:
                    self.updateLayerInfo(layer)
            except TypeError: # first layer
                self.packet = layer['type']()
                self.updateLayerInfo(layer)
                
    def updateLayerInfo(self, layer):
        currentLayer = self.packet[layer['type']]
        for infoItem in layer['info'].keys():
            currentLayer.fields[infoItem] = layer['info'][infoItem]
    
    def initPacket(self):
        self.packet = None
    
    def sendPacket(self):
        sendp(self.packet)