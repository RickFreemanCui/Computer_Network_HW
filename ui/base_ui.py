# base_ui.py provide base ui for gui and ui to inherit
from scapy.all import *

class base_ui(object):
    def __init__(self):
        # I want to organise the protocol stack in a tree manner, from L2 to L4
        self.proto = Protocols()
        

    def getInput(self):
        pass



class Protocols(dict):
    def __init__(self):
        super().__init__()
        self['Ether'] = {'name': 'Ethernet',
                         'type': Ether,
                         'options': {'src': 'ff:ff:ff:ff:ff:ff',
                                     'dst': '00:00:00:00:00:00',
                                     'type': 0x9000}}
        self['IP'] = {'name': 'IP',
                      'type': IP,
                      'options': {'version': 4,
                                  'ihl': 5,
                                  'tos': 0x0,
                                  'len': 20,
                                  'id': 1,
                                  'flags': 0,
                                  'frag': None,
                                  'ttl': 64,
                                  'proto': 'IP',
                                  'chksum': None,
                                  'src': '0.0.0.0',
                                  'dst': '255.255.255.255',
                                  'options': []}}
        self['IPOption'] = {'name': 'IPOption',
                            'type': IPOption,
                            'options': {'copy_flag': 0,
                                        'optclass': 0,
                                        'option': 0,
                                        'length': None,
                                        'value': b''}}
        self['TCP'] = {'name': 'TCP',
                       'type': TCP,
                       'options': {'sport': 21,
                                  'dport': 80,
                                  'seq': 0,
                                  'ack': 0,
                                  'dataofs': 5,
                                  'reserved': 0,
                                  'flags': 'S',
                                  'window': 8192,
                                  'chksum': None,
                                  'urgptr': 0,
                                  'options': []}}
        self['UDP'] = {'name': 'UDP',
                       'type': UDP,
                       'options': {'sport': 'domain',
                                   'dport': 'domain',
                                   'len': 8,
                                   'chksum': None}}
        self['ICMP'] = {'name': 'ICMP',
                        'type': ICMP,
                        'options': {}}
        
        self['ARP'] = {'name': 'ARP',
                       'type': ARP,
                       'options': {'hwtype': 0x1,
                                   'ptype': 0x800,
                                   'hwlen': 6,
                                   'plen': 4,
                                   'hwsrc': '60:14:b3:a9:75:55',
                                   'psrc': '10.162.51.240',
                                   'hwdst': '00:00:00:00:00:00',
                                   'pdst': '0.0.0.0'}}