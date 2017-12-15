# ti.py text interface, used for debugging

from .base_ui import base_ui


class Ti(base_ui):
    def __init__(self):
        super().__init__()
        print('Welcome to packet injector')
        self.config = dict()
        self.info = list()
        self.if_list = []
        for i in ifaces:
            self.if_list.append(i)


    def getInput(self):
        if len(self.config) != 0:
            print('Current interface: %s', self.config['iface'])

        print('available network interfaces:')
        for i in range(len(self.if_list)):
            print('%d: %s' % (i, self.if_list[i]))
        if_number = int(input("Choose one: "))
        self.config = {"iface": self.if_list[if_number]}

        print('rewriting info!')
        self.info = list()
        L2_proto = input('Choose L2 protocol (Ethernet): ')
        if L2_proto == 'Ether' or L2_proto == 'ether':
            src = input('Choose src mac addr: ')
            dst = input('Choose dst mac addr: ')
            self.info.append({'type': Ether, 'info': {'src': src, 'dst': dst}})
        else:
            print('sorry, only ethernet is supported now, assuming L2 to be ethernet')
            self.info.append({'type': Ether, 'info': dict()})
        L3_proto = input('Choose L3 protocol (IP): ')
        if L3_proto == 'IP' or L3_proto == 'ip':
            src = input('choose src IP addr: ')
            dst = input('choose dst IP addr: ')
            version = int(input('choose IP version (4 or 6): '))
            ihl = int(input('choose IP header length (n * 32bit): '))
            ttl = int(input('choose IP TTL: '))
            proto = input('choose upper protocol (TCP): ')
            self.info.append({'type': IP,
                        'info': {'src': src,
                                'dst': dst,
                                'version': version,
                                'ihl': ihl,
                                'ttl': ttl,
                                'proto': proto}})
        else:
            print('sorry, only IP is supported now, assuming L3 to be IP')
            self.info.append({'type': IP, 'info': dict()})
        L4_proto = input('choose transport protocol (TCP):')
        if L4_proto == 'TCP' or L4_proto == 'tcp':
            src_port = int(input('choose src port: '))
            dst_port = int(input('choose dst port: '))
            seq = int(input('choose sequencial number: '))
            ack = int(input('choose ack number: '))
            self.info.append({'type': TCP, 'info': {'sport': src_port,
                                            'dport': dst_port,
                                            'seq': seq,
                                            'ack': ack}})
        else:
            print('sorry, only TCP is supported now')
            self.info.append({'type': TCP, 'info': dict()})
        send = False
        raw_send = input('Send packet? (Y/N)')
        if raw_send[0] in 'Yy':
            send = True
        return (self.config, self.info, send)
