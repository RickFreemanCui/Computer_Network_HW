# Computer_Network_HW
A packet injection program using scapy as injection library, and PyQt5 as its GUI library

Phase 1: Develop a prototype version as soon as possible.

## Current Status

I have figured out a so called ``model-view-controller`` means to develop this packet injecter. The program is splitted into three parts, model, view, and controller. The model part is the easiest part, since scapy do most of the work. I simply pass the packet construction parameters into scapy, and send the packet from L2 when required. The view part should be the most complicated part, since it has to deal with user input and assemble them in to a data structure predefined. The controller part assemble these two parts and defines a mainloop that continuous get new input, and send the input to the model part, and wait for new inputs again, until the program exits.

so the program is split into three parts:

    - Model: simply construst packet using scapy, from the input given
    - View: deal with user input, pack input into a data structure and return (with control information) it to controller
    - Controller: connect the two parts above, after calling its run() function, the program is in a constant loop state, getting new input and updating Engine state (not yet implemented), and send the packet when required.

The data structure passed from UI to Engine needs more elaboration:

    - config: a dict, current only support network interfaces, example:
        config = {'iface': 'eth0'}
        
        note that the UI should take care of choosing the correct name of network interface
    
    - info: a list, the order is from lower protocol to upper protocol. example:
        info = [{'type': Ether, 'info': info_dict_ether},
                {'type': IP, 'info': info_dict_ip},
                {'type': TCP, 'info': info_dict_tcp}]
        info_dict_ether = {'src': '40:10:0f:a0:11:ff',
                           'dst': 'ff:ff:ff:ff:ff:ff'}
        info_dict_ip = {'src': '192.168.1.1',
                        'dst': '10.40.24.25',
                        'ihl': 5}
        info_dict_tcp = {'sprot': 56789,
                        'dport': 8080,
                        'ack': 0,
                        'seq': 100}
        Note that the type in the info dict has value coming from scapy. That is, they are class objects from *scapy.all*. And thus designer of UI should import scapy when before constructing the info list.
        
        of course, @(YKT) add new fields when necessary, and inform me in time.

I wrote a simple text interface for debugging purpose, and it only support TCP over IP over Ethernet.        