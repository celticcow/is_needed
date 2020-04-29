#!/usr/bin/python3

from netaddr import IPNetwork, IPAddress

class Network(object):
    """
    """

    #constructor
    def __init__(self, network="0.0.0.0/0"):
        self.network = network
    
    #modifiers
    def set_network(self, network):
        self.network = network

    #accessors
    def get_network(self):
        return(self.network)

    def print_Network(self):
        print(self.network)
    
    def is_match(self, IP):
        if IPAddress(IP) in IPNetwork(self.network):
            return(1)
        else:
            return(0)
#end of class