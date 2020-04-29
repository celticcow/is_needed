#!/usr/bin/python3

from netaddr import IPNetwork, IPAddress
from network import Network

class Zone(object):
    """
    a collection of networks / hosts that make of a network boundry point
    """

    #constructor
    def __init__(self, name="default"):
        self.name = name
        self.meta = "n/a"
        self.policy = "n/a"
        self.network = list()
    
    #accessor
    def get_name(self):
        return(self.name)
    
    def get_meta(self):
        return(self.meta)
    
    def get_policy(self):
        return(self.policy)

    #modifiers
    def set_name(self,name):
        self.name = name
    
    def set_meta(self,meta):
        self.meta = meta

    def set_policy(self,policy):
        self.policy = policy

    def add_network(self, net1):
        self.network.append(net1)
    
    #compare stuff
    def compare(self, IP):
        #print (IP)

        for n in self.network:
            if(n.is_match(IP) == 1):
                #print(n.print_Network())
                return(1)
        return(0)
    
    #output
    def printZone(self):
        print (self.name)
        print (self.meta)
        print (self.policy)
        
        for x in self.network:
            x.print_Network()
# end of class