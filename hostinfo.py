#!/usr/bin/python3

"""
host info regarding what zones / policies
this host matches on for zone searches

"""
class hostinfo(object):
    ### Constructor ###
    def __init__(self, ip="0.0.0.0"):
        self.ip = ip
        self.count = 0
        self.meta = list()
        self.policy = list()
    
    ### Modifiers ###
    def set_ip(ip):
        self.ip = ip

    def add_info(self, meta_str, policy_str):
        self.meta.append(meta_str)
        self.policy.append(policy_str)
        #self.meta[self.count] = meta_str
        #self.policy[self.cout] = policy_str
        self.count += 1

    ### Accessors ###

    def get_count(self):
        return(self.count)
    
    def get_ip(self):
        return(self.ip)
        
    def get_meta(self, index):
        return(self.meta[index])
    
    def get_policy(self, index):
        return(self.policy[index])
    
    def peer_zone(self, search_str, search_meta):
        #dmz to zmd routed
        if('Services-DMZ' in search_str):
            for x in range(self.count):
                if(self.policy[x] == 'services-zmd Security'):
                    return True
            return False
        #zmd to dmz routed
        elif('services-zmd' in search_str):
            for x in range(self.count):
                if(self.policy[x] == 'Services-DMZ Security'):
                    return True
            #return False
        #zmd to zmd routed
        #elif('services-zmd' in search_str):
            for x in range(self.count):
                if(self.policy[x] == 'services-zmd Security'):
                    return True
            return False
        #DC Seg when in same dc
        elif('DataCenterSeg' in search_str):
            #my_meta_pre   = self.meta.split(' ')[0]
            pass_meta_pre = search_meta.split(' ')[0]
            for x in range(self.count):
                my_meta_pre = self.meta[x].split(' ')[0]
                if((self.policy[x] == 'DataCenterSeg Network') and (my_meta_pre == pass_meta_pre)):
                    print(my_meta_pre + "  " + pass_meta_pre)
                    return True
            return False
        ## more cases to come
        #....
        #Default return case
        return False
    #end of peer_zone()
    
#end of class hostinfo