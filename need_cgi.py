#!/usr/bin/python3 -W ignore::DeprecationWarning

import csv
import sys
import cgi,cgitb

from zone import Zone
from hostinfo import hostinfo
from network import Network
from packetsearch import packetsearch

#remove the InsecureRequestWarning messages
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
Greg Dunlap / celtic_cow 

"""

### Functions
#############
"""
read from zonedata.csv and build list of zones
"""
def build_zone_list(term="\n"):
    debug = 1
    if(debug == 1):
        print("in build_zone_list()")
    
    startZ = 1
    csvindex = 0
    list_of_zones = list()

    #build list of zones from file
    with open('zonedata.csv') as csvfile:
        reader = csv.reader(csvfile, delimiter=',', quotechar='|')
        for row in reader:
            data = row[0]

            if(startZ == 1):
                #zone title
                ztemp = Zone(data)
                list_of_zones.append(ztemp)
                startZ = 0
            elif("Meta" in data):
                list_of_zones[csvindex].set_meta(data)
            elif("Policy" in data):
                list_of_zones[csvindex].set_policy(data)
            elif(data == "****"):
                #end of zone section
                startZ = 1
                csvindex = csvindex + 1
            else:
                tmp_net = Network(data)
                list_of_zones[csvindex].add_network(tmp_net)
        #end of for row
    #end of csv

    return(list_of_zones)
#end of function build_zone

"""
take in two hostsinfo objects and build map of policy differences
"""
def policy_check(hostinfo1, hostinfo2, port, term="\n"):
    debug = 1
    if(debug == 1):
        print("In function policy_check()", end=term)
    
    host_len1 = hostinfo1.get_count()
    host_len2 = hostinfo2.get_count()

    policylist = set()

    ## use case 1: no hits for either 1.  nothing to do
    if(host_len1 == 0 and host_len2 == 0):
        print("Nothing to do : no hits!", end=term)
        return
    elif(host_len1 == 0 and host_len2 > 0):
        #host1 had no hits, but host2 did
        print("host_len1 = 0 : host_len2 > 0", end=term)

        for x in range(host_len2):
            policylist.add(hostinfo2.get_policy(x))

    elif(host_len2 == 0 and host_len1 > 0):
        #host1 had hits but host2 had no hits
        print("host_len1 > 0 : host_len2 = 0", end=term)

        for x in range(host_len1):
            policylist.add(hostinfo1.get_policy(x))
            
    elif(host_len1 > 0 and host_len2 > 0):
        ### both searches returned hits.
        # if dmz in a and zmd in b // exclude both
        # if DataCenterSeg in both ... and both same DC exclude both

        ###
        # issue where zmd to zmd but wtc to edc.   so dc seg on one side
        # so that still gets flagged ... soon wtc will have seg group though ... need special case ?
        ###
        for i in range(host_len1):
            tmp_policy = hostinfo1.get_policy(i)
            tmp_meta   = hostinfo1.get_meta(i)

            if(hostinfo2.peer_zone(tmp_policy, tmp_meta)):
                print("don't need to include : " + tmp_policy, end=term)
            else:
                policylist.add(hostinfo1.get_policy(i))
            
        for j in range(host_len2):
            tmp_policy = hostinfo2.get_policy(j)
            tmp_meta   = hostinfo2.get_meta(j)

            if(hostinfo1.peer_zone(tmp_policy, tmp_meta)):
                print("don't need to include : " + tmp_policy, end=term)
            else:
                policylist.add(hostinfo2.get_policy(j))

        print("-------------------------", end=term)
    else:
        print("Something went wrong with zone searches", end=term)

    return(policylist)
#end of function  policy_check()

def build_hostinfo(hostinfo, zone_list, term="\n"):
    debug = 1

    for x in zone_list:
        if(x.compare(hostinfo.get_ip())):
            if(debug == 1):
                print("match in zone", end=term)
                print(x.get_name(), end=term)
                print(x.get_meta(), end=term)
                print(x.get_policy(), end=term)
            hostinfo.add_info(x.get_meta().split(':')[1], x.get_policy().split(':')[1])
    
    return(hostinfo)
#end of function build_hostinfo()

def main():
    debug = 1
    term="<br>"

    #create instance field storage
    form  = cgi.FieldStorage()
    ip1   = form.getvalue('sourceip')
    ip2   = form.getvalue('destip')
    port  = form.getvalue('service')

    ## html header and config data dump
    print ("Content-type:text/html\r\n\r\n")
    print ("<html>")
    print ("<head>")
    print ("<title>Rule Needed</title>")
    print ("</head>")
    print ("<body>")
    print ("<br><br>")
    print("Needed Search 0.1<br><br>")

    print(ip1, end=term)
    print(ip2, end=term)
    print(port, end=term)
    print("--------------------", end=term)

    zones_list = build_zone_list(term)

    hostinfo1 = hostinfo(ip1)
    hostinfo2 = hostinfo(ip2)
    policies = set()

    print("Zone Data for Source: ", end=term)
    hostinfo1 = build_hostinfo(hostinfo1, zones_list, term)
    print("Zone Data for Dest: ", end=term)
    hostinfo2 = build_hostinfo(hostinfo2, zones_list, term)
    print("**********************************", end=term)

    policies = policy_check(hostinfo1, hostinfo2, port, term)
    print("Policies to Search Against", end=term)
    print(policies, end=term)

    for policy in policies:
        print(policy, end=term)

        #need to add action accept check too
        """packet_mode_json = {
            "name" : policy,
            "filter" : "src:" + ip1 + " AND dst:" + ip2 + " AND svc:" + port,
            "filter-settings" : {
                "search-mode" : "packet"
            }
        }

        print(packet_mode_json)
        """
        if(debug == 1):
            print("creating packet search object", end=term)
        search = packetsearch(ip1, ip2, port, policy)
   
        search.create_json_string()
        print(search.get_json(), end=term)

        search.do_search()

        if(debug == 1):
            print("destroying packet search object", end=term)

    print("***** End of Program *****", end=term)
    print("<br><br>")
    print("</body>")
    print("</html>")


if __name__ == "__main__":
    main()
### end of program