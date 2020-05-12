#!/usr/bin/python3 -W ignore::DeprecationWarning

import cgi, cgitb
import csv
import sys

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