#!/usr/bin/python
# ----------------------------------------------------------------------------
# File: test_sr.py
# Date: Wed Dec 10 10:53:36 PST 2003 
# Author: Martin Casado
#
# Simple testing script to test an sr implementation on a given topology
#
# Usage: ./test_sr.py [<router bin>] [<server>]
#
# This file requires that:
#
# ping, traceroute, ftp and md5sum are in the path
#
#
#   A prefect test should look as follows:
#
#    ++++++++++++++++++++++++++++++++++++++++
#    Test Results
#    ++++++++++++++++++++++++++++++++++++++++
#    ping test      : passed 5  of 5
#    traceroute test: passed 5  of 5
#    http test      : passed
#    ++++++++++++++++++++++++++++++++++++++++
#
# ----------------------------------------------------------------------------

import os
import sys
import string
import httplib

eth0ip = '171.67.243.176 '
eth1ip = '171.67.243.180'
eth2ip = '171.67.243.182'
app1ip = '171.67.243.181'
app2ip = '171.67.243.183'

rtable = 'rtable'
topology    = '1'
username    = 'xin_wu'

def usage():
    print 'Usage: ./test_sr.py [<router bin>] [<server>]'

def start_router(bin, server):
    print 'Connecting to',server,' on topology '+topology
    cmd = bin+' -t '+topology+' -s '+server+ ' -r '+rtable+' -u '+username+' > /dev/null'
    os.system(cmd)

def do_traceroute(ip):
    lines = os.popen('traceroute -n '+ip).readlines()

    for i in range(0, len(lines)):
        line = lines[i]
        line.replace('ms','')
        line.replace('*','')
        line = line.split(' ')
        lines[i] = string.join(line[0:],' ')
    return lines    

def test_traceroute(ip, pos, test_end):
    lines = do_traceroute(ip) 

    end = lines[len(lines) - 1]
    if test_end and end.find(ip) == -1:
        return 1
    line = lines[len(lines) - 1 - pos]
    line = line.split(' ')
    if len(line) <=1 :
        return 1 
    return 0    

def traceroute_routers():        
    ok = 0

    print 'Tracerouting to eth0 on router ..',
    tr1 = test_traceroute(eth0ip, 0, 1)
    if not tr1:
        print 'ok'
        ok = ok + 1
    else:
        print 'failed'
    print 'Tracerouting to eth1 on router ..',
    tr1 = test_traceroute(eth1ip, 0, 0)
    if not tr1:
        print 'ok'
        ok = ok + 1
    else:
        print 'failed'
    print 'Tracerouting to eth2 on router ..',
    tr1 = test_traceroute(eth2ip, 0, 0)
    if not tr1:
        print 'ok'
        ok = ok + 1
    else:
        print 'failed'
    print 'Tracerouting to app server 1 ..',
    tr1 = test_traceroute(app1ip, 1, 1)
    if not tr1:
        print 'ok'
        ok = ok + 1
    else:
        print 'failed'
    print 'Tracerouting to app server 2 ..',
    tr1 = test_traceroute(app2ip, 1, 1)
    if not tr1:
        print 'ok'
        ok = ok + 1
    else:
        print 'failed'

    return ok    

def http_test():

    print 'Attemping to get file from http server ... '
    http = httplib.HTTPConnection(app2ip, 80, 300)
    http.request('GET', '/')
    res = http.getresponse()
    html = res.read()
    http.close()
    print 'content:', html
    if html.find("VNS App Server Website") == -1:
        print 'failed'
        return 1
    else:
        print 'ok'
        return 2
    return 0

# ----------------------------------------------------------------------------
# Ping test
# ----------------------------------------------------------------------------

def ping_test():    
    ok = 0 

    print 'Trying to ping eth0 on router ..',
    retp1 = os.system('ping -c2 -w3 '+eth0ip+' > /dev/null')
    if not retp1:
        print 'ok'
        ok = ok + 1
    else:
        print 'failed'

    print 'Trying to ping eth1 on router ..',
    retp2 = os.system('ping -c2 -w3 '+eth1ip+' > /dev/null')
    if not retp2:
        print 'ok'
        ok = ok + 1
    else:
        print 'failed'

    print 'Trying to ping eth2 on router ..',
    retp3 = os.system('ping -c2 -w3 '+eth2ip+' > /dev/null')
    if not retp3:
        print 'ok'
        ok = ok + 1
    else:
        print 'failed'

    print 'Trying to ping app server 1 ..',
    retp4 = os.system('ping -c2 -w3 '+app1ip+' > /dev/null')
    if not retp4:
        print 'ok'
        ok = ok + 1
    else:
        print 'failed'

    print 'Trying to ping app server 2 ..',
    retp5 = os.system('ping -c2 -w3 '+app2ip+' > /dev/null')
    if not retp5:
        print 'ok'
        ok = ok + 1
    else:
        print 'failed'

    return ok    

#-----------------------------------------------------------------------------
#                 Run all the tests in sequence
#-----------------------------------------------------------------------------

def test_router(bin = './sr', server = 'vns-2.stanford.edu'):

    if not os.access(rtable, os.R_OK):
        print 'Do not have routing table for topology 0'
        return

    if not os.access(bin, os.X_OK):
        print 'Cannot execute binary ',bin
        return

    # -- just in case
    os.system('killall '+bin + ' > /dev/null')

    pid = os.fork()

    ## -- child
    if pid == 0:
        start_router(bin, server)
        sys.exit(0)

    # -- parent

    ping_res = ping_test()
    tr_res   = traceroute_routers()
    http_res  = http_test()

    os.system('killall '+bin)

    # -- report
    print '++++++++++++++++++++++++++++++++++++++++'
    print '             Test Results               '
    print '++++++++++++++++++++++++++++++++++++++++'
    print 'ping test      : passed',ping_res,' of 5'
    print 'traceroute test: passed',tr_res,' of 5'
    if http_res == 1:
        print 'http test      : did not get the right page'
    elif http_res == 2:
        print 'http test      : passed'
    else:
        print 'http test      : failed unclear reason'
    print '++++++++++++++++++++++++++++++++++++++++'


#-----------------------------------------------------------------------------
#                                   Main
#-----------------------------------------------------------------------------

if __name__ == '__main__':
    
    if len(sys.argv) == 1:
        test_router()
    elif len(sys.argv) == 2:
        test_router(sys.argv[1])
    else:
        test_router(sys.argv[1], sys.argv[2])
