# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# For more information, please refer to <http://unlicense.org/>

import struct
from .mcs_pb2 import *
import uuid
from .checkin_pb2 import AndroidCheckinRequest, AndroidCheckinResponse
from .android_checkin_pb2 import AndroidCheckinProto, ChromeBuildProto
import logging
from oscrypto.asymmetric import generate_pair
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import json
import time
from google.protobuf.json_format import MessageToDict
from binascii import hexlify

try:
  from urllib.request import Request, urlopen
  from urllib.parse import urlencode
except ImportError:
  from urllib2 import Request, urlopen
  from urllib import urlencode

try:
  FileExistsError
except NameError:
  FileExistsError = OSError
  FileNotFoundError = IOError

try:
  unicode
except NameError:
  unicode = str

__log = logging.getLogger("push_receiver")

SERVER_KEY = (
    b"\x04\x33\x94\xf7\xdf\xa1\xeb\xb1\xdc\x03\xa2\x5e\x15\x71\xdb\x48\xd3"
    + b"\x2e\xed\xed\xb2\x34\xdb\xb7\x47\x3a\x0c\x8f\xc4\xcc\xe1\x6f\x3c"
    + b"\x8c\x84\xdf\xab\xb6\x66\x3e\xf2\x0c\xd4\x8b\xfe\xe3\xf9\x76\x2f"
    + b"\x14\x1c\x63\x08\x6a\x6f\x2d\xb1\x1a\x95\xb0\xce\x37\xc0\x9c\x6e"
)

REGISTER_URL = "https://android.clients.google.com/c2dm/register3"
CHECKIN_URL = "https://android.clients.google.com/checkin"
FCM_SUBSCRIBE = 'https://fcm.googleapis.com/fcm/connect/subscribe'
FCM_ENDPOINT = 'https://fcm.googleapis.com/fcm/send'


def __do_request(req, retries=5):
  for _ in range(retries):
    try:
      resp = urlopen(req)
      resp_data = resp.read()
      resp.close()
      __log.debug(resp_data)
      return resp_data
    except Exception as e:
      __log.debug("error during request", exc_info=e)
      time.sleep(1)
  return None


def gcm_check_in(androidId=None, securityToken=None, **kwargs):
  """
  perform check-in request

  androidId, securityToken can be provided if we already did the initial
  check-in

  returns dict with androidId, securityToken and more
  """
  chrome = ChromeBuildProto()
  chrome.platform = 3
  chrome.chrome_version = "63.0.3234.0"
  chrome.channel = 1

  checkin = AndroidCheckinProto()
  checkin.type = 3
  checkin.chrome_build.CopyFrom(chrome)

  payload = AndroidCheckinRequest()
  payload.user_serial_number = 0
  payload.checkin.CopyFrom(checkin)
  payload.version = 3
  if androidId:
    payload.id = int(androidId)
  if securityToken:
    payload.security_token = int(securityToken)

  __log.debug(payload)
  req = Request(
      url=CHECKIN_URL,
      headers={"Content-Type": "application/x-protobuf"},
      data=payload.SerializeToString()
  )
  resp_data = __do_request(req)
  resp = AndroidCheckinResponse()
  resp.ParseFromString(resp_data)
  __log.debug(resp)
  return MessageToDict(resp)


def urlsafe_base64(data):
  """
  base64-encodes data with -_ instead of +/ and removes all = padding.
  also strips newlines

  returns a string
  """
  res = urlsafe_b64encode(data).replace(b"=", b"")
  return res.replace(b"\n", b"").decode("ascii")


def gcm_register(appId, retries=5, **kwargs):
  """
  obtains a gcm token

  appId: app id as an integer
  retries: number of failed requests before giving up

  returns {"token": "...", "appId": 123123, "androidId":123123,
           "securityToken": 123123}
  """
  # contains androidId, securityToken and more
  chk = gcm_check_in()
  __log.debug(chk)
  body = {
      "app": "org.chromium.linux",
      "X-subtype": appId,
      "device": chk["androidId"],
      "sender": urlsafe_base64(SERVER_KEY)
  }
  data = urlencode(body)
  __log.debug(data)
  auth = "AidLogin {}:{}".format(chk["androidId"], chk["securityToken"])
  req = Request(
      url=REGISTER_URL,
      headers={"Authorization": auth},
      data=data.encode("utf-8")
  )
  for _ in range(retries):
    resp_data = __do_request(req, retries)
    if b"Error" in resp_data:
      err = resp_data.decode("utf-8")
      __log.error("Register request has failed with " + err)
      continue
    token = resp_data.decode("utf-8").split("=")[1]
    chkfields = {k: chk[k] for k in ["androidId", "securityToken"]}
    res = {"token": token, "appId": appId}
    res.update(chkfields)
    return res
  return None


def fcm_register(sender_id, token, retries=5):
  """
  generates key pair and obtains a fcm token

  sender_id: sender id as an integer
  token: the subscription token in the dict returned by gcm_register

  returns {"keys": keys, "fcm": {...}}
  """
  # I used this analyzer to figure out how to slice the asn1 structs
  # https://lapo.it/asn1js
  # first byte of public key is skipped for some reason
  # maybe it's always zero
  public, private = generate_pair("ec", curve=unicode("secp256r1"))
  from base64 import b64encode
  __log.debug("# public")
  __log.debug(b64encode(public.asn1.dump()))
  __log.debug("# private")
  __log.debug(b64encode(private.asn1.dump()))
  keys = {
      "public": urlsafe_base64(public.asn1.dump()[26:]),
      "private": urlsafe_base64(private.asn1.dump()),
      "secret": urlsafe_base64(os.urandom(16))
  }
  data = urlencode({
      "authorized_entity": sender_id,
      "endpoint": "{}/{}".format(FCM_ENDPOINT, token),
      "encryption_key": keys["public"],
      "encryption_auth": keys["secret"]
  })
  __log.debug(data)
  req = Request(url=FCM_SUBSCRIBE, data=data.encode("utf-8"))
  resp_data = __do_request(req, retries)
  return {"keys": keys, "fcm": json.loads(resp_data)}


def register(sender_id):
  """register gcm and fcm tokens for sender_id"""
  appId = "wp:receiver.push.com#{}".format(uuid.uuid4())
  subscription = gcm_register(appId=appId)
  __log.debug(subscription)
  fcm = fcm_register(sender_id=sender_id, token=subscription["token"])
  __log.debug(fcm)
  res = {"gcm": subscription}
  res.update(fcm)
  return res

# -------------------------------------------------------------------------


MCS_VERSION = 41

PACKET_BY_TAG = [
    HeartbeatPing,
    HeartbeatAck,
    LoginRequest,
    LoginResponse,
    Close,
    "MessageStanza",
    "PresenceStanza",
    IqStanza,
    DataMessageStanza,
    "BatchPresenceStanza",
    StreamErrorStanza,
    "HttpRequest",
    "HttpResponse",
    "BindAccountRequest",
    "BindAccountResponse",
    "TalkMetadata"
]


def __read(s, size):
  buf = b''
  while len(buf) < size:
    buf += s.recv(size - len(buf))
  return buf


# protobuf variable length integers are encoded in base 128
# each byte contains 7 bits of the integer and the msb is set if there's
# more. pretty simple to implement


def __read_varint32(s):
  res = 0
  shift = 0
  while True:
    b, = struct.unpack("B", __read(s, 1))
    res |= (b & 0x7F) << shift
    if (b & 0x80) == 0:
      break
    shift += 7
  return res


def __encode_varint32(x):
  res = bytearray([])
  while x != 0:
    b = (x & 0x7F)
    x >>= 7
    if x != 0:
      b |= 0x80
    res.append(b)
  return bytes(res)


def __send(s, packet):
  header = bytearray([MCS_VERSION, PACKET_BY_TAG.index(type(packet))])
  __log.debug(packet)
  payload = packet.SerializeToString()
  buf = bytes(header) + __encode_varint32(len(payload)) + payload
  __log.debug(hexlify(buf))
  n = len(buf)
  total = 0
  while total < n:
    sent = s.send(buf[total:])
    if sent == 0:
      raise RuntimeError("socket connection broken")
    total += sent


def __recv(s, first=False):
  if first:
    version, tag = struct.unpack("BB", __read(s, 2))
    __log.debug("version {}".format(version))
    if version < MCS_VERSION and version != 38:
      raise RuntimeError("protocol version {} unsupported".format(version))
  else:
    tag, = struct.unpack("B", __read(s, 1))
  __log.debug("tag {} ({})".format(tag, PACKET_BY_TAG[tag]))
  size = __read_varint32(s)
  __log.debug("size {}".format(size))
  if size >= 0:
    buf = __read(s, size)
    __log.debug(hexlify(buf))
    Packet = PACKET_BY_TAG[tag]
    payload = Packet()
    payload.ParseFromString(buf)
    __log.debug(payload)
    return payload
  return None


def __app_data_by_key(p, key, blow_shit_up=True):
  for x in p.app_data:
    if x.key == key:
      return x.value
  if blow_shit_up:
    raise RuntimeError("couldn't find in app_data {}".format(key))
  return None


def __listen(s, credentials, callback, persistent_ids, obj):
  import http_ece
  import cryptography.hazmat.primitives.serialization as serialization
  from cryptography.hazmat.backends import default_backend
  load_der_private_key = serialization.load_der_private_key

  gcm_check_in(**credentials["gcm"])
  req = LoginRequest()
  req.adaptive_heartbeat = False
  req.auth_service = 2
  req.auth_token = credentials["gcm"]["securityToken"]
  req.id = "chrome-63.0.3234.0"
  req.domain = "mcs.android.com"
  req.device_id = "android-%x" % int(credentials["gcm"]["androidId"])
  req.network_type = 1
  req.resource = credentials["gcm"]["androidId"]
  req.user = credentials["gcm"]["androidId"]
  req.use_rmq2 = True
  req.setting.add(name="new_vc", value="1")
  req.received_persistent_id.extend(persistent_ids)
  __send(s, req)
  login_response = __recv(s, first=True)
  while True:
    p = __recv(s)
    if type(p) is not DataMessageStanza:
      continue
    crypto_key = __app_data_by_key(p, "crypto-key")[3:]  # strip dh=
    salt = __app_data_by_key(p, "encryption")[5:]  # strip salt=
    crypto_key = urlsafe_b64decode(crypto_key.encode("ascii"))
    salt = urlsafe_b64decode(salt.encode("ascii"))
    der_data = credentials["keys"]["private"]
    der_data = urlsafe_b64decode(der_data.encode("ascii") + b"========")
    secret = credentials["keys"]["secret"]
    secret = urlsafe_b64decode(secret.encode("ascii") + b"========")
    privkey = load_der_private_key(
        der_data, password=None, backend=default_backend()
    )
    decrypted = http_ece.decrypt(
        p.raw_data, salt=salt,
        private_key=privkey, dh=crypto_key,
        version="aesgcm",
        auth_secret=secret
    )
    callback(obj, json.loads(decrypted), p)


def listen(credentials, callback, received_persistent_ids=[], obj=None):
  """
  listens for push notifications

  credentials: credentials object returned by register()
  callback(obj, notification, data_message): called on notifications
  received_persistent_ids: any persistent id's you already received.
                           array of strings
  obj: optional arbitrary value passed to callback
  """
  import socket
  import ssl
  HOST = "mtalk.google.com"
  context = ssl.create_default_context()
  sock = socket.create_connection((HOST, 5228))
  s = context.wrap_socket(sock, server_hostname=HOST)
  __log.debug(s.version())
  __listen(s, credentials, callback, received_persistent_ids, obj)
  s.close()
  sock.close()


def run_example():
  """sample that registers a token and waits for notifications"""
  import argparse
  import sys
  import appdirs
  import os.path

  parser = argparse.ArgumentParser(description="push_receiver demo")
  parser.add_argument("--sender-id")
  parser.add_argument("--no-listen", action="store_true")
  levels = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
  parser.add_argument("--log", choices=levels)
  args = parser.parse_args(sys.argv[1:])
  logging.basicConfig(level=logging.CRITICAL + 1)
  args.log and logging.getLogger().setLevel(args.log)

  data_path = appdirs.user_data_dir(
      appname="push_receiver",
      appauthor="lolisamurai"
  )
  try:
    os.makedirs(data_path)
  except FileExistsError:
    pass
  credentials_path = os.path.join(data_path, "credentials.json")
  persistent_ids_path = os.path.join(data_path, "persistent_ids")

  try:
    with open(credentials_path, "r") as f:
      credentials = json.load(f)

  except FileNotFoundError:
    credentials = register(sender_id=int(args.sender_id))
    with open(credentials_path, "w") as f:
      json.dump(credentials, f)

  __log.debug(credentials)
  print("send notifications to {}".format(credentials["fcm"]["token"]))
  if args.no_listen:
    return

  def on_notification(obj, notification, data_message):
    idstr = data_message.persistent_id + "\n"
    with open(persistent_ids_path, "r") as f:
      if idstr in f:
        return
    with open(persistent_ids_path, "a") as f:
      f.write(idstr)
    n = notification["notification"]
    text = n["title"]
    if n["body"]:
      text += ": " + n["body"]
    print(text)

  with open(persistent_ids_path, "a+") as f:
    received_persistent_ids = [x.strip() for x in f]

  listen(credentials, on_notification, received_persistent_ids)
