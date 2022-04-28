# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# For more information, please refer to <http://unlicense.org/>

import struct
import select
from .mcs_pb2 import *
import uuid
import logging
from base64 import urlsafe_b64decode
import os
import json
import time
import threading
from binascii import hexlify
from .register import gcm_check_in, register

try:
  FileExistsError
except NameError:
  FileExistsError = OSError
  FileNotFoundError = IOError

__log = logging.getLogger("push_receiver")

READ_TIMEOUT_SECS = 60 * 60
MIN_RESET_INTERVAL_SECS = 60 * 5
CHECKIN_INTERVAL_SECS = 60 * 60
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
  __log.debug(f'Packet to send:\n{packet}')
  payload = packet.SerializeToString()
  buf = bytes(header) + __encode_varint32(len(payload)) + payload
  n = len(buf)
  total = 0
  while total < n:
    sent = s.send(buf[total:])
    if sent == 0:
      raise RuntimeError("socket connection broken")
    total += sent


def __recv(s, first=False):
  try:
    readable, _, _ = select.select([s,], [], [], READ_TIMEOUT_SECS)
    if len(readable) == 0:
      __log.debug("Select read timeout")
      return None
  except select.error:
    __log.debug("Select error")
    return None
  if first:
    version, tag = struct.unpack("BB", __read(s, 2))
    __log.debug("version {}".format(version))
    if version < MCS_VERSION and version != 38:
      raise RuntimeError("protocol version {} unsupported".format(version))
  else:
    tag, = struct.unpack("B", __read(s, 1))
  size = __read_varint32(s)
  __log.debug("Received message with tag {} ({}), size {}".format(tag, PACKET_BY_TAG[tag], size))
  if size >= 0:
    buf = __read(s, size)
    Packet = PACKET_BY_TAG[tag]
    payload = Packet()
    payload.ParseFromString(buf)
    __log.debug(f'Receive payload:\n{payload}')
    return payload
  return None


def __app_data_by_key(p, key, blow_shit_up=True):
  for x in p.app_data:
    if x.key == key:
      return x.value
  if blow_shit_up:
    raise RuntimeError("couldn't find in app_data {}".format(key))
  return None


def __open():
  import socket
  import ssl
  HOST = "mtalk.google.com"
  context = ssl.create_default_context()
  sock = socket.create_connection((HOST, 5228))
  s = context.wrap_socket(sock, server_hostname=HOST)
  __log.debug("connected to ssl socket")
  return s


def __login(credentials, persistent_ids):
  s = __open()
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
  __log.info(f'Received login response:\n{login_response}')
  return s


last_reset = 0
def __reset(s, credentials, persistent_ids):
  global last_reset
  now = time.time()
  if (now - last_reset < MIN_RESET_INTERVAL_SECS):
    raise Exception("Too many connection reset attempts.")
  last_reset = now
  __log.debug("Reestablishing connection")
  try:
    s.shutdown(2)
    s.close()
  except OSError as e:
    __log.debug(f"Unable to close connection {e}")  
  return __login(credentials, persistent_ids)


def __handle_data_message(p, credentials, callback, obj):
  import http_ece
  import cryptography.hazmat.primitives.serialization as serialization
  from cryptography.hazmat.backends import default_backend
  load_der_private_key = serialization.load_der_private_key

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
  __log.info(f'Received data message {p.persistent_id}: {decrypted}')
  callback(obj, json.loads(decrypted.decode("utf-8")), p)
  return p.persistent_id


def __handle_ping(s, p):
  __log.debug(f'Responding to ping: Stream ID: {p.stream_id}, Last: {p.last_stream_id_received}, Status: {p.status}')
  req = HeartbeatAck()
  req.stream_id = p.stream_id + 1
  req.last_stream_id_received = p.stream_id
  req.status = p.status
  __send(s, req)


def checkin_on_schedule(credentials):
  global checkin_thread
  gcm_check_in(**credentials["gcm"])
  checkin_thread = threading.Timer(CHECKIN_INTERVAL_SECS, checkin_on_schedule, [credentials])
  checkin_thread.start()


def listen(credentials, callback, received_persistent_ids=[], obj=None):
  """
  listens for push notifications

  credentials: credentials object returned by register()
  callback(obj, notification, data_message): called on notifications
  received_persistent_ids: any persistent id's you already received.
                           array of strings
  obj: optional arbitrary value passed to callback
  """
  s = __login(credentials, received_persistent_ids)
  checkin_on_schedule(credentials)  
  while True:
    try:
      p = __recv(s)
      if type(p) is DataMessageStanza:
        id = __handle_data_message(p, credentials, callback, obj)
        received_persistent_ids.append(id)
      elif type(p) is HeartbeatPing:
        __handle_ping(s, p)
      elif p == None or type(p) is Close:
        s = __reset(s, credentials, received_persistent_ids)
      else:
        __log.debug(f'Unexpected message type {type(p)}.')
    except ConnectionResetError:
      __log.debug("Connection Reset: Reconnecting")
      s = __login(credentials, received_persistent_ids)


def shutdown():
  checkin_thread.cancel()
