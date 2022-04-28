import os
import json
import logging
from .android_checkin_pb2 import AndroidCheckinProto, ChromeBuildProto
from .checkin_pb2 import AndroidCheckinRequest, AndroidCheckinResponse
from google.protobuf.json_format import MessageToDict
from base64 import urlsafe_b64encode
from oscrypto.asymmetric import generate_pair
try:
  from urllib.request import Request, urlopen
  from urllib.parse import urlencode
except ImportError:
  from urllib2 import Request, urlopen
  from urllib import urlencode
try:
  unicode
except NameError:
  unicode = str
import time


REGISTER_URL = "https://android.clients.google.com/c2dm/register3"
CHECKIN_URL = "https://android.clients.google.com/checkin"
FCM_SUBSCRIBE = 'https://fcm.googleapis.com/fcm/connect/subscribe'
FCM_ENDPOINT = 'https://fcm.googleapis.com/fcm/send'
SERVER_KEY = (
    b"\x04\x33\x94\xf7\xdf\xa1\xeb\xb1\xdc\x03\xa2\x5e\x15\x71\xdb\x48\xd3"
    + b"\x2e\xed\xed\xb2\x34\xdb\xb7\x47\x3a\x0c\x8f\xc4\xcc\xe1\x6f\x3c"
    + b"\x8c\x84\xdf\xab\xb6\x66\x3e\xf2\x0c\xd4\x8b\xfe\xe3\xf9\x76\x2f"
    + b"\x14\x1c\x63\x08\x6a\x6f\x2d\xb1\x1a\x95\xb0\xce\x37\xc0\x9c\x6e"
)

__log = logging.getLogger("push_receiver")

def __do_request(req, retries=5):
  for _ in range(retries):
    try:
      resp = urlopen(req)
      resp_data = resp.read()
      resp.close()
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

  __log.debug(f'GCM check in payload:\n{payload}')
  req = Request(
      url=CHECKIN_URL,
      headers={"Content-Type": "application/x-protobuf"},
      data=payload.SerializeToString()
  )
  resp_data = __do_request(req)
  resp = AndroidCheckinResponse()
  resp.ParseFromString(resp_data)
  __log.debug(f'GCM check in response (raw):\n{resp}')
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
  __log.debug(f'GCM check in response {chk}')
  body = {
      "app": "org.chromium.linux",
      "X-subtype": appId,
      "device": chk["androidId"],
      "sender": urlsafe_base64(SERVER_KEY)
  }
  data = urlencode(body)
  __log.debug(f'GCM Registration request: {data}')
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
      time.sleep(1)
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
  __log.debug(f"# public: {b64encode(public.asn1.dump())}")
  __log.debug(f"# private: {b64encode(private.asn1.dump())}")
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
  __log.debug(f'FCM registration data: {data}')
  req = Request(url=FCM_SUBSCRIBE, data=data.encode("utf-8"))
  resp_data = __do_request(req, retries)
  return {"keys": keys, "fcm": json.loads(resp_data.decode("utf-8"))}


def register(sender_id, app_id):
  """register gcm and fcm tokens for sender_id"""
  subscription = gcm_register(appId=app_id)
  if (subscription == None):
    raise Error("Unable to establish subscription with Google Cloud Messaging.")
  __log.debug(f'GCM subscription: {subscription}')
  fcm = fcm_register(sender_id=sender_id, token=subscription["token"])
  __log.debug(f'FCM registration: {fcm}')
  res = {"gcm": subscription}
  res.update(fcm)
  __log.debug(f"Credential: {credentials}")
  return res
