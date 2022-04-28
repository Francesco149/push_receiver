import appdirs
import argparse
import json
import logging
import sys
import os.path
from .register import register
from .push_receiver import listen

def run_example():
  """sample that registers a token and waits for notifications"""

  parser = argparse.ArgumentParser(description="push_receiver demo")
  parser.add_argument("--app-id")
  parser.add_argument("--sender-id")
  parser.add_argument("--no-listen", action="store_true")
  levels = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
  parser.add_argument("--log", choices=levels)
  args = parser.parse_args(sys.argv[1:])
  logging.basicConfig(level=logging.INFO)
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
    credentials = register(sender_id=int(args.sender_id), app_id=args.app_id)
    with open(credentials_path, "w") as f:
      json.dump(credentials, f)

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
