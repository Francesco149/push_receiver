subscribe to GCM/FCM and receive notifications

python implementation of https://github.com/MatthieuLemoine/push-receiver

tested on python 2.7.16, 3.4.10 and 3.7.5

I put this together in a day or so, it's still rough around the edges,
especially the listen part, which I don't really use myself and have just
implemented for fun and only briefly tested

note that for the listening part I had to pull in http-ece which depends
on a full blown native crypto library rather than just oscrypto. it is
an optional dependency so you'll have to install it explicitly by depending
on push_receiver[listen]

usage
============

.. code-block:: sh

    pip install push_receiver[listen,example]


basic usage example that stores and loads credentials and persistent ids
and prints new notifications

you can also run this example with this command (change the sender id)

.. code-block:: sh

    python -m "push_receiver" --sender-id=722915550290


.. code-block:: python

    from push_receiver import register, listen
    import json


    def on_notification(obj, notification, data_message):
      idstr = data_message.persistent_id + "\n"

      # check if we already received the notification
      with open("persistent_ids.txt", "r") as f:
        if idstr in f:
          return

      # new notification, store id so we don't read it again
      with open("persistent_ids.txt", "a") as f:
        f.write(idstr)

      # print notification
      n = notification["notification"]
      text = n["title"]
      if n["body"]:
        text += ": " + n["body"]
      print(text)


    if __name__ == "__main__":
      SENDER_ID = 722915550290  # change this to your sender id

      try:
        # already registered, load previous credentials
        with open("credentials.json", "r") as f:
          credentials = json.load(f)

      except FileNotFoundError:
        # first time, register and store credentials
        credentials = register(sender_id=SENDER_ID)
        with open("credentials.json", "w") as f:
          json.dump(credentials, f)

      print("send notifications to {}".format(credentials["fcm"]["token"]))

      with open("persistent_ids.txt", "a+") as f:
        received_persistent_ids = [x.strip() for x in f]

      listen(credentials, on_notification, received_persistent_ids)
