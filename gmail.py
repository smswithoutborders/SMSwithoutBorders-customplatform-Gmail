import os
import sys

import base64
import json
import logging

from inspect import getsourcefile
from os.path import abspath

from email.mime.text import MIMEText as MIMEText
from googleapiclient.discovery import build

from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request 
from google.oauth2.credentials import Credentials 

dir_path = os.path.dirname(abspath(getsourcefile(lambda:0)))
sys.path.insert(0, dir_path)

import quickstart as googleAuths
# print("GMAIL")

def create_message(sender, to, subject, message_text, sender_name=None):
    message = MIMEText(message_text)
    message['to'] = to

    if sender_name is None:
        message['from'] = sender
    else:
        message['from'] = f"{sender_name} <{sender}>"

    message['subject'] = subject
    print(message)
    return {'raw' : base64.urlsafe_b64encode(message.as_string().encode('utf-8'))}

def send(sender, to, subject, message_text, sender_name, user_details):
    print(">> sending email....")
    try:
        if user_details is not None:
            service = googleAuths.main(user_details)
        else:
            # service = googleAuths.main()
            print("[-] No user credentials for gmail available")
            raise Exception("Missing user credentials to send...")
    except Exception as error:
        raise Exception(error)
    else:
        message = create_message(sender, to, subject, message_text, sender_name)
        message['raw'] = message['raw'].decode('utf-8')

        print(">> Gmail Send Service...")
        print(message)
        print(service)

        try:
            user_id = "me"
            message = (service.users().messages().send(userId=user_id, body=message).execute())
            print(message)

        except Exception as error:
            print(f">> An error occured: {error}")
            raise Exception(error)

def execute(body: str, user_details: dict) -> None:
    """
    {to}:{cc}:{bcc}:{subject}:{<message body>}
    """

    body = body.split(':')
    to=body[0]
    cc=body[1]
    bcc=body[2]
    subject=body[3]
    message = ":".join(body[4:])


    logging.debug("to: %s", to)
    logging.debug("cc: %s", cc)
    logging.debug("bcc: %s", bcc)
    logging.debug("subject: %s", subject)
    logging.debug("message: %s", message)

    client_id=None
    client_secret=None

    credentials_filepath = os.path.join(os.path.dirname(__file__), 'configs', 'credentials.json')
    try:
        creds_fd = open(credentials_filepath)
        credentials = json.load( creds_fd )
        client_id = credentials["web"]["client_id"]
        client_secret = credentials["web"]["client_secret"]

    except Exception as error:
        raise error

    else:
        logging.debug("client id: %s", client_id)
        logging.debug("client secret: %s", client_secret)
    finally:
        creds_fd.close()

    """

    sender = user_details["username"]
    user_details["token"]["client_id"] = client_id
    user_details["token"]["client_secret"] = client_secret

    user_details["token"]["scope"] = user_details["token"]["scope"].replace("openid ", '');
    user_details["token"]["scope"] = user_details["token"]["scope"].split(' ')

    try:
        send(sender=sender, to=to, subject=subject, message_text=message_text, sender_name=name, user_details=user_details)
    except Exception as error:
        raise Exception(error)
    else:
        return True
    """

if __name__ == '__main__':
    sender_name = input(">> Your name:")
    sender = input(">> Sender email address:")
    to = input(">> Receipient email address:")
    subject = input(">> Email subject:")
    message_text=input("[+] Message:")

    send(sender, to, subject, message_text, sender_name)
