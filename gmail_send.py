import os.path
import base64

from email.mime.text import MIMEText as MIMEText
from googleapiclient.discovery import build

from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

import quickstart as googleAuths


def create_message(sender, to, subject, message_text, sender_name=None):
    message = MIMEText(message_text)
    message['to'] = to
    if sender_name is not None:
        message['from'] = f"{sender_name} <{sender}>"
    else:
        message['from'] = sender
    message['subject'] = subject
    print(message)
    return {'raw' : base64.urlsafe_b64encode(message.as_string().encode('utf-8'))}

def send(sender, to, subject, message_text, sender_name=None):
    try:
        service = googleAuths.main()
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

if __name__ == '__main__':
    sender_name = input(">> Your name:")
    sender = input(">> Sender email address:")
    to = input(">> Receipient email address:")
    subject = input(">> Email subject:")
    message_text=input("[+] Message:")

    send(sender, to, subject, message_text, sender_name)
