import os.path
import base64
import json

from email.mime.text import MIMEText as MIMEText
from googleapiclient.discovery import build

from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials


from . import quickstart as googleAuths
print("GMAIL")

def create_message(sender, to, subject, message_text, sender_name=None):
    message = MIMEText(message_text)
    message['to'] = to

    if sender is None:
        message['from'] = sender_name
    elif sender_name is None:
        message['from'] = sender
    else:
        message['from'] = f"{sender_name} <{sender}>"

    message['subject'] = subject
    print(message)
    return {'raw' : base64.urlsafe_b64encode(message.as_string().encode('utf-8'))}

def send(sender, to, subject, message_text, sender_name, userDetails):
    try:
        if userDetails is not None:
            service = googleAuths.main(userDetails)
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

def execute(protocol, body, userDetails):
    print("[+] Executing gmail:google...")
    print(f"[+] Gmail about to send email: {protocol}:{body}:{userDetails}")
    split_body = body.split(':')
    subject=split_body[0]
    to=split_body[1]
    message_text = ":".join(split_body[2:])

    # TODO: Using this as a todo, but should change the contents to be more dynamic
    # userDetails["token_path"] = "Platforms/google/token.json"
    # userDetails["credentials_path"] = "Platforms/google/credentials.json"

    print(f"\tsubject: {subject}\n\tto: {to}\n\tmessage_text: {message_text}")

    client_id=None
    client_secret=None
    with open("Platforms/google/credentials.json") as creds:
        creds = json.load( creds )
        for key in creds.keys():
            if "client_id" in creds[key] and "client_secret" in creds[key]:
                client_id = creds[key]["client_id"]
                client_secret = creds[key]["client_secret"]
                break
    userDetails["token"]["client_id"] = client_id
    userDetails["token"]["client_secret"] = client_secret

    # TODO: get email address and user and user name from userDetails
    try:
        # send("wisdomnji@gmail.com", to, subject, message_text, "Wisdom Nji", userDetails)
        sender_name = userDetails["profile"]["data"]["name"]
        send(to=to, subject=subject, message_text=message_text, sender_name=sender_name, userDetails=userDetails)
    except Exception as error:
        raise Exception(error)
    else:
        return True

if __name__ == '__main__':
    sender_name = input(">> Your name:")
    sender = input(">> Sender email address:")
    to = input(">> Receipient email address:")
    subject = input(">> Email subject:")
    message_text=input("[+] Message:")

    send(sender, to, subject, message_text, sender_name)
