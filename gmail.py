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
from googleapiclient.discovery import build

dir_path = os.path.dirname(abspath(getsourcefile(lambda:0)))
sys.path.insert(0, dir_path)

def __get_service__(user_details: dict):
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    credentials_filepath = os.path.join(
            os.path.dirname(__file__), '../configs', 'credentials.json')

    logging.debug("user_details: %s", user_details)
    creds = Credentials.from_authorized_user_info(
            user_details["token"], user_details["token"]["scope"])

    if not creds or not creds.valid:

        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())

    service = build('gmail', 'v1', credentials=creds)
    return service


def __create_message__(
        sender_email: str, 
        to: str, 
        subject: str, 
        body: str, 
        sender_name=None) -> dict:
    """
    """
    message = MIMEText(body)
    message['to'] = to

    if sender_name is None:
        message['from'] = sender
    else:
        message['from'] = f"{sender_name} <{sender_email}>"

    message['subject'] = subject
    return {'raw' : base64.urlsafe_b64encode(message.as_string().encode('utf-8'))}

def send(
        sender_email: str, 
        to: str, 
        subject: str, 
        body: str, 
        sender_name: str, 
        service) -> None:
    """
    """
    message = __create_message__(
            sender_email=sender_email, 
            to=to, 
            subject=subject, 
            body=body, 
            sender_name=sender_name)

    logging.debug(message)

    message['raw'] = message['raw'].decode('utf-8')

    try:
        user_id = "me"
        message = (
                service.
                users().
                messages().
                send(userId=user_id, body=message).execute())

    except Exception as error:
        raise error

def parse_input(body: str) -> tuple:
    """
    """
    body = body.split(':')

    to=body[0]
    cc=body[1]
    bcc=body[2]
    subject=body[3]
    body = ":".join(body[4:])


    return to, cc, bcc, subject, body


def execute(body: str, user_details: dict) -> None:
    """
    {to}:{cc}:{bcc}:{subject}:{<message body>}
    """

    to, cc, bcc, subject, body = parse_input(body=body)
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

        try:
            user_details["token"]["client_id"] = client_id

            user_details["token"]["client_secret"] = client_secret

            user_details["token"]["scope"] = \
                    user_details["token"]["scope"].replace("openid ", '')

            user_details["token"]["scope"] = \
                    user_details["token"]["scope"].split(' ')

            user_tokens = user_details["token"]
            user_token_scopes = user_details["token"]["scope"]

            sender_email = user_details["uniqueId"]
            sender_name = user_details["username"]

            service = __get_service__(user_details)
            send(
                    sender_email = sender_email, 
                    to = to, 
                    subject = subject, 
                    body = body, 
                    sender_name = sender_name, 
                    service = service)

        except Exception as error:
            raise error
        else:
            logging.debug("Email sent successfully")

    finally:
        creds_fd.close()


