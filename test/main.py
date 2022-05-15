#!/usr/bin/env python3

from __future__ import print_function

import os
import logging
import json
import argparse
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

__scopes = ['https://www.googleapis.com/auth/gmail.send']

logging.basicConfig(level='DEBUG')

def write_token_file(token_filepath: str, creds):
    """ """
    with open(token_filepath, 'w') as token:
        token.write(creds.to_json())


def initiate_and_store_token_file(credentials_filepath: str, 
        token_filepath: str, 
        port: int = 8000) -> None:
    """ """

    flow = InstalledAppFlow.from_client_secrets_file(credentials_filepath, __scopes)

    creds = flow.run_local_server(port=port)

    # Save the credentials for the next run
    write_token_file(token_filepath, creds)


def refresh_token(token_filepath: str):
    """ """
    creds = Credentials.from_authorized_user_file(token_filepath, __scopes)

    if not creds.refresh_token:
        raise Exception("NO_REFRESH_TOKEN")

    creds.refresh(Request())
    write_token_file(token_filepath, creds)


def is_expired(token_filepath: str) -> bool:
    """ """
    creds = Credentials.from_authorized_user_file(token_filepath, __scopes)

    return creds.expired


def is_token_filepath(token_filepath: str) -> bool:
    """Checks if token files are available."""
    return os.path.exists(token_filepath)


def is_valid_credentails(token_filepath: str) -> bool:
    """ """
    creds = Credentials.from_authorized_user_file(token_path, __scopes)

    return creds.valid


def read_user_details(token_filepath: str):
    """Reads the user token file and returns the user details object."""

    user_details = None
    with open(token_filepath, 'r') as token_file_fd:
        user_details = json.load(token_file_fd)

    return user_details

def fetch_token():
    """ """
    token_filepath = os.path.join(
            os.path.dirname(__file__), '', 'token.json')

    logging.debug("[*] Token file: %s", token_filepath)

    credentials_filepath = os.path.join(
            os.path.dirname(__file__), '', 'credentials.json')

    logging.debug("[*] Credentials file: %s", credentials_filepath)

    if (
            not is_token_filepath(token_filepath=token_filepath) 
            or not is_valid_credentials(token_filepath)):

        logging.debug('[*] Is not a valid token')
        initiate_and_store_token_file(
                credentials_filepath=credentials_filepath, 
                token_filepath=token_filepath)

    elif is_expired(token_filepath):

        logging.debug("[*] Token is expired")
        refresh_token(token_filepath)

    user_details = read_user_details(token_filepath)
    return user_details


if __name__ == "__main__":
    """ """
    parser = argparse.ArgumentParser(description='Process some integers.')

    parser.add_argument(
            '-l', '--log',
            default='DEBUG',
            help='--log=[DEBUG, INFO, WARNING, ERROR, CRITICAL]')

    parser.add_argument("-m", "--mode",
            nargs='?',
            default="get-token-only",
            help="get-token-only")

    args = parser.parse_args()
    logging.basicConfig(level=args.log.upper())

    if args.mode == "get-token-only":
        user_details = fetch_token()

        logging.info(user_details)

