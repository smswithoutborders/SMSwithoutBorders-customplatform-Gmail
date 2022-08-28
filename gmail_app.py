import logging
logger = logging.getLogger(__name__)

import requests
import json
import os

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

credentials_filepath = os.path.join(os.path.dirname(__file__), 'configs', 'credentials.json')

if not os.path.exists(credentials_filepath):
    error = "credentials.json file not found at %s" % credentials_filepath
    raise FileNotFoundError(error)

class Gmail:
    def __init__(self, originalUrl:str) -> None:
        """
        """
        self.credentials_filepath = credentials_filepath
        self.scopes = [
            'openid',
            'https://www.googleapis.com/auth/gmail.send',
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email'
        ]
        self.originalUrl=originalUrl
        self.gmail=Flow.from_client_secrets_file(
                self.credentials_filepath,
                scopes = self.scopes,
                redirect_uri = f'{originalUrl}/platforms/gmail/protocols/oauth2/redirect_codes/'
            )

    def init(self) -> str:
        """
        """
        try:
            auth_uri = self.gmail.authorization_url()

            logger.info("- Successfully fetched init url")

            return {"url":auth_uri[0]}

        except HttpError as error:
            logger.error('Google-client lib error at init. See logs below')
            raise error

        except Exception as error:
            logger.error('Gmail-OAuth2-init failed. See logs below')
            raise error

    def validate(self, code: str) -> dict:
        """
        """
        try:
            self.gmail.fetch_token(code=code)
            credentials = self.gmail.credentials

            user_info_service = build('oauth2', 'v2', credentials=credentials)
            user_info = user_info_service.userinfo().get().execute()

            logger.info("- Successfully fetched token and profile")

            return {
                "profile": user_info,
                "token": credentials.to_json()
            }

        except HttpError as error:
            logger.error('Google-client lib error at validate. See logs below')
            raise error

        except Exception as error:
            logger.error('Gmail-OAuth2-validate failed. See logs below')
            raise error

    def revoke(self, token: dict) -> None:
        """
        """
        try:
            try:
                creds_fd = open(credentials_filepath)
                credentials = json.load( creds_fd )
                client_id = credentials["web"]["client_id"]
                client_secret = credentials["web"]["client_secret"]

            except Exception as error:
                logger.error("Error loading credentials file")
                raise error

            else: 
                if not "client_id" in token:
                    token["client_id"] = client_id
                
                if not "client_secret" in token:
                    token["client_secret"] = client_secret
                
                if not "scopes" in token:
                    token["scopes"] = token["scope"].split(' ')

                grant = Credentials.from_authorized_user_info(token, self.scopes)

                if not grant or not grant.valid:
                    if grant and grant.expired and grant.refresh_token:
                        grant.refresh(Request())
                
                revoke = requests.post('https://oauth2.googleapis.com/revoke', params={'token': grant.token}, headers = {'content-type': 'application/x-www-form-urlencoded'})

                status_code = getattr(revoke, 'status_code')
                if status_code == 200:
                    logger.info("- Successfully revoked access")

                    return True
                else:
                    raise Exception(getattr(revoke, 'reason'))

        except HttpError as error:
            logger.error('Google-client lib error at revoke. See logs below')
            raise error

        except Exception as error:
            logger.error('Gmail-OAuth2-revoke failed. See logs below')
            raise error
    