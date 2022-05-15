#!/usr/bin/env python3


import test.gmail_authentication as gmail_auth
import logging


if __name__ == "__main__":

    """
    - Acquires and stores token if not present
    - Use token to send out email
    """


    if os.path.exists(token_path):
        gmail_auth.main()
