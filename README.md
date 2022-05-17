# Gmail Send

## How to configure for Publisher

Once installed copy your [**credentials.json**](https://console.cloud.google.com/) file to `configs/`


## How to test

Test scripts are found in the dir `test/`.

The test attempts to acquire your token and stores in the path:

`test/token.json`

To run the test, you will need your [**credentials.json**](https://console.cloud.google.com/) which can be downloaded from Google cloud console.

Place the credentials file in the `test/` directory (make sure the file is called credentials.json).

The flow runs on `port 8000`, be sure to have this added to list of redirect origins in your cloud console.

To run the test and acquire the token file only.

```bash
python3 test/main.py --log INFO --mode get-token-only
```

This should begin a flow for the Google OAuth service. 

