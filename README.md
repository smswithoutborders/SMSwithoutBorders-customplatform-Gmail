##### Requirements
- credentials.json 
_maybe set your app type to TV and or other type to avoid OAuth redirect issues_

# Notes
- Developer needs to activate gmail for their account
> https://console.cloud.google.com/apis/library/
- Then download the needed credentials.json from there
> _On your gmail console: add your email as a test email_

##### How it parses body
```
message_body = subject:recipient:message
```
