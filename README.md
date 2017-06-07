# steam-totp



## Main features
- Generating login tokens
- Generating confirmation tokens
- Generating device ids

## Requirements
See requirements.txt
 

## Examples
```
from totp import SteamTOTP

code = SteamTOTP(secret=accountDetails['secret']).generateLoginToken()
```

```
from totp import SteamTOTP

totp = SteamTOTP()

code = totp.generateLoginToken(accountDetails['secret'])
confToken = totp.generateConfirmationToken('conf', identity_secret = accountDetails['identitySecret'])
```


##account.py

account.py has been added due to not being implemented in ValvePython/Steam

From my perspective this class provides good access to everything related to Stream 2FA

