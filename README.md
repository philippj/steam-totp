# steam-totp

Generates steam login/confirmation tokens, based on sharedSecret and identitySecret

Example usage
```
from steamtotp import SteamTOTP

code = SteamTOTP(identity=accountDetails['identitySecret']).generateLoginToken()
```

```
from steamtotp import SteamTOTP

totpGen = SteamTOTP()

code = totpGen.generateLoginToken(accountDetails['identitySecret'])

```
