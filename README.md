# steam-totp

Generates steam login/confirmation tokens, based on sharedSecret and identitySecret

Example usage
```
from totp import SteamTOTP

code = SteamTOTP(identity=accountDetails['identitySecret']).generateLoginToken()
```

```
from totp import SteamTOTP

totpGen = SteamTOTP()

code = totpGen.generateLoginToken(accountDetails['identitySecret'])

```
