# steam-totp

Generates steam login/confirmation tokens, based on sharedSecret and identitySecret

Example usage
```
from steam-totp import SteamTOTP

code = SteamTOTP(shared=accountDetails['identitySecret']).generateLoginToken()
```

```
from steam-totp import SteamTOTP

totpGen = SteamTOTP()

code = totpGen.generateLoginToken(accountDetails['identitySecret'])

```
