#!/usr/bin/python
# -*- coding: utf-8 -*
'''
The MIT License (MIT)
Copyright (c) 2016 Philipp Joos
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
'''

'''
Base code by https://github.com/Elipzer/
(https://github.com/Elipzer/SteamAuthenticatorPython/)
'''

import hmac
import time
import base64
import hashlib
import requests

from binascii import unhexlify

STEAM_CHARS = [
    '2', '3', '4', '5', '6', '7', '8', '9', 'B',
    'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'N',
    'P', 'Q', 'R', 'T', 'V', 'W', 'X', 'Y'
]

SYNC_URL = 'https://api.steampowered.com:443/ITwoFactorService/QueryTime/v0001'


class SteamTOTP:
    def __init__(self, secret=False, identity_secret=False, deviceID=False, steamID=False):
        self.secrets    = {}
        self.deviceID   = False
        self.steamID    = False

        if secret:
            self.secrets['secret']          = secret

        if identity_secret:
            self.secrets['identitySecret']  = identity_secret
            
        if deviceID:
            self.deviceID                   = deviceID

        if steamID:
            self.steamID                    = steamID64
            
            
    @property
    def serverTime(self):
        try:
            resp = requests.post(SYNC_URL)
        except Exception, e:
            raise ServerTimeError('Could not retrieve steam server time - %s' % e)
        return resp.json().get('response').get('server_time')

    def generateLoginToken(self, secret=None):
        if not secret and 'secret' not in self.secrets.keys():
            raise SecretMissing(
                'Could not generate login token without secret'
            )

        secret = secret or self.secrets.get('secret')

        toLong = lambda x: long(x.encode('hex'), 16)
        local = lambda: long(
            round(time.mktime(time.localtime(time.time())) * 1000)
        )
        timediff = local() - (long(self.serverTime) * 1000)
        codeinterval = lambda: long((local() + timediff) / 30000)

        v = self.long_to_bytes(codeinterval())
        try:
            h = hmac.new(base64.b64decode(secret), v, hashlib.sha1)
        except TypeError, e:
            raise PaddingError('%s - Please check your secret' % str(e))

        digest = h.digest()

        start = toLong(digest[19]) & 0x0f
        b = digest[start:start + 4]

        fullcode = toLong(b) & 0x7fffffff
        CODE_LENGTH = 5

        code = ''

        for i in range(CODE_LENGTH):
            code += STEAM_CHARS[fullcode % len(STEAM_CHARS)]
            fullcode /= len(STEAM_CHARS)

        return code

    def generateConfirmationToken(self, tag, time=None, identity_secret=None):
        if not identity_secret and 'identitySecret' not in self.secrets.keys():
            raise IdentitySecretMissing(
                'Could not generate confirmation token without identitySecret'
            )

        time = time or self.serverTime
    
        identity_secret = identity_secret or self.secrets.get('identitySecret')
        v = self.long_to_bytes(long(time))

        if tag:
            v += tag

        try:
            h = hmac.new(base64.b64decode(identity_secret), v, hashlib.sha1)
        except TypeError, e:
            raise PaddingError('%s - Please check your identitySecret' % str(e))

        return h.digest().encode('base64')

    def long_to_bytes(self, val, endianness='big'):
        width = 64

        fmt = '%%0%dx' % (width // 4)

        s = unhexlify(fmt % val)

        if (endianness == 'little'):
            s = s[::-1]

        return s

    def getDeviceID(self, steamID=False):
        return self.deviceID or self.generateDeviceID()

    def generateDeviceID(self, steamID=False, prefix='android'):
        if not steamID:
            if self.steamID:
                steamID = self.steamID
            else:
                raise SteamIDMissing('Could not generate device id without steamID')

        hashed = hashlib.sha1()
        hashed.update(str(steamID))
        digest = hashed.hexdigest()[:32]

        deviceID = u''
        deviceID += prefix
        deviceID += ':'
        deviceID += digest[0:8]
        deviceID += '-'
        deviceID += digest[9:13]
        deviceID += '-'
        deviceID += digest[14:18]
        deviceID += '-'
        deviceID += digest[19:23]
        deviceID += '-'
        deviceID += digest[24:]

        return deviceID

class SteamTOTPException(Exception):
    pass

class SteamIDMissing(SteamTOTPException):
    pass

class IdentitySecretMissing(SteamTOTPException):
    pass

class SecretMissing(SteamTOTPException):
    pass

class PaddingError(SteamTOTPException):
    pass

class ServerTimeError(SteamTOTPException):
    pass
