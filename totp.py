
'''
The MIT License (MIT)
Copyright (c) 2015 Michael Peters
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
import string
import requests

from binascii import unhexlify

STEAM_CHAR_INTEGERS = [str(x) for x in range(2, 10)]
STEAM_CHAR_LETTERS = [x for x in string.letters[1:26]]

STEAM_CHARS = STEAM_CHAR_INTEGERS + STEAM_CHAR_LETTERS
SYNC_URL = 'https://api.steampowered.com:443/ITwoFactorService/QueryTime/v0001'


class SteamTOTP:
    def __init__(self, shared=False, identity=False):
        self.secrets = {}

        if shared:
            self.secrets['sharedSecret'] = shared

        if identity:
            self.secrets['identitySecret'] = identity

    def generateLoginToken(self, secret=False):
        if not secret or 'identitySecret' not in self.secrets:
            raise Exception(
                'Could not generate login token without identitySecret'
            )

        secret = secret or self.secrets.get('identitySecret')

        toLong = lambda x: long(x.encode('hex'), 16)
        local = lambda: long(
            round(time.mktime(time.localtime(time.time())) * 1000)
        )
        timediff = local() - (long(self.getServerTime()) * 1000)
        codeinterval = lambda: long((local() + timediff) / 30000)

        v = self.long_to_bytes(codeinterval())
        h = hmac.new(base64.b64decode(secret), v, hashlib.sha1)
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

    def generateConfirmationToken(self, time, tag, secret=False):
        if not secret or 'sharedSecret' not in self.secrets:
            raise Exception(
                'Could not generate confirmation token without sharedSecret'
            )

        secret = secret or self.secrets.get('sharedSecret')
        v = self.long_to_bytes(long(time))

        if tag:
            v += tag

        h = hmac.new(base64.b64decode(secret), v, hashlib.sha1)

        return h.digest().encode('base64')

    def long_to_bytes(self, val, endianness='big'):
        width = 64

        fmt = '%%0%dx' % (width // 4)

        s = unhexlify(fmt % val)

        if (endianness == 'little'):
            s = s[::-1]

        return s

    def getServerTime(self):
        resp = requests.post(SYNC_URL)

        return resp.json().get('response').get('server_time')
