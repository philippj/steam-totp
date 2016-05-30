#!/usr/bin/python
# -*- coding: utf-8 -*
'''
The MIT License (MIT)
Copyright (c) 2016 Philipp Joos
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

'''
Base code by https://github.com/Elipzer/ ( https://github.com/Elipzer/SteamAuthenticatorPython/ )
'''
import re
import hmac
import hashlib
import struct
import time
import sys
import base64
import urllib
import urllib2
import json
from datetime import datetime
from binascii import unhexlify


class SteamTOTP:
    def __init__(self, shared=False, identity=False, secret=False, deviceID=False, steamID64=False):
        self.secrets = { }
        self.steamID = False
        self.session = False

        if shared:
            self.secrets['sharedSecret'] = shared

        if identity:
            self.secrets['identitySecret'] = identity

        if secret:
            self.secrets['secret'] = secret

        if deviceID:
            self.secrets['deviceID'] = deviceID

        if steamID64:
            self.steamID = steamID64

    def setSharedSecret(self, shared):
        self.secrets['sharedSecret'] = shared

    def setIdentitySecret(self, identity):
        self.secrets['identitySecret'] = identity

    def setSecret(self, secret):
        self.secrets['secret'] = secret

    def setDeviceID(self, deviceID):
        self.secrets['deviceID'] = deviceID

    def setSteamID(self, steamID64):
        self.steamID = steamID64

    def generateLoginToken(self, secret=False):
        if not secret:
            if 'secret' in self.secrets:
                secret = self.secrets['secret']
            else:
                print 'Error in SteamTOTP.generateLoginToken() - Could not generate login token without secret'
                return False
        try:
            STEAM_CHARS = ['2', '3', '4', '5', '6', '7', '8', '9', 'B','C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q', 'R', 'T', 'V', 'W','X', 'Y']
            toLong = lambda x: long(x.encode('hex'), 16)
            local = lambda:long(round(time.mktime(time.localtime(time.time())) * 1000))
            timediff = local() - (long(self.getServerTime()) * 1000)
            codeinterval = lambda: long((local() + timediff) /  30000)
            v = self.long_to_bytes(codeinterval())
            h = hmac.new(base64.b32decode(secret), v, hashlib.sha1)
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
        except Exception, e:
            print 'Exception in SteamTOTP.generateLoginToken() - %s' % e
            return False

    def generateConfirmationToken(self, tag, time=False, secret = False, includeTime=False):
        if not secret:
            if 'identitySecret' in self.secrets:
                secret = self.secrets['identitySecret']
            else:
                print 'Error in SteamTOTP.generateConfirmationToken() - Could not generate confirmation token without identitySecret'
                return False
                
        if not time:
            time = self.getServerTime()

        v = self.long_to_bytes(long(time))
        if tag:
            v += tag

        h = hmac.new(base64.b64decode(secret), v, hashlib.sha1)
        if not includeTime:
            return h.digest().encode('base64')
        else:
            return [h.digest().encode('base64'), time]
    
    def long_to_bytes(self, val, endianness='big'):
        width = 64

        fmt = '%%0%dx' % (width // 4)

        s = unhexlify(fmt % val)

        if (endianness == 'little'):
            s = s[::-1]

        return s

    def getServerTime(self):
        SYNC_URL = 'https://api.steampowered.com:443/ITwoFactorService/QueryTime/v0001'
        values = {}
        data = urllib.urlencode(values)
        req = urllib2.Request(SYNC_URL, data)
        resp = urllib2.urlopen(req)
        resp_text = resp.read()
        json_resp = json.loads(resp_text)
        return json_resp['response']['server_time']

    def getDeviceID(self, steamID=False):
        if 'deviceID' not in self.secrets:
            return self.generateDeviceID(steamID)
        else:
            return self.secrets['deviceID']

    def generateDeviceID(self, steamID=False, prefix='android'):
        if not steamID:
            if self.steamID:
                steamID = self.steamID
            else:
                print 'Error in SteamTOTP.generateDeviceID() - Could not generate device id without steamID'
                return False

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
