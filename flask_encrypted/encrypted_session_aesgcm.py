#!/usr/bin/env python3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from werkzeug.datastructures import CallbackDict
from flask.sessions import SessionInterface, SessionMixin, MutableMapping
from flask import request
from datetime import timedelta
from base64 import b64decode as bdecode
from base64 import b64encode as bencode
from base64 import binascii # Catch malformed encoding
import os, time, zlib
from msgpack import dumps, loads
# TODO: make json take binary data or find alternative
"""
try:
    from msgpack import dumps, loads
except ImportError:
    from json import dumps, loads # JSON can not hold binary data
"""
# SESSION_REFRESH_EACH_REQUEST 
#    Control whether the cookie is sent with every response when session.permanent is true. Sending the cookie every time (the default) can more reliably keep the session from expiring, but uses more bandwidth. Non-permanent sessions are not affected.
#    Default: True


SESSION_DELIMITER= '-'
COMPRESSION_THRESHOLD = 768
SECRET_KEY_BYTE_LEN = 16
SESSION_TTL_DEFAULT = 24 * 60 * 60
SESSION_MAX_AGE_TTL_DEFAULT = True

# SESSION_TTL_NAME | name of session key to store TTL
SESSION_TTL_NAME = '_ttl'
# SECRET_KEY | name of crypto key in app.config
SECRET_KEY = 'SECRET_KEY'

"""
app.config[SECRET_KEY] = b'' | AES-GCM key | 16 bytes long
app.config['SESSION_TTL'] = int | TTL for session
app.config['SESSION_MAX_AGE_TTL'] = True | set max_age in session cookie to SESSION_TTL
app.config['SESSION_TTL_RESET_PER_REQUEST'] = True | TTL counter reset every request | sends new session cookie every request
app.config['PERMANENT_SESSION'] = True | set expire on session cookie | expire takes presidence over max_age
app.config['PERMANENT_SESSION_LIFETIME'] = int|datetime | value of expire flag on session cookie | can be datetime.datetime obj
"""

class EncryptedSession(CallbackDict, SessionMixin):
    def __init__(self, initial=None):
        def on_update(self):
            self.modified = True
        CallbackDict.__init__(self, initial, on_update)
        self.modified = False

class EncryptedSessionInterface(SessionInterface):
    session_class = EncryptedSession
    print("cookie!!!")

    def save_session(self, app, session, response) -> None:
        name = self.get_cookie_name(app)
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        secure = self.get_cookie_secure(app)
        samesite = self.get_cookie_samesite(app)
        httponly = self.get_cookie_httponly(app)
        if not session:
        # NOTE: delete_cookie is same as set_cookie without data and max_age is set to 0
            if session.modified:
                response.delete_cookie(
                    name,
                    domain=domain,
                    path=path,
                    secure=secure,
                    samesite=samesite,
                    httponly=httponly,
                )
            return

        # session.modified is not set
        if not self.should_set_cookie(app, session):
            return

        # Get the crypto key
        assert len(app.config[SECRET_KEY]) == SECRET_KEY_BYTE_LEN
        crypto_key = app.config[SECRET_KEY]
        
        plaintext = dumps(dict(session))
        
        # Compress before encryption
        compress_prefix = 'u'
        if len(plaintext) > COMPRESSION_THRESHOLD:
            plaintext = zlib.compress(plaintext)
            compress_prefix = 'z' 


        c = AESGCM(crypto_key)
        nonce = os.urandom(12) # Recommended by NIST
        # nonce must never be reused
        
        # Make expiration time
        current_time = int(time.time())
        session_ttl = self.get_session_ttl(app, session)
        expiration_time = current_time + session_ttl

        # Encrypt
        """               nounce/iv | plaintext | data to authenticate but not encrypt """
        ciphertext = c.encrypt(nonce, plaintext, (compress_prefix + str(expiration_time)).encode('utf-8'))
         
        #""" # Uncomment this line
        # Create session cookie as <u|z> | <expiration_unix:bytes(integer, unsigned, little-endian)> | <nonce> | <ciphertext>
        expiration_time = expiration_time.to_bytes((expiration_time.bit_length() + 7) // 8, byteorder='little', signed=False)
        session_cookie = [compress_prefix, bencode(expiration_time).decode(), \
            bencode(nonce).decode(), bencode(ciphertext).decode()]
        session_cookie = SESSION_DELIMITER.join(session_cookie)
        """ # 5 byte bigger footprint with msgpack compared to ^
        # Create session cookie with a msgpack formated encoded dict
        session_cookie = dumps([
            compress_prefix,
            expiration_time,
            nonce,
            ciphertext
        ])
        session_cookie = bencode(session_cookie).decode('utf-8')
        #"""

        expires = self.get_expiration_time(app, session)

        # Set session cookie flag max_age to ttl
        # By default if both max_age and expires is passed to response.set_cookie, max_age takes presidence 
        max_age = None if expires else session_ttl # < this line makes expires override max_age
        max_age_bool = SESSION_MAX_AGE_TTL_DEFAULT if app.config.get('SESSION_MAX_AGE_TTL') == None else app.config['SESSION_MAX_AGE_TTL'] 
        max_age = max_age if max_age_bool == True else None
        
        response.set_cookie(
            name,
            session_cookie,
            max_age=max_age,
            expires=expires,
            httponly=httponly,
            domain=domain,
            path=path,
            secure=secure,
            samesite=samesite,
        )

    def open_session(self, app, request) -> session_class:
        # Get session cookie
        session_cookie = request.cookies.get(self.get_cookie_name(app))
        if not session_cookie:
            return self.session_class()

        # Get crypto key
        assert len(app.config[SECRET_KEY]) == SECRET_KEY_BYTE_LEN
        crypto_key = app.config[SECRET_KEY]
        
        try:
            #""" # Uncomment this line
            # Create session cookie as <u|z> | <expiration_unix:bytes(integer, signed, little-endian)> | <nonce> | <ciphertext>
            compress_prefix, expiration_time, nonce, ciphertext = session_cookie.split(SESSION_DELIMITER)

            expiration_time, nonce, ciphertext = expiration_time.encode('utf-8'), nonce.encode('utf-8'), ciphertext.encode('utf-8')
            expiration_time = int.from_bytes((bdecode(expiration_time)), byteorder='little', signed=False)
            nonce, ciphertext = bdecode(nonce), bdecode(ciphertext)
            """ # 5 byte bigger footprint with msgpack compared to ^
            session_cookie = bdecode(session_cookie)
            compress_prefix, expiration_time, nonce, ciphertext = loads(session_cookie)
            #"""
        except (binascii.Error, ValueError): # binascii.Error = malformed base64 | ValueError = not all entries precent
            return self.session_class()

        # Check if session has expired
        current_time = int(time.time())
        if expiration_time <= current_time:
            return self.session_class()

        # Decrypt
        try:
            c = AESGCM(crypto_key)
            """              nounce/iv | ciphertext | data to authenticate but not encrypt """
            plaintext = c.decrypt(nonce, ciphertext, (compress_prefix + str(expiration_time)).encode('utf-8'))
            
            # Decompress
            if compress_prefix == 'z':
                plaintext = zlib.decompress(plaintext)

            session_dict = loads(plaintext)

            # Include session TTL in session dictionary
            session_dict[SESSION_TTL_NAME] = expiration_time - current_time # place last
            #session_dict = {SESSION_TTL_NAME: expiration_time - current_time} | session_dict # place first

            return self.session_class(session_dict)

        except InvalidTag: # Session cookie malformed/changed
            return self.session_class()


    # Adds universal app.config['PERMANENT_SESSION'] setting
    def get_expiration_time(self, app, session) -> int:
        if session.permanent or app.config.get('PERMANENT_SESSION'):
            return int(time.time() + timedelta.total_seconds(app.permanent_session_lifetime))
        return None
    
    def get_session_ttl(self, app, session) -> int:
        session_ttl = SESSION_TTL_DEFAULT if app.config.get('SESSION_TTL') == None else app.config['SESSION_TTL'] 
        if app.config.get('SESSION_TTL_RESET_PER_REQUEST'):
            session.modified == True
            return session_ttl
        return session_ttl if session.get(SESSION_TTL_NAME) == None else session[SESSION_TTL_NAME]
