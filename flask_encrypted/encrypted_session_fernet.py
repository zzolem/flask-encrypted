#!/usr/bin/env python3
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.datastructures import CallbackDict
from flask.sessions import SessionInterface, SessionMixin
from flask import request
from datetime import timedelta
import json, time, base64, zlib
# TODO
# Optimize towards encrypted_session_aesgcm

COMPRESSION_THRESHOLD = 1024
# SESSION_TTL_NAME | name of session key to store TTL in
SESSION_TTL_NAME = 'SESSION_TTL'
# SECRET_KEY | name of crypto key for Fernet
SECRET_KEY = 'SECRET_KEY'

# app.config[SECRET_KEY] | Fernet key | 44 bytes long
# app.config['SESSION_TTL'] | Time where session is valid
SESSION_TTL_DEFAULT = 24 * 60 * 60
# app.config['SESSION_TTL_PERMANENT'] | If False session TTL is renewed every request
SESSION_TTL_PERMANENT_DEFAULT = False
# app.config['SESSION_MAX_AGE_TTL'] | Set max_age in cookie to SESSION_TTL
SESSION_MAX_AGE_TTL_DEFAULT = True
# app.config['PERMANENT_SESSION'] | Set expire on cookie | max_age is ignored if this is set
PERMANENT_SESSION_DEFAULT = False
# app.config['PERMANENT_SESSION_LIFETIME'] | Time til expire on session cookie

class EncryptedSession(CallbackDict, SessionMixin):
    def __init__(self, initial=None):
        def on_update(self):
            self.modified = True
        CallbackDict.__init__(self, initial, on_update)
        self.modified = False
        self.permanent = False # May be dumb

class EncryptedSessionInterface(SessionInterface):
    session_class = EncryptedSession

    def open_session(self, app, request):
        # Get the session cookie
        ciphertext = request.cookies.get(self.get_cookie_name(app))
        if not ciphertext:
            return self.session_class()

        # Get the crypto key
        assert len(app.config[SECRET_KEY]) == 44
        crypto_key = app.config[SECRET_KEY]
        
        # Decrypt
        try:
            f = Fernet(crypto_key)

            # Check if session has expired
            expiration_time = f.extract_timestamp(ciphertext)
            current_time = int(time.time())
            if expiration_time <= current_time:
                return self.session_class()
            
            plaintext = f.decrypt(ciphertext)
            
            # Decompress
            if plaintext[1:2] == b'1': # compressed
                plaintext = zlib.decompress(plaintext[1:])
            elif plaintext[1:2] == b'0':
                plaintext = plaintext[1:]                

            session_dict = json.loads(plaintext)

            # Include time til session expires
            session_dict[SESSION_TTL_NAME] = expiration_time - current_time

            return self.session_class(session_dict)
        except InvalidToken: # Key is wrong or data is malformed
            return self.session_class()

    def save_session(self, app, session, response) -> None:
        name = self.get_cookie_name(app)
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        secure = self.get_cookie_secure(app)
        samesite = self.get_cookie_samesite(app)
        httponly = self.get_cookie_httponly(app)
        if not session:
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
        assert len(app.config[SECRET_KEY]) == 44
        crypto_key = app.config[SECRET_KEY]
        
        plaintext = bytes(json.dumps(dict(session)),'utf-8')
        
        # Compress
        print(f'Save1>>> {plaintext}')
        if len(plaintext) > COMPRESSION_THRESHOLD:
            plaintext = zlib.compress(plaintext)
            plaintext = b'1' + plaintext
        else:
            plaintext = b'0' + plaintext

        print(f'Save2>>> {plaintext}')

        f = Fernet(crypto_key)
        
        # Make expiration time
        current_time = int(time.time())
        session_ttl = self.get_session_ttl(app, session)
        expiration_time = current_time + session_ttl

        # Use timestamp in Fernet to set session expiration
        ciphertext = f.encrypt_at_time(plaintext, current_time=expiration_time)
        ciphertext = ciphertext.decode('utf-8')

        # Set expires time
        expires = self.get_expiration_time(app, session)

        # Set session cookie max_age to ttl
        # By default if both max_age and expires is passed to response.set_cookie, max_age takes presidence 
        max_age_bool: bool = app.config['SESSION_MAX_AGE_TTL'] if app.config.get('SESSION_MAX_AGE_TTL') \
            else SESSION_MAX_AGE_TTL_DEFAULT
        max_age: str = None if expires else session_ttl
        # ^ this line makes expires override max_age
        max_age = max_age if max_age_bool else None
        
        response.set_cookie(
            name,
            ciphertext,
            max_age=max_age,
            expires=expires,
            httponly=httponly,
            domain=domain,
            path=path,
            secure=secure,
            samesite=samesite,
        )

    # Adds universal app.config['PERMANENT_SESSION'] setting
    def get_expiration_time(self, app, session) -> int: 
        if session.permanent or \
                app.config['PERMANENT_SESSION'] if app.config.get('PERMANENT_SESSION') else PERMANENT_SESSION_DEFAULT:
            return int(time.time() + timedelta.total_seconds(app.permanent_session_lifetime))
        return None
    
    def get_session_ttl(self, app, session) -> int:
        session_ttl:int = app.config['SESSION_TTL'] if app.config.get('SESSION_TTL') else SESSION_TTL_DEFAULT
        if app.config['SESSION_TTL_PERMANENT'] if app.config.get('SESSION_TTL_PERMANENT') else SESSION_TTL_PERMANENT_DEFAULT:
            session_ttl = session[SESSION_TTL_NAME] if session.get(SESSION_TTL_NAME) else session_ttl
        return session_ttl