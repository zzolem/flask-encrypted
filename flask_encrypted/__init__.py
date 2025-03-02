class Encrypted:
    """
    # NOT YET IN USE
    app.config[SESSION_ENCRYPTION] = str(aesgcm | fernet) | Encryption method
    """
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        # Decide on interface
        # As of now there is only one, aesgcm, but fernet will come
        app.session_interface = self._get_interface(app)
    
    def _get_interface(self, app):
        print("getting interface")
        #config = app.config
    
        #SESSION_ENCRYPTION = app.config['SESSION_ENCRYPTION'].lower()
        SESSION_ENCRYPTION = "aesgcm"
        if SESSION_ENCRYPTION == "aesgcm": # Default 
            from .encrypted_session_aesgcm import EncryptedSessionInterface
            session_interface = EncryptedSessionInterface()
        elif SESSION_ENCRYPTION == "fernet": # Not ready for use
            from .encrypted_session_fernet import EncryptedSessionInterface
            session_interface = EncryptedSessionInterface()
    
        return session_interface

