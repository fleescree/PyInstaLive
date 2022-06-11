import datetime
import os.path
import time
import requests
import os
import pickle

from datetime import datetime

from . import logger
from . import globals
from . import api
from .constants import Constants

class Session:
    def _save_session(self):
        with open(self.session_file, "wb") as f:
            pickle.dump(requests.utils.dict_from_cookiejar(self._session.cookies), f)

    def _load_session(self):
        with open(self.session_file, "rb") as f:
            session = requests.Session()
            session.cookies = requests.utils.cookiejar_from_dict(pickle.load(f))
            session.headers.update(self._get_session_headers())
            logger.error(repr(self._get_session_headers()))
            # session.headers.update({'X-CSRFToken': session.cookies.get_dict()['csrftoken']})
            return session

    def _get_session_headers(self):
        headers = Constants.BASE_HEADERS
        user_agent = getattr(globals.args, "user_agent",None) or getattr(globals.config, "user_agent", None) or Constants.BASE_HEADERS["User-Agent"]
        if user_agent:
            headers.update({"User-Agent": user_agent})
        return headers

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session_file = None
        self.session = None
        self.cookies = None
        self.expires_epoch = None

    def authenticate(self, username=None, password=None):
        try:
            login_success = False
            if username and password:
                self.username = username
                self.password = password
                logger.binfo("The default login credentials have been overridden.")
                logger.separator()
            
            self.session_file = os.path.join(os.path.dirname(globals.config.config_path), "{}.dat".format(self.username))

            if not os.path.isfile(self.session_file):
                logger.warn("Could not find existing login session file: {}".format(os.path.basename(self.session_file)))
                logger.separator()
                logger.info("A new login session file will be created upon successful login.")
            
                self.session = requests.Session()
                self.session.headers = self._get_session_headers
                self.session.headers.update({"x-csrftoken": api.get_csrf_token()})

                login_result = api.do_login()
                if login_result.get("authenticated") == True:
                    self._save_session()
                    logger.info("Successfully created a new login session file.")
                    for cookie in list(self.session.cookies):
                        if cookie.name == "csrftoken":
                            self.expires_epoch = cookie.expires
                    login_success = True
                else:
                    logger.separator()
                    if (login_result.get("message") == "checkpoint_required"):
                        logger.error("Could not login: The action was flagged as suspicious by Instagram.")
                        logger.error("Complete the security checkpoint on another device and try again.")
                    else:
                        logger.error("Could not login: Ensure your credentials are correct and try again.")
                    logger.separator()
                    login_success = False
            else:
                logger.info("An existing login session file was found: {}".format(os.path.basename(self.session_file)))
                logger.info("Checking the validity of the saved login session.")

                self.session = self._load_session()
                for cookie in list(self.session.cookies):
                    logger.warn(f"Cookie: {cookie.name}: {cookie.value} - Expiry: {cookie.expires}")
                    if cookie.name == "csrftoken":
                        self.expires_epoch = cookie.expires
                        # logger.warn(f"Cookie csrftoken expiry: {cookie.expires} ---- {cookie}")
                self.expires_epoch = 1660193799
                # if int(self.expires_epoch) <= int(time.time()):
                #     os.remove(self.session_file)
                #     self.session_file = None

                #     logger.warn("The login session file has expired and has been deleted.")
                #     logger.warn("A new login attempt will be made in a few moments.")

                #     time.sleep(2.5)
                #     self.authenticate(username, password)
                #     return
                # else:
                logger.info("Hacking away!!")
                # return False
                login_state = api.get_login_state()
                if login_state.get("entry_data", {}) != {}:
                    if login_state.get("entry_data").get("Challenge", None) != None:
                        logger.separator()
                        logger.error("The login session file is no longer valid.")
                        logger.error("The session was flagged as suspicious by Instagram.")
                        logger.error("Complete the security checkpoint on another device and try again.")
                        logger.separator()
                        login_success = False
                    else:
                        logger.error("The login session file is no longer valid.")
                        logger.error("Unspecified error. Delete the login session file and try again.")
                        logger.separator()
                        login_success = False
                else:
                    login_success = True
            if login_success:
                if self.session.cookies["csrftoken"] != self.session.headers.get("x-csrftoken"):
                    self.session.cookies.set("csrftoken", self.session.headers.get("x-csrftoken"), domain=".instagram.com", expires=self.expires_epoch)
                logger.separator()
                logger.info('Successfully logged in using account: {:s}'.format(str(self.username)))

                expiry_date = datetime.fromtimestamp(self.expires_epoch).strftime('%m-%d-%Y at %I:%M:%S %p')
                logger.info("The login session file will expire on: {:s}".format(expiry_date))

                logger.separator()
                return True
            else:
                return False
        except Exception as e:
            logger.error('Could not login: {:s}'.format(str(e)))
            logger.separator()
            return False
        except KeyboardInterrupt:
            logger.separator()
            logger.binfo('The process was aborted by the user.')
            logger.separator()
            return False