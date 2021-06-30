"""Dyson Pure Cool Link library."""

# pylint: disable=too-many-public-methods,too-many-instance-attributes

import logging

import requests
from requests.auth import HTTPBasicAuth

import urllib3
import datetime

from .dyson_pure_cool import DysonPureCool
from .dyson_pure_hotcool import DysonPureHotCool
from .utils import is_360_eye_device, \
    is_heating_device, is_dyson_pure_cool_device, \
    is_heating_device_v2, is_dyson_pure_humidifycool_device
from .dyson_pure_humidifycool import DysonPureHumidifyCool

from .dyson_360_eye import Dyson360Eye
from .dyson_pure_cool_link import DysonPureCoolLink
from .dyson_pure_hotcool_link import DysonPureHotCoolLink
from .exceptions import DysonNotLoggedException

_LOGGER = logging.getLogger(__name__)

DYSON_API_URL = "appapi.cp.dyson.com"
DYSON_API_URL_CN = "appapi.cp.dyson.cn"
DYSON_API_USER_AGENT = "android client"

import json
import appdirs
import os

class DysonAccount:
    """Dyson account."""

    def __init__(self, email, password, country):
        """Create a new Dyson account.

        :param email: User email
        :param password: User password
        :param country: 2 characters language code
        """
        self._email = email
        self._password = password
        self._country = country
        self._logged = False
        self._auth = None
        self._headers = {
            'User-Agent': DYSON_API_USER_AGENT
        }
        self._authNextTime = None
        if country == "CN":
            self._dyson_api_url = DYSON_API_URL_CN
        else:
            self._dyson_api_url = DYSON_API_URL
        self._wait2faStart = False
        self._wait2faVerify = False
        self.loadCache()

    def writeCache(self):
        p = appdirs.user_cache_dir("libpurecool")
        if os.path.isdir(p) == False:
            os.makedirs(p)
        with open(p + '/cachev3.json', 'w') as jf:
            _LOGGER.info('Writing cache: %s' % self._cache)
            json.dump(self._cache, jf)

    def loadCache(self):
        p = appdirs.user_cache_dir("libpurecool")
        if os.path.isdir(p) == False or os.path.isfile(p + '/cachev3.json') == False:
            self._cache = {}
        else:
            _LOGGER.info('reading cache from: %s' % p)
            with open(p + '/cachev3.json') as jf:
                self._cache = json.load(jf)

    def pre_login(self):
        forceQry = False
        _LOGGER.info('pre_login')
        if "pre_login_next_run" in self._cache:
            if datetime.datetime.now() > datetime.datetime.fromisoformat(self._cache["pre_login_next_run"]):
                _LOGGER.info('we should pre_login')
                #del self._cache['pre_login_next_run']
                #del self._cache['pre_login']
                #self.writeCache()
                forceQry = True
        if "pre_login" not in self._cache or forceQry:
            pre_login = requests.post(
                "https://{0}/v3/userregistration/email/userstatus?country={1}".format(
                    self._dyson_api_url, self._country),
                headers=self._headers,
                json={'email': self._email},
                verify=False
            )
            _LOGGER.info("pre_login return code: %d, text: %s" % (pre_login.status_code, pre_login.text))
            if pre_login.status_code == requests.codes.ok:
                self._cache["pre_login"] = pre_login.json()
                self._cache["pre_login_next_run"] = (datetime.datetime.now() + datetime.timedelta(hours=24)).isoformat()
                self.writeCache()
            elif 'Retry-After' in pre_login.headers:
                self._authNextTime = datetime.datetime.now() + datetime.timedelta(seconds=int(pre_login.headers['Retry-After']))
        else:
            _LOGGER.info('pre_login using cache')
        if "pre_login" in self._cache and 'accountStatus' in self._cache['pre_login'] and self._cache['pre_login']['accountStatus'] == 'ACTIVE':
            _LOGGER.info('pre_login data are available in cache, we are connected...')
            return True
        return False

    def authenticate(self):
        _LOGGER.info('authenticate')
        if "authenticate" not in self._cache:
            uri = "https://{0}/v3/userregistration/email/auth".format(self._dyson_api_url)
            login = requests.post(
                uri,
                headers=self._headers,
                params={'country': self._country, 'culture': 'en-US'},
                json={ 'email': self._email },
                verify=False
            )
            _LOGGER.info("authenticate return code: %d, text: %s" % (login.status_code, login.text))
            if login.status_code == requests.codes.ok:
                self._cache["authenticate"] = login.json()
                self._cache["authenticate_next_run"] = (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat()
                self.writeCache()
                self._wait2faStart = False
                self._wait2faVerify = True
            elif 'Retry-After' in login.headers:
                self._authNextTime = datetime.datetime.now() + datetime.timedelta(seconds=int(login.headers['Retry-After']))
        else:
            _LOGGER.info('authenticate using cache')
        if 'authenticate' in self._cache and 'challengeId' in self._cache['authenticate']:
            return True
        return False

    def verify(self, token):
        if "verify" not in self._cache:
            verify = requests.post(
                "https://{0}/v3/userregistration/email/verify".format(
                    self._dyson_api_url),
                headers=self._headers,
                params={'country': self._country},
                json={ 'email': self._email, 'password': self._password,
                       'challengeId': self._cache['authenticate']['challengeId'],
                       'otpCode': token
                },
                verify=False
            )
            _LOGGER.info("verify return code: %d, text: %s" % (verify.status_code, verify.text))
            if verify.status_code == requests.codes.ok:
                self._cache["verify"] = verify.json()
                self.writeCache()
                self._wait2faStart = False
            elif 'Retry-After' in verify.headers:
                self._authNextTime = datetime.datetime.now() + datetime.timedelta(seconds=int(verify.headers['Retry-After']))
            else:
                del self._cache['authenticate'] # If we fail here, it means our challenge is bad, thus we need to re-run the query
                del self._cache['pre_login']
        else:
            _LOGGER.info('verify using cache')
        if 'verify' in self._cache and 'account' in self._cache['verify'] and 'token' in self._cache['verify'] and 'tokenType' in self._cache['verify']:
            self._logged = True
            return True
        return False

    def prune(self):
        self._cache = {}
        self.writeCache()

    def login(self):
        self._logged = False
        self._wait2faStart = False
        self._wait2faVerify = False
        if self._authNextTime != None and self._authNextTime > datetime.datetime.now():
            _LOGGER.info("Could not identify for the moment, next authent will be made at: %s" % (self._authNextTime))
        else:
            """Login to dyson web services."""
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            _LOGGER.info("Disabling insecure request warnings since "
                  "dyson are using a self signed certificate.")
            if self.pre_login():
                if "authenticate" not in self._cache or \
                   ('verify' not in self._cache and datetime.datetime.now() > datetime.datetime.fromisoformat(self._cache['authenticate_next_run'])):
                    _LOGGER.info('Waiting for 2fa')
                    self._wait2faStart = True
                elif 'authenticate' in self._cache and 'verify' not in self._cache:
                    self._wait2faVerify = True
                elif 'verify' in self._cache and 'account' in self._cache['verify'] and 'token' in self._cache['verify'] and 'tokenType' in self._cache['verify']:
                    self._logged = True
            else:
                _LOGGER.info('pre_login ko')
        _LOGGER.info("Return %d" % self._logged)
        return self._logged

    def getDevices(self, version):
        key = 'devicesv%d' % version
        headers = self._headers.copy()
        headers['Authorization'] = '%s %s' % (self._cache['verify']['tokenType'], self._cache['verify']['token'])
        if key not in self._cache:
            device_response = requests.get(
                "https://{0}/v{1}/provisioningservice/manifest".format(
                    self._dyson_api_url, version),
                headers=headers,
                verify=False,
                auth=self._auth)
            _LOGGER.info("get devicesv%d return code: %d, text: %s" % (version, device_response.status_code, device_response.text))
            if device_response.status_code == requests.codes.ok:
                self._cache[key] = device_response.json()
                self.writeCache()
            elif device_response.status_code == requests.codes.unauthorized:
                del self._cache['authenticate']
                del self._cache['verify']
                self.writeCache()
                self._logged = False
        else:
            _LOGGER.info('get_device %d using cache' % version)
        return self._logged

    def devices(self):
        """Return all devices linked to the account."""
        if self._logged:
            devices = []
            if self.getDevices(1) and self.getDevices(2):
                for device in self._cache['devicesv1']:
                    if is_360_eye_device(device):
                        dyson_device = Dyson360Eye(device)
                    elif is_heating_device(device):
                        dyson_device = DysonPureHotCoolLink(device)
                    else:
                        dyson_device = DysonPureCoolLink(device)
                    devices.append(dyson_device)

                for device_v2 in self._cache['devicesv2']:
                    if is_dyson_pure_humidifycool_device(device_v2):
                        devices.append(DysonPureHumidifyCool(device_v2))
                    elif is_dyson_pure_cool_device(device_v2):
                        devices.append(DysonPureCool(device_v2))
                    elif is_heating_device_v2(device_v2):
                        devices.append(DysonPureHotCool(device_v2))
            return devices

        _LOGGER.warning("Not logged to Dyson Web Services.")
        raise DysonNotLoggedException()

    def nukeDeviceCache(self):
        if 'devicesv1' in self._cache:
            del self._cache['devicesv1']
        if 'devicesv2' in self._cache:
            del self._cache['devicesv2']
        self.writeCache()

    @property
    def logged(self):
        """Return True if user is logged, else False."""
        return self._logged

    @property
    def wait_2fa_start(self):
        return self._wait2faStart

    @property
    def wait_2fa_verify(self):
        return self._wait2faVerify
