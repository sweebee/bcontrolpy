import asyncio
import aiohttp
import json
import logging
from .key_mapping import key_mapping

_LOGGER = logging.getLogger(__name__)

# Eigene Exceptions
class CookieRetrievalError(Exception):
    pass

class LoginValueError(Exception):
    pass

class CookieValueError(Exception):
    pass

class AuthenticationError(Exception):
    """Raised when login fails due to invalid credentials."""
    pass

class NotAuthenticatedError(Exception):
    """Raised when trying to get data without authentication."""
    pass

async def getcookie(base_url: str):
    url = f"{base_url}/start.php"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                resp.raise_for_status()
                return resp.cookies, await resp.text()
    except aiohttp.ClientError as e:
        raise CookieRetrievalError(f"HTTP error during initial request: {e}")
    except asyncio.TimeoutError:
        raise CookieRetrievalError("Initial request timed out")
    except Exception as e:
        raise CookieRetrievalError(f"Unexpected error during cookie retrieval: {e}")

async def authenticate(session: aiohttp.ClientSession, base_url: str, login: str, password: str, cookie_value: str):
    url = f"{base_url}/start.php"
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': f'PHPSESSID={cookie_value}'}
    data = {'login': login, 'password': password}
    try:
        async with session.post(url, data=data, headers=headers) as resp:
            # Spezielles Handling für falsche Anmeldedaten
            if resp.status == 403:
                raise AuthenticationError("Invalid credentials: access forbidden (403)")
            resp.raise_for_status()
            return await resp.text()
    except AuthenticationError:
        raise
    except aiohttp.ClientResponseError as e:
        raise AuthenticationError(f"Authentication failed: HTTP {e.status}")
    except aiohttp.ClientError as e:
        raise AuthenticationError(f"HTTP error during authentication: {e}")
    except asyncio.TimeoutError:
        raise AuthenticationError("Authentication request timed out")
    except Exception as e:
        raise AuthenticationError(f"Unexpected error during authentication: {e}")

async def getdata(session: aiohttp.ClientSession, base_url: str, cookie_value: str):
    url = f"{base_url}/mum-webservice/data.php"
    headers = {'Cookie': f'PHPSESSID={cookie_value}'}
    async with session.get(url, headers=headers) as resp:
        resp.raise_for_status()
        return await resp.text()


def translate_keys(data: dict, mapping: dict) -> dict:
    return {mapping.get(k, k): v for k, v in data.items()}

class BControl:
    def __init__(self, ip: str, password: str, session: aiohttp.ClientSession = None):
        """Initialize the client.

        Parameters
        ----------
        ip: str
            IP address of the B-Control meter.
        password: str
            Password used for authentication.
        session: aiohttp.ClientSession, optional
            Reuse an existing session. If omitted, ``BControl`` creates its
            own ``ClientSession`` which will be closed on :meth:`close`.
        """

        self.base_url = f"http://{ip}"
        self.password = password
        if session is None:
            self.session = aiohttp.ClientSession()
            self._session_owner = True
        else:
            self.session = session
            self._session_owner = False
        self.cookie_value = None
        self.logged_in = False
        self.serial = None
        self.app_version = None

    async def login(self) -> dict:
        """
        Logs in and returns a dict with serial, app_version and authentication status.
        Raises AuthenticationError if credentials are invalid.
        """
        try:
            cookies, text = await getcookie(self.base_url)
            init_data = json.loads(text)
            login_val = init_data.get("serial")
            if not login_val:
                raise LoginValueError("Start response missing 'serial'.")

            phpsess = cookies.get("PHPSESSID")
            if not phpsess or not phpsess.value:
                raise CookieValueError("PHPSESSID cookie missing after start.")
            self.cookie_value = phpsess.value

            auth_text = await authenticate(self.session, self.base_url, login_val, self.password, self.cookie_value)
            auth = json.loads(auth_text)

            # nur die benötigten Felder
            self.serial = auth.get("serial")
            self.app_version = auth.get("app_version")
            auth_status = bool(auth.get("authentication"))
            self.logged_in = auth_status

            _LOGGER.info("Login successful: serial=%s, app_version=%s", self.serial, self.app_version)
            return {"serial": self.serial, "app_version": self.app_version, "authentication": auth_status}

        except AuthenticationError as e:
            _LOGGER.error("Authentication error: %s", e)
            self.logged_in = False
            raise
        except (CookieRetrievalError, LoginValueError, CookieValueError) as e:
            _LOGGER.error("Login preparation failed: %s", e)
            self.logged_in = False
            raise

    async def get_data(self) -> dict:
        if not self.logged_in:
            _LOGGER.info("Session not valid, logging in first...")
            await self.login()

        raw = await getdata(self.session, self.base_url, self.cookie_value)
        data = json.loads(raw)
        if data.get("authentication") is False:
            _LOGGER.warning("Session expired, re-login")
            await self.login()
            raw = await getdata(self.session, self.base_url, self.cookie_value)
            data = json.loads(raw)

        translated_data = translate_keys(data, key_mapping)

        # Divide Total Energy+ and Total Energy- values by 100
        energy_keys = [
            "Total Energy+", "Total Energy-",
            "L1 Total Energy+", "L1 Total Energy-",
            "L2 Total Energy+", "L2 Total Energy-",
            "L3 Total Energy+", "L3 Total Energy-"
        ]

        for key in energy_keys:
            if key in translated_data and translated_data[key] is not None:
                try:
                    translated_data[key] = float(translated_data[key]) / 100
                except (ValueError, TypeError):
                    _LOGGER.warning(f"Could not convert {key} value to float: {translated_data[key]}")

        return translated_data

    async def close(self):
        """Close the underlying :class:`aiohttp.ClientSession` if owned."""
        if self._session_owner:
            await self.session.close()
