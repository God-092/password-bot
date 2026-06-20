"""
🔐 Secure Password Generator — Telegram Bot
Uses python-telegram-bot v20+ (async) + secrets module.
Uses HTML parse mode (more reliable than MarkdownV2 for special chars).
Free for all users. Mobile-friendly copy button included.
"""

import os
import logging
import secrets
import string
import math
import time
from collections import defaultdict
from html import escape as html_escape

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# ── Token ──────────────────────────────────────────────────────────────────────
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# ── Rate limiting (max 20 requests / user / 60 sec) ───────────────────────────
_rate_limit: dict = defaultdict(list)

def is_rate_limited(user_id: int, max_req: int = 20, window: int = 60) -> bool:
    now = time.time()
    _rate_limit[user_id] = [t for t in _rate_limit[user_id] if now - t < window]
    if len(_rate_limit[user_id]) >= max_req:
        return True
    _rate_limit[user_id].append(now)
    return False

# ── Character pools ────────────────────────────────────────────────────────────
POOLS = {
    "upper":   string.ascii_uppercase,
    "lower":   string.ascii_lowercase,
    "digits":  string.digits,
    "symbols": "!@#$%^&*()-_=+[]{}|;:,.<>?",
}

# ── Per-user settings ──────────────────────────────────────────────────────────
DEFAULT_SETTINGS = {
    "length":  20,
    "upper":   True,
    "lower":   True,
    "digits":  True,
    "symbols": True,
    "count":   1,
}

def get_settings(context: ContextTypes.DEFAULT_TYPE) -> dict:
    for k, v in DEFAULT_SETTINGS.items():
        context.user_data.setdefault(k, v)
    return context.user_data

# ── Crypto-secure generator ────────────────────────────────────────────────────
def generate_password(length: int, use_upper: bool, use_lower: bool,
                      use_digits: bool, use_symbols: bool) -> str:
    active = {}
    if use_upper:   active["upper"]   = POOLS["upper"]
    if use_lower:   active["lower"]   = POOLS["lower"]
    if use_digits:  active["digits"]  = POOLS["digits"]
    if use_symbols: active["symbols"] = POOLS["symbols"]

    if not active:
        raise ValueError("No character sets enabled.")

    charset   = "".join(active.values())
    mandatory = [secrets.choice(pool) for pool in active.values()]
    rest      = [secrets.choice(charset) for _ in range(length - len(mandatory))]
    combined  = mandatory + rest
    secrets.SystemRandom().shuffle(combined)
    return "".join(combined)

# ── Entropy info ───────────────────────────────────────────────────────────────
def entropy_info(length: int, settings: dict) -> str:
    size = sum(len(POOLS[k]) for k in ["upper","lower","digits","symbols"] if settings.get(k))
    if size == 0:
        return ""
    bits = length * math.log2(size)
    if bits < 40:    label = "❌ Very Weak"
    elif bits < 60:  label = "⚠️ Weak"
    elif bits < 80:  label = "🟡 Fair"
    elif bits < 100: label = "🟢 Strong"
    else:            label = "🔒 Very Strong"
    return f"{bits:.0f} bits — {label}"

# ── Settings keyboard & text (HTML) ───────────────────────────────────────────
def settings_keyboard(s: dict) -> InlineKeyboardMarkup:
    def tog(key, label):
        icon = "✅" if s[key] else "☐"
        return InlineKeyboardButton(f"{icon} {label}", callback_data=f"tog_{key}")

    return InlineKeyboardMarkup([
        [tog("upper", "Uppercase A–Z"),  tog("lower",   "Lowercase a–z")],
        [tog("digits","Numbers 0–9"),    tog("symbols", "Symbols !@#…")],
        [
            InlineKeyboardButton("➖", callback_data="len_down"),
            InlineKeyboardButton(f"📏 Length: {s['length']}", callback_data="len_show"),
            InlineKeyboardButton("➕", callback_data="len_up"),
        ],
        [
            InlineKeyboardButton("➖", callback_data="cnt_down"),
            InlineKeyboardButton(f"🔢 Count: {s['count']}", callback_data="cnt_show"),
            InlineKeyboardButton("➕", callback_data="cnt_up"),
        ],
        [InlineKeyboardButton("🔐 Generate Now", callback_data="do_generate")],
    ])

def settings_text(s: dict) -> str:
    sets_on = ", ".join(
        k.capitalize() for k in ["upper","lower","digits","symbols"] if s[k]
    ) or "None"
    return (
        "⚙️ <b>Password Settings</b>\n\n"
        f"📏 Length  : <code>{s['length']}</code>\n"
        f"🔢 Count   : <code>{s['count']}</code>\n"
        f"🔡 Sets    : {sets_on}\n"
        f"🔬 Entropy : <code>{entropy_info(s['length'], s)}</code>\n\n"
        "Tap to toggle options, then hit <b>Generate Now</b>."
    )

# ── Copy keyboard ──────────────────────────────────────────────────────────────
def copy_keyboard(pw_key: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📋 Copy Password", callback_data=f"copy|{pw_key}")],
        [
            InlineKeyboardButton("🔄 New Password", callback_data="do_generate"),
            InlineKeyboardButton("⚙️ Settings",     callback_data="open_settings"),
        ],
    ])

# ── Password storage (per user, keyed by short id) ────────────────────────────
_pw_store: dict = {}

def store_password(user_id: int, pw: str) -> str:
    """Store password and return a short key safe for callback_data."""
    import hashlib
    key = hashlib.md5(f"{user_id}{pw}{time.time()}".encode()).hexdigest()[:12]
    _pw_store[key] = pw
    return key

# ── Send passwords — always sends TWO messages per password ───────────────────
# Message 1: formatted info (entropy, instructions)
# Message 2: PLAIN password only — user long-presses → Copy (works 100% on all phones)
async def send_passwords(update: Update, context: ContextTypes.DEFAULT_TYPE, s: dict):
    try:
        passwords = [
            generate_password(s["length"], s["upper"], s["lower"], s["digits"], s["symbols"])
            for _ in range(s["count"])
        ]
    except ValueError:
        await update.effective_message.reply_text(
            "❌ No character sets active. Use /settings to enable some."
        )
        return

    info = entropy_info(s["length"], s)

    for i, pw in enumerate(passwords, 1):
        header = f"Password #{i}" if s["count"] > 1 else "Your Password"

        # Message 1 — info card with buttons
        await update.effective_message.reply_text(
            f"🔐 <b>{header}</b>\n"
            f"🔬 {info}\n"
            f"📏 {s['length']} chars\n\n"
            "⬇️ <b>Password is in the next message — long press it → Copy</b>",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🔄 New Password", callback_data="do_generate"),
                InlineKeyboardButton("⚙️ Settings",     callback_data="open_settings"),
            ]]),
        )

        # Message 2 — PASSWORD ONLY, plain text, no formatting
        # Long press on any phone → "Copy" appears — works 100% iOS & Android
        await update.effective_message.reply_text(pw)

# ── Command handlers ───────────────────────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if is_rate_limited(update.effective_user.id):
        await update.message.reply_text("⚠️ Too many requests. Wait a moment.")
        return
    name = html_escape(update.effective_user.first_name)
    await update.message.reply_text(
        f"👋 Hey <b>{name}</b>! I'm your <b>Secure Password Bot</b> 🔐\n\n"
        "I generate cryptographically strong passwords using Python's "
        "<code>secrets</code> module — impossible to predict.\n\n"
        "🆓 <b>100% free for everyone!</b>\n\n"
        "📋 <b>How to copy on phone:</b>\n"
        "• Android: Tap the password text\n"
        "• iPhone: Press the 📋 Copy Password button\n\n"
        "<b>Commands:</b>\n"
        "• /generate — password with your settings\n"
        "• /settings — change length, sets, count\n"
        "• /quick — instant 20-char password\n"
        "• /strong — 32-char max security\n"
        "• /pin — 6-digit PIN\n"
        "• /help — all commands\n\n"
        "Or just type a number like <code>32</code> for a quick password.",
        parse_mode="HTML",
    )

async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🔐 <b>Commands</b>\n\n"
        "/generate — generate with current settings\n"
        "/settings — interactive panel\n"
        "/quick — 20-char password\n"
        "/strong — 32-char password\n"
        "/pin — 6-digit PIN\n"
        "/start — welcome\n\n"
        "💡 Type a number (e.g. <code>24</code>) for instant password.\n\n"
        "📋 <b>Copy on phone:</b>\n"
        "• Android — tap the <code>password text</code>\n"
        "• iPhone — tap the 📋 <b>Copy Password</b> button",
        parse_mode="HTML",
    )

async def cmd_generate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if is_rate_limited(update.effective_user.id):
        await update.message.reply_text("⚠️ Too many requests. Wait a moment.")
        return
    await send_passwords(update, context, get_settings(context))

async def cmd_quick(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if is_rate_limited(update.effective_user.id):
        await update.message.reply_text("⚠️ Too many requests. Wait a moment.")
        return
    s = {"length":20,"upper":True,"lower":True,"digits":True,"symbols":True,"count":1}
    await send_passwords(update, context, s)

async def cmd_strong(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if is_rate_limited(update.effective_user.id):
        await update.message.reply_text("⚠️ Too many requests. Wait a moment.")
        return
    s = {"length":32,"upper":True,"lower":True,"digits":True,"symbols":True,"count":1}
    await send_passwords(update, context, s)

async def cmd_pin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if is_rate_limited(update.effective_user.id):
        await update.message.reply_text("⚠️ Too many requests. Wait a moment.")
        return
    pin = "".join(secrets.choice(string.digits) for _ in range(6))
    await update.message.reply_text(
        "🔢 <b>Your PIN</b>\n\n"
        "⬇️ <b>PIN is in the next message — long press it → Copy</b>",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup([[
            InlineKeyboardButton("🔄 New PIN", callback_data="do_pin"),
        ]])
    )
    await update.message.reply_text(pin)

async def cmd_settings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_settings(context)
    await update.message.reply_text(
        settings_text(s),
        parse_mode="HTML",
        reply_markup=settings_keyboard(s),
    )

# ── Inline button callbacks ────────────────────────────────────────────────────

async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    s    = get_settings(context)
    data = query.data

    # 📋 Copy button — legacy handler (no longer used but kept safe)
    if data.startswith("copy|"):
        await query.answer("Generate a new password to get a fresh copy button.", show_alert=True)
        return

    elif data == "do_generate":
        await send_passwords(update, context, s)
        return

    elif data == "do_pin":
        pin = "".join(secrets.choice(string.digits) for _ in range(6))
        await query.message.reply_text(
            "🔢 <b>Your PIN</b>\n\n"
            "⬇️ <b>PIN is in the next message — long press it → Copy</b>",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🔄 New PIN", callback_data="do_pin"),
            ]])
        )
        await query.message.reply_text(pin)
        return

    elif data == "open_settings":
        await query.message.reply_text(
            settings_text(s),
            parse_mode="HTML",
            reply_markup=settings_keyboard(s),
        )
        return

    elif data.startswith("tog_"):
        key = data[4:]
        active_count = sum(1 for k in ["upper","lower","digits","symbols"] if s[k])
        if s[key] and active_count == 1:
            await query.answer("⚠️ Keep at least one set active!", show_alert=True)
            return
        s[key] = not s[key]

    elif data == "len_up":
        s["length"] = min(s["length"] + 4, 64)
    elif data == "len_down":
        s["length"] = max(s["length"] - 4, 8)
    elif data == "cnt_up":
        s["count"] = min(s["count"] + 1, 10)
    elif data == "cnt_down":
        s["count"] = max(s["count"] - 1, 1)

    # Refresh settings panel
    await query.edit_message_text(
        settings_text(s),
        parse_mode="HTML",
        reply_markup=settings_keyboard(s),
    )

# ── Plain number → instant password ──────────────────────────────────────────

async def handle_number(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    # Only respond to pure numbers — ignore passwords or other text silently
    if not text.isdigit():
        return
    if is_rate_limited(update.effective_user.id):
        await update.message.reply_text("⚠️ Too many requests. Wait a moment.")
        return
    length = int(text)
    if length < 4:
        await update.message.reply_text("❌ Minimum length is 4.")
        return
    if length > 128:
        await update.message.reply_text("❌ Maximum length is 128.")
        return
    s = {"length":length,"upper":True,"lower":True,"digits":True,"symbols":True,"count":1}
    await send_passwords(update, context, s)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if BOT_TOKEN == "YOUR_TOKEN_HERE":
        print("\n❌  No token! Edit telegram_bot.py and add your BotFather token.\n")
        return

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start",    cmd_start))
    app.add_handler(CommandHandler("help",     cmd_help))
    app.add_handler(CommandHandler("generate", cmd_generate))
    app.add_handler(CommandHandler("quick",    cmd_quick))
    app.add_handler(CommandHandler("pin",      cmd_pin))
    app.add_handler(CommandHandler("strong",   cmd_strong))
    app.add_handler(CommandHandler("settings", cmd_settings))
    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_number))

    logger.info("🔐 Password Bot is running… Press Ctrl+C to stop.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
