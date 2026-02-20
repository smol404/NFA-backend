import os
import re
import json
import logging
import asyncio
from datetime import datetime
from typing import Optional, Dict, Any
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from web3 import Web3
from eth_abi import encode as abi_encode, decode as abi_decode

# --- CONFIGURATION ---
load_dotenv()
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
RPC_URL = "https://bsc-dataseed.binance.org/"

# Contract addresses by agent type (type is set per chat via access code A-XXX / B-XXX)
CONTRACT_ECHO = "0xC0AD345393752506Eb63A627a124646645f8267f"
CONTRACT_TRADER = "0x424621D3Efa7bB7214D11f95B6Aa04D9CE6AEBeF" 

# Setup Logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Setup Web3
w3 = Web3(Web3.HTTPProvider(RPC_URL))
try:
    account = w3.eth.account.from_key(PRIVATE_KEY)
    my_address = account.address
except Exception as e:
    logger.error(f"Private Key Error: {e}")
    exit(1)

# Contract ABI (Minimal required for handleAction)
CONTRACT_ABI = [{
    "inputs": [
        {"internalType": "uint256", "name": "tokenId", "type": "uint256"},
        {"internalType": "string", "name": "action", "type": "string"},
        {"internalType": "bytes", "name": "payload", "type": "bytes"}
    ],
    "name": "handleAction",
    "outputs": [
        {"internalType": "bool", "name": "success", "type": "bool"},
        {"internalType": "bytes", "name": "result", "type": "bytes"}
    ],
    "stateMutability": "nonpayable",
    "type": "function"
}]

def _contract(agent_type: str):
    """Contract instance for the given agent type (A = Echo, B/C = Trader)."""
    addr = CONTRACT_ECHO if agent_type == "A" else CONTRACT_TRADER
    return w3.eth.contract(address=Web3.to_checksum_address(addr), abi=CONTRACT_ABI)

# Known token symbols -> BSC address (for type B)
TOKENS_JSON_PATH = os.path.join(os.path.dirname(__file__), "tokens.json")
TOKEN_SYMBOLS: Dict[str, str] = {}
if os.path.isfile(TOKENS_JSON_PATH):
    try:
        with open(TOKENS_JSON_PATH, "r") as f:
            TOKEN_SYMBOLS = json.load(f)
    except Exception as e:
        logger.warning(f"Could not load tokens.json: {e}")

# --- SESSION STORAGE ---
# Format: { user_id: { "type": "A"|"B"|"C", "tokenId": int, "data": { "action": str, "token": str, "amount": str } } }
sessions: Dict[int, Any] = {}

# --- DCA STORAGE ---
# Format: { user_id: [{"dca_id": str, "task": asyncio.Task, "token_id": int, "action": "buy_token"|"sell_token", "token_address": str, "token_symbol": str, "amount": str, "interval_seconds": int, "start_time": datetime}, ...] }
active_dcas: Dict[int, list] = {}

# --- HELPER FUNCTIONS ---

def resolve_token(token: str) -> Optional[str]:
    """Resolve token to BSC address: if already 0x... return it, else look up symbol in tokens.json."""
    if not token or not token.strip():
        return None
    token = token.strip()
    if re.match(r"^0x[a-fA-F0-9]{40}$", token):
        return w3.to_checksum_address(token)
    sym = token.upper()
    if sym in TOKEN_SYMBOLS:
        return w3.to_checksum_address(TOKEN_SYMBOLS[sym])
    return None

def claude_get_intent(user_message: str, agent_type: str) -> Dict[str, Any]:
    """
    Uses Claude to understand user intent. agent_type is "A", "B", or "C" (passed so Claude knows allowed actions).
    Returns either {"understood": True, "action": str, "token": str, "amount": str|None, "interval_seconds": int|None} or {"understood": False, "message": str}.
    """
    api_key = os.getenv("CLAUDE_API_KEY")
    if not api_key:
        return {"understood": False, "message": "Bot is not configured with an API key for understanding messages."}

    if agent_type == "A":
        allowed = "Only allowed action: echo_message (write the user's message on-chain)."
    elif agent_type == "B":
        allowed = "Allowed actions: buy_token, sell_token, check_balance. For buy_token/sell_token you need a token (BSC address 0x... or symbol like CAKE, BNB) and an amount in BNB. For check_balance only the token."
    else:  # agent_type == "C"
        allowed = (
            "Allowed actions: start_dca_buy, start_dca_sell, stop_dca, list_dcas, check_balance.\n"
            "- start_dca_buy/start_dca_sell: requires token (address 0x... or symbol), amount (BNB), and interval (e.g. '5 minutes', '1 hour', '30 seconds'). Multiple DCAs can run simultaneously.\n"
            "- stop_dca: stops DCA(s). If user says 'stop DCA', 'stop my DCA', 'stop active DCA', 'stop all DCA' without specifying token or action, set both stop_action and stop_token to null (will stop all DCAs). If user specifies a token (e.g. 'stop DCA BTC'), set stop_token. If user specifies an action (e.g. 'stop buy DCA'), set stop_action. If both are specified, stop matching ones.\n"
            "- list_dcas: lists all active DCAs with details (token, action, amount, interval).\n"
            "- check_balance: check token and BNB balance. Requires token address (0x...) or symbol."
        )
    
    system = (
        f"You are a blockchain bot. Agent type is {agent_type}. {allowed}\n"
        "CRITICAL: Understand the USER'S INTENTION, not just exact wording. Be flexible and intelligent.\n"
        "Understand the user in ANY language (English, French, Spanish, slang, etc.). Focus on INTENT, not exact phrases.\n"
        "Examples of intent understanding:\n"
        "- 'stop my active dca', 'stop dca', 'stop all dca', 'cancel dca' → stop_dca with stop_action=null, stop_token=null (stop all)\n"
        "- 'stop btc dca', 'stop dca btc', 'cancel btc' → stop_dca with stop_token='BTC'\n"
        "- 'stop buy dca', 'cancel buy orders' → stop_dca with stop_action='buy_token'\n"
        "- 'buy cake', 'purchase cake', 'get cake' → buy_token with token='CAKE'\n"
        "- 'check btc balance', 'show btc balance', 'what's my btc' → check_balance with token='BTC'\n"
        "Token: accept symbol (CAKE, cake, BTC, btc, BNB...) or full address 0x.... If the user only gives a name/symbol you don't recognize as a standard token, set understood: false and ask for the token address (0x...).\n"
        "Interval parsing: Convert time expressions to seconds. Examples: '5 minutes' = 300, '1 hour' = 3600, '30 seconds' = 30.\n"
        "For stop_dca: If the user wants to stop DCA(s) but doesn't specify which one clearly, assume they want to stop ALL active DCAs (set stop_action=null, stop_token=null). Only ask for clarification if the request is truly ambiguous AND you cannot infer intent.\n"
        "NEVER mention other agents or tools. Only mention what THIS agent can do.\n"
        "Reply ONLY with a single JSON object, no markdown or extra text.\n"
        f"If you understand the INTENTION: {{\"understood\": true, \"action\": \"...\", \"token\": \"...\" (for start/stop/check_balance), \"amount\": \"...\" (only for start), \"interval_seconds\": ... (only for start), \"stop_action\": \"buy_token\"|\"sell_token\"|null (only for stop_dca), \"stop_token\": \"...\"|null (only for stop_dca)}}\n"
        "If the intent is truly unclear: {\"understood\": false, \"message\": \"Short reply explaining what you need.\"}"
    )
    try:
        client = __import__("anthropic").Anthropic(api_key=api_key)
        model = os.getenv("CLAUDE_MODEL", "claude-haiku-4-5")
        resp = client.messages.create(
            model=model,
            max_tokens=512,
            system=system,
            messages=[{"role": "user", "content": user_message}],
        )
        text = resp.content[0].text if resp.content else ""
        # Strip markdown code blocks if present
        if "```" in text:
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
        data = json.loads(text.strip())
        if data.get("understood"):
            result = {
                "understood": True,
                "action": (data.get("action") or "").strip(),
                "token": (data.get("token") or "").strip() or None,
                "amount": (data.get("amount") or "").strip() or None,
                "stop_action": (data.get("stop_action") or "").strip() or None,
                "stop_token": (data.get("stop_token") or "").strip() or None,
            }
            if "interval_seconds" in data:
                try:
                    result["interval_seconds"] = int(data.get("interval_seconds", 0))
                except (ValueError, TypeError):
                    result["interval_seconds"] = None
            return result
        return {"understood": False, "message": (data.get("message") or "I didn't understand. Please try again.")}
    except json.JSONDecodeError as e:
        logger.warning(f"Claude returned non-JSON: {e}")
        return {"understood": False, "message": "I didn't understand that. Try: \"Buy 0.001 BNB of CAKE\" or \"Check balance of 0x...\"."}
    except Exception as e:
        logger.exception(f"Claude API error: {e}")
        return {"understood": False, "message": "Something went wrong. Please try again later."}

def extract_address(text: str) -> Optional[str]:
    """
    Extracts a BSC/ETH address (0x...) using Regex.
    """
    match = re.search(r"0x[a-fA-F0-9]{40}", text)
    if match:
        return match.group(0)
    return None

def extract_amount(text: str, token_id: int) -> Optional[str]:
    """
    Extracts a numeric amount (BNB). 
    Ignores the token_id if it appears in the text to avoid confusion.
    """
    # Find all numbers (integers or decimals)
    matches = re.findall(r"\b\d+(\.\d+)?\b", text)
    
    for match in matches:
        # If match is a tuple from the group, take the full match
        val = match[0] if isinstance(match, tuple) else match
        
        # Logic to ignore the Token ID (e.g., if ID is 10 and user types "10", ignore it)
        # Also ignore very long number strings that might be part of an address
        if val == str(token_id) or len(val) > 10:
            continue
            
        return val # Return the first valid number found
    return None

# --- BOT HANDLERS ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Welcome!\n\n"
        "Send your access code:\n"
        "👉 **A-XXX** — Echo (write messages on-chain)\n"
        "👉 **B-XXX** — Trader (buy, sell, check balance)\n"
        "👉 **C-XXX** — DCA Agent (automated buy/sell)\n\n"
        "Example: `A-1`, `B-123`, or `C-456`"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    bot = context.bot
    user_id = update.effective_user.id
    text = update.message.text.strip()

    # 1. AUTHENTICATION (If user is not logged in)
    if user_id not in sessions:
        match = re.match(r"^([ABC])-(\d+)$", text.upper())
        if match:
            code_type, token_id = match.groups()
            sessions[user_id] = {
                "type": code_type,
                "tokenId": int(token_id),
                "data": {"action": None, "token": None, "amount": None},
            }
            if code_type == "A":
                role_name = "Echo"
                hint = "Send any text to write on-chain."
            elif code_type == "B":
                role_name = "Trader"
                hint = 'Tell me what to buy, sell, or check balance (e.g. "Buy 0.001 BNB of CAKE").'
            else:  # C
                role_name = "DCA Agent"
                hint = 'Start a DCA: "Start DCA buy BTC with 0.0001 every 5 minutes" or "Stop DCA" or "List DCAs" or "Check balance of BTC"'
            await update.message.reply_text(
                f"✅ Authenticated as **{role_name}** (ID: {token_id}).\n{hint}"
            )
        else:
            await update.message.reply_text("❌ Invalid format. Send a code like `A-1`, `B-123`, or `C-456`.")
        return

    # Load session
    session = sessions[user_id]
    
    # ---------------------------------------------------------
    # AGENT TYPE A: ECHO
    # ---------------------------------------------------------
    if session["type"] == "A":
        await update.message.reply_text("⏳ Sending message to blockchain...")
        try:
            # Type A payload is just dummy bytes or string encoding
            payload = text.encode('utf-8') 
            tx_hash = send_transaction(session["tokenId"], text, payload, session["type"])
            await update.message.reply_text(f"✅ Message sent!\nHash: {tx_hash}")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
        return

    # ---------------------------------------------------------
    # AGENT TYPE B: TRADER (Claude parses intent, then we execute)
    # ---------------------------------------------------------
    elif session["type"] == "B":
        intent = claude_get_intent(text, "B")
        if not intent.get("understood"):
            await update.message.reply_text(intent.get("message", "I didn't understand. Please try again."))
            return

        action = (intent.get("action") or "").strip().lower()
        token_raw = intent.get("token")
        amount_raw = intent.get("amount")

        if action not in ("buy_token", "sell_token", "check_balance"):
            await update.message.reply_text("I can only help with: buy, sell, or check balance. Please rephrase.")
            return

        token_address = resolve_token(token_raw) if token_raw else None
        if not token_address:
            await update.message.reply_text(
                f"I couldn't find a valid token from « {token_raw or '?'} ». Use an address (0x...) or a symbol like CAKE, BNB."
            )
            return

        if action in ("buy_token", "sell_token"):
            if not amount_raw:
                await update.message.reply_text("Please specify an amount in BNB (e.g. 0.001).")
                return
            try:
                amount_val = float(amount_raw.replace(",", "."))
            except ValueError:
                await update.message.reply_text("Invalid amount. Use a number for BNB (e.g. 0.001).")
                return
            if amount_val <= 0:
                await update.message.reply_text("Amount must be greater than 0.")
                return
            data_amount = str(amount_val)
        else:
            data_amount = None

        # --- EXECUTE ---
        if action == "check_balance":
            await update.message.reply_text(f"✅ Checking balance for token {token_address[:10]}...\n⏳ Querying contract...")
        else:
            await update.message.reply_text(
                f"✅ **{action.replace('_', ' ').title()}**\n"
                f"🪙 Token: {token_address[:10]}...\n"
                f"💰 Amount: {data_amount} BNB\n\n⏳ Sending transaction..."
            )

        try:
            if action == "check_balance":
                payload = abi_encode(["address"], [token_address])
                bnb_balance, token_balance = call_check_balance(session["tokenId"], payload, session["type"])
                bnb_balance_ether = w3.from_wei(bnb_balance, "ether")
                token_balance_formatted = format_token_balance(token_balance, token_address)
                await update.message.reply_text(
                    f"💰 **Balance:**\n"
                    f"🟡 BNB: {bnb_balance_ether:.6f}\n"
                    f"🪙 Token: {token_balance_formatted}\n"
                )
            else:
                amount_wei = w3.to_wei(float(data_amount), "ether")
                slippage_bps = 0
                payload = abi_encode(
                    ["address", "uint256", "uint256"],
                    [token_address, amount_wei, slippage_bps],
                )
                tx_hash = send_transaction(session["tokenId"], action, payload, session["type"])
                await update.message.reply_text(
                    f"🎉 **Done!**\n🔗 [View on BscScan](https://bscscan.com/tx/{tx_hash})"
                )
        except Exception as e:
            logger.exception(f"Transaction failed: {e}")
            await update.message.reply_text(f"❌ Transaction failed: {str(e)}")

    # ---------------------------------------------------------
    # AGENT TYPE C: DCA AGENT
    # ---------------------------------------------------------
    elif session["type"] == "C":
        intent = claude_get_intent(text, "C")
        
        # Fallback: If Claude didn't understand but user seems to want to stop DCA and there's only one active
        if not intent.get("understood"):
            text_lower = text.lower()
            # Check if user wants to stop DCA (common phrases)
            stop_keywords = ["stop", "cancel", "end", "terminate", "close"]
            dca_keywords = ["dca", "order", "trade", "buying", "selling"]
            
            if any(kw in text_lower for kw in stop_keywords) and any(kw in text_lower for kw in dca_keywords):
                if user_id in active_dcas and len(active_dcas[user_id]) == 1:
                    # Only one DCA active, stop it automatically
                    dca = active_dcas[user_id][0]
                    task = dca.get("task")
                    if task and not task.done():
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                    del active_dcas[user_id]
                    await update.message.reply_text("✅ Stopped your active DCA.")
                    return
                elif user_id in active_dcas and len(active_dcas[user_id]) > 1:
                    # Multiple DCAs, ask which one
                    await update.message.reply_text(
                        f"You have {len(active_dcas[user_id])} active DCAs. Please specify which one to stop: "
                        "mention the token (e.g. 'stop BTC DCA') or action (e.g. 'stop buy DCA'), or say 'stop all DCAs'."
                    )
                    return
            
            await update.message.reply_text(intent.get("message", "I didn't understand. Please try again."))
            return

        action = (intent.get("action") or "").strip().lower()

        # --- STOP DCA ---
        if action == "stop_dca":
            if user_id not in active_dcas or not active_dcas[user_id]:
                await update.message.reply_text("❌ No active DCA found to stop.")
                return

            stop_action = intent.get("stop_action")  # "buy_token" or "sell_token" or None
            stop_token_raw = intent.get("stop_token")  # Token symbol/address or None
            
            # Resolve stop_token if provided
            stop_token_address = None
            if stop_token_raw:
                stop_token_address = resolve_token(stop_token_raw)
            
            stopped_count = 0
            dcas_to_remove = []
            
            # Make a copy of the list to avoid modification during iteration
            dcas_list = active_dcas[user_id].copy()
            
            for dca in dcas_list:
                should_stop = False
                dca_id = dca.get("dca_id")
                
                # If no filters, stop all
                if not stop_action and not stop_token_address:
                    should_stop = True
                else:
                    # Check action filter
                    if stop_action and dca.get("action") != stop_action:
                        continue
                    # Check token filter
                    if stop_token_address and dca.get("token_address") != stop_token_address:
                        continue
                    should_stop = True
                
                if should_stop:
                    task = dca.get("task")
                    if task and not task.done():
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                    # Remove by dca_id instead of index to avoid race conditions
                    if user_id in active_dcas:
                        active_dcas[user_id] = [d for d in active_dcas[user_id] if d.get("dca_id") != dca_id]
                    stopped_count += 1
            
            # Clean up empty list
            if user_id in active_dcas and not active_dcas[user_id]:
                del active_dcas[user_id]
            
            if stopped_count > 0:
                await update.message.reply_text(f"✅ Stopped {stopped_count} DCA(s) successfully.")
            else:
                await update.message.reply_text("❌ No matching DCA found to stop.")
            return

        # --- LIST DCAS ---
        if action == "list_dcas":
            if user_id not in active_dcas or not active_dcas[user_id]:
                await update.message.reply_text("❌ No active DCA found.")
                return

            messages = ["📊 **Active DCAs:**\n"]
            for idx, dca in enumerate(active_dcas[user_id], 1):
                token_addr = dca.get("token_address", "?")
                token_symbol = dca.get("token_symbol", token_addr[:10] + "...")
                amount = dca.get("amount", "?")
                interval = dca.get("interval_seconds", 0)
                dca_action = dca.get("action", "?")
                start_time = dca.get("start_time", datetime.now())
                elapsed = (datetime.now() - start_time).total_seconds()
                
                messages.append(
                    f"\n**DCA #{idx}:**\n"
                    f"🔄 Action: {dca_action.replace('_', ' ').title()}\n"
                    f"🪙 Token: {token_symbol} ({token_addr[:10]}...)\n"
                    f"💰 Amount: {amount} BNB\n"
                    f"⏱️ Interval: {interval}s ({interval/60:.1f} min)\n"
                    f"⏰ Running: {elapsed/60:.1f} min"
                )
            
            await update.message.reply_text("".join(messages))
            return

        # --- CHECK BALANCE ---
        if action == "check_balance":
            token_raw = intent.get("token")
            token_address = resolve_token(token_raw) if token_raw else None
            if not token_address:
                await update.message.reply_text(
                    f"I couldn't find a valid token from « {token_raw or '?'} ». Use an address (0x...) or a symbol like CAKE, BTC, BNB."
                )
                return

            await update.message.reply_text(f"✅ Checking balance for token {token_address[:10]}...\n⏳ Querying contract...")
            try:
                payload = abi_encode(["address"], [token_address])
                bnb_balance, token_balance = call_check_balance(session["tokenId"], payload, session["type"])
                bnb_balance_ether = w3.from_wei(bnb_balance, "ether")
                token_balance_formatted = format_token_balance(token_balance, token_address)
                await update.message.reply_text(
                    f"💰 **Balance:**\n"
                    f"🟡 BNB: {bnb_balance_ether:.6f}\n"
                    f"🪙 Token: {token_balance_formatted}\n"
                )
            except Exception as e:
                logger.exception(f"Check balance failed: {e}")
                await update.message.reply_text(f"❌ Failed to check balance: {str(e)}")
            return

        # --- START DCA (BUY or SELL) ---
        if action not in ("start_dca_buy", "start_dca_sell"):
            await update.message.reply_text("I can help with: start DCA (buy/sell), stop DCA, list DCAs, or check balance. Please rephrase.")
            return

        # Initialize list if needed
        if user_id not in active_dcas:
            active_dcas[user_id] = []

        token_raw = intent.get("token")
        amount_raw = intent.get("amount")
        interval_seconds = intent.get("interval_seconds")

        token_address = resolve_token(token_raw) if token_raw else None
        if not token_address:
            await update.message.reply_text(
                f"I couldn't find a valid token from « {token_raw or '?'} ». Use an address (0x...) or a symbol like CAKE, BTC, BNB."
            )
            return

        if not amount_raw:
            await update.message.reply_text("Please specify an amount in BNB (e.g. 0.001).")
            return

        try:
            amount_val = float(amount_raw.replace(",", "."))
        except ValueError:
            await update.message.reply_text("Invalid amount. Use a number for BNB (e.g. 0.001).")
            return

        if amount_val <= 0:
            await update.message.reply_text("Amount must be greater than 0.")
            return

        if not interval_seconds or interval_seconds <= 0:
            await update.message.reply_text("Please specify a valid interval (e.g. '5 minutes', '1 hour', '30 seconds').")
            return

        # Get token symbol for display
        token_symbol = token_raw.upper() if token_raw else token_address[:10] + "..."
        for sym, addr in TOKEN_SYMBOLS.items():
            if addr.lower() == token_address.lower():
                token_symbol = sym
                break

        # Start DCA
        dca_action = "buy_token" if action == "start_dca_buy" else "sell_token"
        chat_id = update.effective_chat.id
        dca_id = f"{dca_action}_{token_address}_{datetime.now().timestamp()}"
        
        task = asyncio.create_task(
            dca_loop(user_id, dca_id, session["tokenId"], dca_action, token_address, str(amount_val), interval_seconds, bot, chat_id)
        )
        
        dca_info = {
            "dca_id": dca_id,
            "task": task,
            "token_id": session["tokenId"],
            "action": dca_action,
            "token_address": token_address,
            "token_symbol": token_symbol,
            "amount": str(amount_val),
            "interval_seconds": interval_seconds,
            "start_time": datetime.now(),
        }
        active_dcas[user_id].append(dca_info)

        await update.message.reply_text(
            f"✅ **DCA Started!**\n"
            f"🔄 Action: {dca_action.replace('_', ' ').title()}\n"
            f"🪙 Token: {token_symbol} ({token_address[:10]}...)\n"
            f"💰 Amount: {amount_val} BNB\n"
            f"⏱️ Interval: {interval_seconds}s ({interval_seconds/60:.1f} min)\n\n"
            f"💡 Say 'stop DCA {token_symbol}' or 'stop {dca_action.replace('_', ' ')} DCA' to stop this one."
        )


async def dca_loop(user_id: int, dca_id: str, token_id: int, action: str, token_address: str, amount: str, interval_seconds: int, bot, chat_id: int):
    """
    Async loop that executes buy_token or sell_token at regular intervals.
    Stops when the task is cancelled or this DCA is removed from active_dcas.
    """
    logger.info(f"DCA loop started for user {user_id} (ID: {dca_id}): {action} {amount} BNB every {interval_seconds}s")
    
    try:
        # Check if this specific DCA still exists in active_dcas
        while user_id in active_dcas:
            dca_exists = False
            for dca in active_dcas[user_id]:
                if dca.get("dca_id") == dca_id:
                    dca_exists = True
                    break
            if not dca_exists:
                logger.info(f"DCA {dca_id} removed from list, stopping loop")
                break
            
            # Execute transaction
            try:
                amount_wei = w3.to_wei(float(amount), "ether")
                slippage_bps = 0
                payload = abi_encode(
                    ["address", "uint256", "uint256"],
                    [token_address, amount_wei, slippage_bps],
                )
                tx_hash = send_transaction(token_id, action, payload, "C")
                
                # Notify user
                await bot.send_message(
                    chat_id=chat_id,
                    text=(
                        f"🔄 **DCA executed:** {action.replace('_', ' ').title()}\n"
                        f"💰 {amount} BNB\n"
                        f"🔗 [View on BscScan](https://bscscan.com/tx/{tx_hash})"
                    ),
                    parse_mode="Markdown"
                )
            except Exception as e:
                logger.error(f"DCA transaction failed for user {user_id} (DCA {dca_id}): {e}")
                try:
                    await bot.send_message(chat_id=chat_id, text=f"❌ DCA transaction failed: {str(e)}")
                except:
                    pass
            
            # Wait for interval (with cancellation check)
            try:
                await asyncio.sleep(interval_seconds)
            except asyncio.CancelledError:
                logger.info(f"DCA loop cancelled for user {user_id} (DCA {dca_id})")
                raise
    
    except asyncio.CancelledError:
        logger.info(f"DCA loop stopped for user {user_id} (DCA {dca_id})")
        # Remove this DCA from the list (safe check)
        try:
            if user_id in active_dcas and active_dcas[user_id]:
                active_dcas[user_id] = [dca for dca in active_dcas[user_id] if dca.get("dca_id") != dca_id]
                if not active_dcas[user_id]:
                    del active_dcas[user_id]
        except Exception as e:
            logger.warning(f"Error cleaning up DCA {dca_id}: {e}")
        raise
    except Exception as e:
        logger.exception(f"DCA loop error for user {user_id} (DCA {dca_id}): {e}")
        # Remove this DCA from the list (safe check)
        try:
            if user_id in active_dcas and active_dcas[user_id]:
                active_dcas[user_id] = [dca for dca in active_dcas[user_id] if dca.get("dca_id") != dca_id]
                if not active_dcas[user_id]:
                    del active_dcas[user_id]
        except Exception as cleanup_error:
            logger.warning(f"Error cleaning up DCA {dca_id}: {cleanup_error}")
        try:
            await bot.send_message(chat_id=chat_id, text=f"❌ DCA stopped due to error: {str(e)}")
        except:
            pass


def call_check_balance(token_id: int, payload_bytes: bytes, agent_type: str) -> tuple:
    """
    Calls handleAction with check_balance action and decodes the result.
    Returns (bnb_balance, token_balance) as integers (wei). Uses Trader contract (type B).
    """
    c = _contract(agent_type)
    func = c.functions.handleAction(token_id, "check_balance", payload_bytes)
    
    # Use call() to simulate the transaction and get the result
    try:
        result = func.call({'from': my_address})
        # result is a tuple: (success: bool, result_bytes: bytes)
        success, result_bytes = result
        
        if not success:
            raise Exception("Contract call returned success=False")
        
        # Decode the result: abi.encode(bnbBal, tokenBal)
        # Returns (bnb_balance, token_balance) as integers
        decoded = abi_decode(['uint256', 'uint256'], result_bytes)
        bnb_balance, token_balance = decoded
        
        return (bnb_balance, token_balance)
    except Exception as e:
        logger.error(f"Check balance call failed: {e}")
        raise Exception(f"Failed to check balance: {str(e)}")


def format_token_balance(balance_wei: int, token_address: str) -> str:
    """
    Formats token balance by fetching decimals from ERC20 contract, or defaults to 18.
    """
    if balance_wei == 0:
        return "0"
    
    # Try to fetch decimals from ERC20 contract
    decimals = 18  # Default for most tokens
    try:
        erc20_abi = [
            {
                "constant": True,
                "inputs": [],
                "name": "decimals",
                "outputs": [{"name": "", "type": "uint8"}],
                "type": "function"
            }
        ]
        token_contract = w3.eth.contract(address=Web3.to_checksum_address(token_address), abi=erc20_abi)
        decimals = token_contract.functions.decimals().call()
    except Exception as e:
        logger.debug(f"Could not fetch decimals for {token_address}, using default 18: {e}")
        # Use default 18 decimals
    
    try:
        balance_formatted = balance_wei / (10 ** decimals)
        
        # Format based on magnitude
        if balance_formatted >= 1000000:
            return f"{balance_formatted:,.2f}"
        elif balance_formatted >= 1:
            return f"{balance_formatted:,.6f}"
        elif balance_formatted >= 0.000001:
            return f"{balance_formatted:.6f}"
        else:
            # Very small amounts: show scientific notation or raw
            return f"{balance_formatted:.2e}"
    except Exception as e:
        logger.warning(f"Error formatting balance: {e}")
        return f"{balance_wei} (raw)"


def send_transaction(token_id: int, action_str: str, payload_bytes: bytes, agent_type: str) -> str:
    """
    Constructs and sends the transaction to the BSC blockchain (Echo or Trader contract depending on agent_type).
    """
    c = _contract(agent_type)
    func = c.functions.handleAction(token_id, action_str, payload_bytes)
    
    # 2. Estimate Gas & Build Transaction
    tx_params = {
        'from': my_address,
        'nonce': w3.eth.get_transaction_count(my_address),
        'gasPrice': w3.eth.gas_price,
    }
    
    try:
        gas_estimate = func.estimate_gas(tx_params)
        tx_params['gas'] = int(gas_estimate * 1.2) # Buffer 20%
    except Exception as e:
        logger.warning(f"Gas estimation failed (using default): {e}")
        tx_params['gas'] = 500000

    tx = func.build_transaction(tx_params)
    
    # 3. Sign & Send
    signed_tx = w3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
    
    # Handle both Web3.py versions
    # Recent versions use .raw_transaction (with underscore)
    # We handle both cases to be safe
    try:
        raw_tx = signed_tx.raw_transaction
    except AttributeError:
        # Fallback for older versions
        raw_tx = signed_tx.rawTransaction
        
    tx_hash = w3.eth.send_raw_transaction(raw_tx)
    
    return w3.to_hex(tx_hash) 

if __name__ == "__main__":
    if not TOKEN:
        print("Error: TELEGRAM_BOT_TOKEN not found in .env")
        exit(1)
        
    app = Application.builder().token(TOKEN).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    print("🤖 Bot is running on BSC... Waiting for messages.")
    app.run_polling()