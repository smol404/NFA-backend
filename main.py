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

# Chainlink Price Feed addresses on BSC (token symbol -> feed address)
# These feeds return prices in USD with 8 decimals
CHAINLINK_FEEDS: Dict[str, str] = {
    "BNB": "0x0567F2323251f0Aab15c8dFb1967E4e8A7D42aeE",  # BNB/USD
    "BTC": "0x264990fbd0A4796A3E3d8E37C4d5F87a3aCa5Ebf",  # BTC/USD
    "BTCB": "0x264990fbd0A4796A3E3d8E37C4d5F87a3aCa5Ebf",  # BTCB/USD
    "BUSD": "0xcBb98864Ef56E9042e7d2efEfE41dbEcFd1D86F1",  # BUSD/USD
    "CAKE": "0xB6064eD41d4f67e353768aA239cA86f4F73665a1",  # CAKE/USD
    "ETH": "0x9ef1B8c0E4F7dc8bF5719Ea496883DC6401d5b2e",  # ETH/USD
    "USDT": "0xB97Ad0E74fa7d920791E90258A6E2085088b4320",  # USDT/USD
}

# --- SESSION STORAGE ---
# Format: { user_id: { "type": "A"|"B"|"C", "tokenId": int, "data": { "action": str, "token": str, "amount": str } } }
sessions: Dict[int, Any] = {}

# --- DCA STORAGE ---
# Format: { user_id: [{"dca_id": str, "task": asyncio.Task, "token_id": int, "action": "buy_token"|"sell_token", "token_address": str, "token_symbol": str, "amount": str, "interval_seconds": int, "start_time": datetime}, ...] }
active_dcas: Dict[int, list] = {}

# --- LIMIT ORDER STORAGE ---
# Format: { user_id: [{"order_id": str, "task": asyncio.Task, "token_id": int, "action": "buy_token"|"sell_token", "token_address": str, "token_symbol": str, "amount": str, "target_price": float, "created_time": datetime}, ...] }
active_limit_orders: Dict[int, list] = {}

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
        allowed = (
            "Allowed actions: buy_token, sell_token, check_balance, get_price, buy_limit, sell_limit, cancel_limit, list_limits.\n"
            "- buy_token/sell_token: instant buy/sell. Requires token (address 0x... or symbol) and amount in BNB.\n"
            "- get_price: get the current price of a token in USDT. This is for INFORMATION ONLY, not for trading. Requires token (address 0x... or symbol like BTC, ETH, CAKE). Examples: 'what is the price of BTC?', 'what the price of BTC', 'price of ETH', 'how much is CAKE?', 'BTC price', 'show me ETH price', 'what's BTC worth?', 'tell me the price of BTC'\n"
            "- buy_limit/sell_limit: place limit order. Requires: target_token (token to buy/sell like BTC, ETH), payment_amount (amount to spend in BNB or USDT), payment_currency ('BNB' or 'USDT'), and target_price in USDT per target_token. Examples: 'buy 0.0001 BNB of BTC when BTC price is 68260' → target_token=BTC, payment_amount=0.0001, payment_currency=BNB, target_price=68260. 'buy 10 USDT of ETH when ETH price is 2000' → target_token=ETH, payment_amount=10, payment_currency=USDT, target_price=2000.\n"
            "- cancel_limit: cancel a limit order. Examples: 'cancel limit', 'cancel my order limit', 'cancel order', 'cancel limit BTC', 'cancel all limits', 'cancel my limit order'. If user says 'cancel limit' or 'cancel order' without specifying token, cancel all orders.\n"
            "- list_limits: list all active limit orders. Examples: 'list limits', 'list limit', 'show limits', 'show my orders', 'my orders'.\n"
            "- check_balance: check token and BNB balance. Requires token."
        )
    else:  # agent_type == "C"
        allowed = (
            "Allowed actions: start_dca_buy, start_dca_sell, stop_dca, list_dcas, check_balance, get_price.\n"
            "- start_dca_buy/start_dca_sell: requires token (address 0x... or symbol), amount (BNB), and interval (e.g. '5 minutes', '1 hour', '30 seconds'). Multiple DCAs can run simultaneously.\n"
            "- get_price: get the current price of a token in USDT. This is for INFORMATION ONLY, not for trading. Requires token (address 0x... or symbol like BTC, ETH, CAKE). Examples: 'what is the price of BTC?', 'what the price of BTC', 'price of ETH', 'how much is CAKE?', 'BTC price', 'what price is BTC?', 'tell me BTC price'\n"
            "- stop_dca: stops DCA(s). If user says 'stop DCA', 'stop my DCA', 'stop active DCA', 'stop all DCA' without specifying token or action, set both stop_action and stop_token to null (will stop all DCAs). If user specifies a token (e.g. 'stop DCA BTC'), set stop_token. If user specifies an action (e.g. 'stop buy DCA'), set stop_action. If both are specified, stop matching ones.\n"
            "- list_dcas: lists all active DCAs with details (token, action, amount, interval).\n"
            "- check_balance: check token and BNB balance. Requires token address (0x...) or symbol."
        )
    
    system = (
        f"You are an intelligent COORDINATOR AGENT for a blockchain trading system.\n"
        f"Your role: Understand the user's INTENTION and route them to the correct action.\n\n"
        f"Agent Type: {agent_type}. Available actions: {allowed}\n\n"
        "CRITICAL: You are NOT a keyword matcher. You are an INTENTION UNDERSTANDER.\n"
        "Your job is to ANALYZE what the user REALLY wants to accomplish, regardless of how they phrase it.\n\n"
        "THINK LIKE A COORDINATOR:\n"
        "1. Read the user's message\n"
        "2. Ask yourself: 'What is the user trying to accomplish?'\n"
        "3. Map that intention to the correct action\n"
        "4. Extract the necessary parameters\n\n"
        "INTENTION MAPPING (think about PURPOSE, not exact words):\n\n"
        "INTENTION: User wants to KNOW THE PRICE of a token\n"
        "→ Action: get_price\n"
        "→ Examples (all mean the same thing): 'what is the price of BTC?', 'what the price of BTC', 'price of BTC', 'BTC price', 'how much is BTC?', 'tell me BTC price', 'show me BTC price', 'what's BTC worth?', 'BTC?', 'what price is BTC?'\n"
        "→ Key insight: User is asking for INFORMATION, not trying to trade. No buying/selling mentioned.\n\n"
        "INTENTION: User wants to TRADE RIGHT NOW (immediate execution)\n"
        "→ Action: buy_token or sell_token\n"
        "→ Examples: 'buy BTC', 'sell ETH', 'buy 0.001 BNB of CAKE', 'sell my BTC'\n"
        "→ Key insight: User wants immediate action, no conditions or delays.\n\n"
        "INTENTION: User wants to TRADE WHEN PRICE REACHES A TARGET (conditional execution)\n"
        "→ Action: buy_limit or sell_limit\n"
        "→ Examples: 'buy BTC when price is 68000', 'sell ETH at 2000', 'buy BTC when it reaches 68000', 'sell when BTC hits 70000'\n"
        "→ Key insight: User mentions a PRICE CONDITION or TARGET. They want to wait for price.\n\n"
        "INTENTION: User wants to TRADE REPEATEDLY AT INTERVALS (automated recurring trades)\n"
        "→ Action: start_dca_buy or start_dca_sell\n"
        "→ Examples: 'start DCA buy BTC every 5 minutes', 'DCA sell ETH every hour', 'buy BTC every 10 minutes'\n"
        "→ Key insight: User mentions REPETITION or INTERVALS. They want automated recurring trades.\n\n"
        "INTENTION: User wants to SEE WHAT'S CURRENTLY RUNNING (list active operations)\n"
        "→ Action: list_limits or list_dcas\n"
        "→ Examples: 'list limits', 'list limit', 'show my orders', 'my orders', 'what orders do I have?', 'show limits', 'list DCAs', 'my DCAs'\n"
        "→ Key insight: User wants to VIEW/SEE/CHECK what's active. They're asking for STATUS.\n\n"
        "INTENTION: User wants to STOP/CANCEL something that's running\n"
        "→ Action: cancel_limit or stop_dca\n"
        "→ Examples: 'cancel limit', 'cancel my order limit', 'cancel order', 'cancel my order', 'stop DCA', 'stop my DCA', 'cancel all limits', 'stop all DCAs'\n"
        "→ Key insight: User wants to TERMINATE/STOP something. They mention cancel/stop/remove/delete.\n\n"
        "INTENTION: User wants to CHECK THEIR BALANCE\n"
        "→ Action: check_balance\n"
        "→ Examples: 'check balance', 'my balance', 'balance of BTC', 'how much BTC do I have?', 'show balance'\n"
        "→ Key insight: User wants to KNOW their holdings/balance.\n\n"
        "UNDERSTANDING LIMIT ORDERS:\n"
        "- User mentions a PRICE TARGET or CONDITION (e.g. 'when price is X', 'at price X', 'when BTC reaches X') → it's a limit order\n"
        "- Identify: WHAT token they want to buy/sell (token field), HOW MUCH they want to spend (amount field), WHAT currency they're spending (payment_currency: BNB or USDT), and AT WHAT PRICE (target_price in USDT)\n"
        "- The token to buy/sell is ALWAYS mentioned in the message - extract it! Examples:\n"
        "  * 'buy BTC when it hits 68000' → token=BTC\n"
        "  * 'Buy 0.0001 BNB of BTC when BTC reaches 68170' → token=BTC (BTC is mentioned twice - once as target, once in price condition)\n"
        "  * 'spend 0.0001 BNB on BTC when BTC is 68210' → token=BTC\n"
        "  * 'sell ETH when ETH reaches 2000' → token=ETH\n"
        "- Examples of complete parsing:\n"
        "  * 'buy BTC when it hits 68000' → action=buy_limit, token=BTC, amount=0.001 (default), payment_currency=BNB, target_price=68000\n"
        "  * 'Buy 0.0001 BNB of BTC when BTC reaches 68170' → action=buy_limit, token=BTC, amount=0.0001, payment_currency=BNB, target_price=68170\n"
        "  * 'sell 10 USDT worth of ETH when ETH reaches 2000' → action=sell_limit, token=ETH, amount=10, payment_currency=USDT, target_price=2000\n\n"
        "UNDERSTANDING PAYMENT vs TARGET:\n"
        "- Payment currency (BNB/USDT): What the user is SPENDING to buy, or RECEIVING when selling\n"
        "- Target token: What the user wants to BUY or SELL (BTC, ETH, CAKE, etc.)\n"
        "- If user says 'buy X BNB of Y' or 'spend X BNB on Y', X is payment_amount in BNB, Y is target_token\n"
        "- If user says 'buy X USDT of Y', X is payment_amount in USDT, Y is target_token\n"
        "- If user says 'sell Y when price is X', Y is target_token, X is target_price\n\n"
        "UNDERSTANDING DCA:\n"
        "- User wants REPEATED purchases/sales at INTERVALS → DCA\n"
        "- Extract: token, amount (BNB), and interval (convert to seconds)\n\n"
        "UNDERSTANDING STOP/CANCEL:\n"
        "- User wants to STOP something → identify what (all, specific token, specific action)\n"
        "- If unclear, default to stopping ALL\n\n"
        "CRITICAL: PRICE QUERIES:\n"
        "- If user asks about price WITHOUT buying/selling → action=get_price\n"
        "- Examples of get_price: 'what is the price of BTC?', 'what the price of BTC', 'price of BTC', 'BTC price', 'how much is BTC?', 'what price is BTC?', 'tell me BTC price', 'show me BTC price'\n"
        "- If user asks about price WITH buying/selling intention → buy_limit/sell_limit (NOT get_price)\n"
        "- Examples of buy_limit (NOT get_price): 'buy BTC when price is 68000', 'buy BTC at 68000', 'buy BTC when it reaches 68000'\n\n"
        "HOW TO WORK:\n"
        "1. Read the user's message completely\n"
        "2. Identify the CORE INTENTION (what they want to achieve)\n"
        "3. Don't get stuck on exact wording - 'cancel my order limit' = 'cancel limit' = 'cancel order' = same intention\n"
        "4. Don't require perfect grammar - 'list limit' (singular) = 'list limits' (plural) = same intention\n"
        "5. Think about synonyms and variations - 'show' = 'list' = 'display' = same intention\n"
        "6. Extract parameters from context, even if not explicitly stated\n\n"
        "EXAMPLES OF INTENTION UNDERSTANDING:\n"
        "- 'list limit' → User wants to SEE their orders → list_limits (don't require plural!)\n"
        "- 'cancel my order limit' → User wants to STOP their order → cancel_limit (don't require exact phrase!)\n"
        "- 'what the price of BTC' → User wants INFORMATION about price → get_price (don't require perfect grammar!)\n"
        "- 'my orders' → User wants to VIEW what's active → list_limits (understand context!)\n"
        "- 'cancel order' → User wants to TERMINATE something → cancel_limit (understand synonyms!)\n\n"
        "LANGUAGE: Understand ANY language naturally. Don't look for specific phrases - understand the MEANING.\n"
        "If the user's intention is CLEAR, extract it even if the wording is imperfect.\n"
        "Only ask for clarification if the intention is truly ambiguous.\n"
        "NEVER mention other agents or tools.\n\n"
        "Reply ONLY with JSON, no markdown:\n"
        f"If understood: {{\"understood\": true, \"action\": \"...\", \"token\": \"...\", \"amount\": \"...\", \"payment_currency\": \"BNB\"|\"USDT\"|null, \"interval_seconds\": ..., \"target_price\": ..., \"stop_action\": \"buy_token\"|\"sell_token\"|null, \"stop_token\": \"...\"|null}}\n"
        "If not understood: {{\"understood\": false, \"message\": \"...\"}}"
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
            # Extract token - try different field names Claude might use
            token_value = (
                data.get("token") or 
                data.get("target_token") or 
                data.get("token_symbol") or 
                ""
            )
            
            # Extract amount - handle both string and numeric values
            amount_value = data.get("amount") or data.get("payment_amount")
            if amount_value is not None:
                amount_str = str(amount_value).strip()
            else:
                amount_str = None
            
            # Extract payment_currency - handle string or null
            payment_currency_value = data.get("payment_currency")
            payment_currency_str = str(payment_currency_value).strip() if payment_currency_value else None
            
            result = {
                "understood": True,
                "action": str(data.get("action") or "").strip(),
                "token": str(token_value).strip() if token_value else None,
                "amount": amount_str,
                "payment_currency": payment_currency_str,
                "stop_action": str(data.get("stop_action") or "").strip() if data.get("stop_action") else None,
                "stop_token": str(data.get("stop_token") or "").strip() if data.get("stop_token") else None,
            }
            if "interval_seconds" in data:
                try:
                    result["interval_seconds"] = int(data.get("interval_seconds", 0))
                except (ValueError, TypeError):
                    result["interval_seconds"] = None
            if "target_price" in data:
                try:
                    result["target_price"] = float(data.get("target_price", 0))
                except (ValueError, TypeError):
                    result["target_price"] = None
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
        
        # Fallback: If Claude didn't understand but user seems to want to cancel limit order and there's only one active
        if not intent.get("understood"):
            text_lower = text.lower()
            # Check if user wants to cancel limit order (common phrases)
            cancel_keywords = ["cancel", "delete", "remove", "stop"]
            limit_keywords = ["limit", "order", "orders"]
            
            if any(kw in text_lower for kw in cancel_keywords) and any(kw in text_lower for kw in limit_keywords):
                if user_id in active_limit_orders and len(active_limit_orders[user_id]) == 1:
                    # Only one limit order active, cancel it automatically
                    order = active_limit_orders[user_id][0]
                    order_id = order.get("order_id")
                    task = order.get("task")
                    if task and not task.done():
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                    del active_limit_orders[user_id]
                    await update.message.reply_text("✅ Cancelled your limit order.")
                    return
                elif user_id in active_limit_orders and len(active_limit_orders[user_id]) > 1:
                    # Multiple orders, ask which one
                    await update.message.reply_text(
                        f"You have {len(active_limit_orders[user_id])} active limit orders. Please specify which one to cancel: "
                        "mention the token (e.g. 'cancel limit BTC') or action (e.g. 'cancel buy limit'), or say 'cancel all limits'."
                    )
                    return
            
            # Check if user wants to list limits (common variations)
            list_keywords = ["list", "show", "display", "my"]
            if any(kw in text_lower for kw in list_keywords) and any(kw in text_lower for kw in limit_keywords):
                # User wants to list limits, set intent to understood
                intent = {"understood": True, "action": "list_limits"}
            
            if not intent.get("understood"):
                await update.message.reply_text(intent.get("message", "I didn't understand. Please try again."))
                return

        action = (intent.get("action") or "").strip().lower()
        token_raw = intent.get("token")
        amount_raw = intent.get("amount")

        # --- LIMIT ORDERS ---
        if action == "list_limits":
            if user_id not in active_limit_orders or not active_limit_orders[user_id]:
                await update.message.reply_text("❌ No active limit orders found.")
                return
            
            messages = ["📊 **Active Limit Orders:**\n"]
            for idx, order in enumerate(active_limit_orders[user_id], 1):
                token_addr = order.get("token_address", "?")
                token_symbol = order.get("token_symbol", token_addr[:10] + "...")
                amount_bnb = order.get("amount", "?")
                amount_original = order.get("amount_original", amount_bnb)
                payment_currency = order.get("payment_currency", "BNB")
                target_price = order.get("target_price", "?")
                order_action = order.get("action", "?")
                created_time = order.get("created_time", datetime.now())
                
                amount_display = f"{amount_original} {payment_currency}"
                if payment_currency == "USDT" and amount_bnb != "?":
                    try:
                        amount_display += f" (~{float(amount_bnb):.6f} BNB)"
                    except:
                        pass
                else:
                    amount_display = f"{amount_bnb} BNB"
                
                messages.append(
                    f"\n**Order #{idx}:**\n"
                    f"🔄 Action: {order_action.replace('_', ' ').title()}\n"
                    f"🪙 Token: {token_symbol} ({token_addr[:10]}...)\n"
                    f"💰 Amount: {amount_display}\n"
                    f"🎯 Target Price: {target_price} USDT per token\n"
                    f"⏰ Created: {created_time.strftime('%Y-%m-%d %H:%M:%S')}"
                )
            
            await update.message.reply_text("".join(messages))
            return

        if action == "cancel_limit":
            if user_id not in active_limit_orders or not active_limit_orders[user_id]:
                await update.message.reply_text("❌ No active limit orders found to cancel.")
                return

            cancel_action = intent.get("stop_action")  # "buy_token" or "sell_token" or None
            cancel_token_raw = intent.get("stop_token")  # Token symbol/address or None
            
            # Resolve cancel_token if provided
            cancel_token_address = None
            if cancel_token_raw:
                cancel_token_address = resolve_token(cancel_token_raw)
            
            cancelled_count = 0
            orders_list = active_limit_orders[user_id].copy()
            
            for order in orders_list:
                should_cancel = False
                order_id = order.get("order_id")
                
                # If no filters, cancel all
                if not cancel_action and not cancel_token_address:
                    should_cancel = True
                else:
                    # Check action filter
                    if cancel_action and order.get("action") != cancel_action:
                        continue
                    # Check token filter
                    if cancel_token_address and order.get("token_address") != cancel_token_address:
                        continue
                    should_cancel = True
                
                if should_cancel:
                    task = order.get("task")
                    if task and not task.done():
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                    if user_id in active_limit_orders:
                        active_limit_orders[user_id] = [o for o in active_limit_orders[user_id] if o.get("order_id") != order_id]
                    cancelled_count += 1
            
            if user_id in active_limit_orders and not active_limit_orders[user_id]:
                del active_limit_orders[user_id]
            
            if cancelled_count > 0:
                await update.message.reply_text(f"✅ Cancelled {cancelled_count} limit order(s).")
            else:
                await update.message.reply_text("❌ No matching limit orders found to cancel.")
            return

        if action in ("buy_limit", "sell_limit"):
            # Try to extract token from the original message if Claude didn't provide it
            if not token_raw:
                # Fallback: try to find token symbol in the original message
                text_upper = text.upper()
                for symbol in TOKEN_SYMBOLS.keys():
                    if symbol in text_upper and symbol != "BNB":  # Don't use BNB as target token
                        token_raw = symbol
                        logger.info(f"Extracted token {symbol} from message as fallback")
                        break
            
            token_address = resolve_token(token_raw) if token_raw else None
            if not token_address:
                await update.message.reply_text(
                    f"I couldn't identify which token you want to trade. Please specify the token (e.g. BTC, ETH, CAKE) or its address (0x...)."
                )
                return

            if not amount_raw:
                await update.message.reply_text("Please specify an amount (e.g. '0.001 BNB' or '10 USDT').")
                return

            target_price = intent.get("target_price")
            if not target_price:
                await update.message.reply_text("Please specify a target price in USDT per token (e.g. 'sell BTC when price reaches 100000').")
                return

            payment_currency = intent.get("payment_currency", "BNB").upper()  # Default to BNB if not specified
            
            try:
                amount_val = float(amount_raw.replace(",", "."))
                target_price_val = float(str(target_price).replace(",", "."))
            except (ValueError, TypeError):
                await update.message.reply_text("Invalid amount or price. Use numbers (e.g. amount: 0.001, price: 10000).")
                return

            if amount_val <= 0 or target_price_val <= 0:
                await update.message.reply_text("Amount and target price must be greater than 0.")
                return

            # Convert USDT to BNB if payment currency is USDT
            amount_bnb = amount_val
            if payment_currency == "USDT":
                bnb_price = get_bnb_usdt_price()
                if bnb_price is None or bnb_price <= 0:
                    await update.message.reply_text("❌ Could not get BNB/USDT price. Please try again later.")
                    return
                amount_bnb = amount_val / bnb_price
                logger.info(f"Converted {amount_val} USDT to {amount_bnb:.6f} BNB (BNB price: {bnb_price:.2f} USDT)")

            # Get token symbol
            token_symbol = token_raw.upper() if token_raw else token_address[:10] + "..."
            for sym, addr in TOKEN_SYMBOLS.items():
                if addr.lower() == token_address.lower():
                    token_symbol = sym
                    break

            # Initialize list if needed
            if user_id not in active_limit_orders:
                active_limit_orders[user_id] = []

            order_action = "buy_token" if action == "buy_limit" else "sell_token"
            order_id = f"{order_action}_{token_address}_{datetime.now().timestamp()}"
            chat_id = update.effective_chat.id
            
            task = asyncio.create_task(
                limit_order_loop(user_id, order_id, session["tokenId"], order_action, token_address, str(amount_bnb), target_price_val, bot, chat_id, payment_currency, str(amount_val))
            )
            
            order_info = {
                "order_id": order_id,
                "task": task,
                "token_id": session["tokenId"],
                "action": order_action,
                "token_address": token_address,
                "token_symbol": token_symbol,
                "amount": str(amount_bnb),  # Store in BNB for execution
                "amount_original": str(amount_val),  # Store original amount
                "payment_currency": payment_currency,  # Store original currency
                "target_price": target_price_val,
                "created_time": datetime.now(),
            }
            active_limit_orders[user_id].append(order_info)

            amount_display = f"{amount_val} {payment_currency}"
            if payment_currency == "USDT":
                amount_display += f" (~{amount_bnb:.6f} BNB)"
            
            await update.message.reply_text(
                f"✅ **Limit Order Placed!**\n"
                f"🔄 Action: {order_action.replace('_', ' ').title()}\n"
                f"🪙 Token: {token_symbol} ({token_address[:10]}...)\n"
                f"💰 Amount: {amount_display}\n"
                f"🎯 Target Price: {target_price_val} USDT per token\n\n"
                f"💡 Say 'cancel limit {token_symbol}' or 'list limits' to manage orders."
            )
            return

        if action not in ("buy_token", "sell_token", "check_balance", "get_price"):
            await update.message.reply_text("I can help with: buy, sell, check balance, get price, limit orders (buy_limit/sell_limit), cancel_limit, or list_limits. Please rephrase.")
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

        # --- GET PRICE ---
        if action == "get_price":
            token_symbol = token_raw.upper() if token_raw else None
            if not token_symbol:
                await update.message.reply_text("❌ Please specify a token (e.g., 'price of BTC', 'what is ETH price?').")
                return
            
            await update.message.reply_text(f"⏳ Fetching price for {token_symbol}...")
            try:
                price = get_asset_price(token_symbol)
                if price is not None:
                    await update.message.reply_text(
                        f"💰 **{token_symbol} Price:**\n"
                        f"💵 {price:.2f} USDT per token"
                    )
                else:
                    await update.message.reply_text(f"❌ Could not fetch price for {token_symbol}. Please try again later.")
            except Exception as e:
                logger.exception(f"Error getting price: {e}")
                await update.message.reply_text(f"❌ Error fetching price: {str(e)}")
            return

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

        # --- GET PRICE ---
        if action == "get_price":
            token_raw = intent.get("token")
            token_symbol = token_raw.upper() if token_raw else None
            if not token_symbol:
                await update.message.reply_text("❌ Please specify a token (e.g., 'price of BTC', 'what is ETH price?').")
                return
            
            await update.message.reply_text(f"⏳ Fetching price for {token_symbol}...")
            try:
                price = get_asset_price(token_symbol)
                if price is not None:
                    await update.message.reply_text(
                        f"💰 **{token_symbol} Price:**\n"
                        f"💵 {price:.2f} USDT per token"
                    )
                else:
                    await update.message.reply_text(f"❌ Could not fetch price for {token_symbol}. Please try again later.")
            except Exception as e:
                logger.exception(f"Error getting price: {e}")
                await update.message.reply_text(f"❌ Error fetching price: {str(e)}")
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


def get_bnb_usdt_price() -> Optional[float]:
    """
    Gets the current BNB price in USDT using Chainlink BNB/USD feed.
    Returns USDT per BNB, or None if error.
    """
    try:
        bnb_feed_address = CHAINLINK_FEEDS.get("BNB")
        if not bnb_feed_address:
            logger.warning("BNB Chainlink feed not configured")
            return None
        
        # Chainlink AggregatorV3Interface ABI (minimal for latestAnswer)
        chainlink_abi = [
            {
                "inputs": [],
                "name": "latestAnswer",
                "outputs": [{"internalType": "int256", "name": "", "type": "int256"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "decimals",
                "outputs": [{"internalType": "uint8", "name": "", "type": "uint8"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]
        
        feed = w3.eth.contract(address=Web3.to_checksum_address(bnb_feed_address), abi=chainlink_abi)
        # latestAnswer returns price with 8 decimals
        price_raw = feed.functions.latestAnswer().call()
        price = float(price_raw) / (10 ** 8)  # Chainlink uses 8 decimals
        return price
    except Exception as e:
        logger.warning(f"Failed to get BNB/USDT price from Chainlink: {e}")
        return None


def get_asset_price(token_symbol_or_address: str) -> Optional[float]:
    """
    Public function to get the current price of an asset.
    Accepts either a token symbol (e.g., "BTC", "ETH", "CAKE") or a token address (0x...).
    Returns price in USDT per token, or None if error.
    
    Args:
        token_symbol_or_address: Token symbol (e.g., "BTC") or token address (0x...)
    
    Returns:
        Price in USDT per token, or None if error
    """
    try:
        # Check if it's an address or symbol
        if token_symbol_or_address.startswith("0x") and len(token_symbol_or_address) == 42:
            # It's an address
            return get_token_price(token_symbol_or_address)
        else:
            # It's a symbol - resolve to address first
            token_symbol = token_symbol_or_address.upper()
            token_address = resolve_token(token_symbol)
            
            if not token_address:
                logger.warning(f"Token address not found for symbol {token_symbol}")
                return None
            
            return get_token_price(token_address)
    except Exception as e:
        logger.error(f"Error getting asset price for {token_symbol_or_address}: {e}")
        return None


def get_token_price(token_address: str) -> Optional[float]:
    """
    Gets the current price of a token in USDT using Chainlink Price Feeds.
    Returns price in USDT per token, or None if error.
    Uses Chainlink feeds which return prices with 8 decimals.
    """
    try:
        # Find token symbol from address
        token_symbol = None
        for sym, addr in TOKEN_SYMBOLS.items():
            if addr.lower() == token_address.lower():
                token_symbol = sym
                break
        
        if not token_symbol:
            logger.warning(f"Token symbol not found for address {token_address}, cannot use Chainlink")
            # Try PancakeSwap directly
            return get_token_price_pancakeswap(token_address)
        
        # Get Chainlink feed address for this token
        feed_address = CHAINLINK_FEEDS.get(token_symbol)
        if not feed_address:
            logger.warning(f"Chainlink feed not available for {token_symbol}, falling back to PancakeSwap")
            # Fallback to PancakeSwap for tokens without Chainlink feed
            return get_token_price_pancakeswap(token_address)
        
        # Chainlink AggregatorV3Interface ABI (minimal for latestAnswer)
        chainlink_abi = [
            {
                "inputs": [],
                "name": "latestAnswer",
                "outputs": [{"internalType": "int256", "name": "", "type": "int256"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "decimals",
                "outputs": [{"internalType": "uint8", "name": "", "type": "uint8"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]
        
        feed = w3.eth.contract(address=Web3.to_checksum_address(feed_address), abi=chainlink_abi)
        # latestAnswer returns price with 8 decimals
        price_raw = feed.functions.latestAnswer().call()
        price = float(price_raw) / (10 ** 8)  # Chainlink uses 8 decimals
        return price
        
    except Exception as e:
        logger.warning(f"Failed to get price for {token_address} from Chainlink: {e}")
        # Fallback to PancakeSwap
        return get_token_price_pancakeswap(token_address)


def get_token_price_pancakeswap(token_address: str) -> Optional[float]:
    """
    Fallback: Gets the current price of a token in USDT using PancakeSwap V2 router.
    Returns price in USDT per token, or None if error.
    """
    try:
        PANCAKESWAP_ROUTER = "0x10ED43C718714eb63d5aA57B78B54704E256024E"
        WBNB_ADDRESS = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"
        USDT_ADDRESS = "0x55d398326f99059fF775485246999027B3197955"
        
        router_abi = [
            {
                "inputs": [
                    {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
                    {"internalType": "address[]", "name": "path", "type": "address[]"}
                ],
                "name": "getAmountsOut",
                "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]
        
        router = w3.eth.contract(address=Web3.to_checksum_address(PANCAKESWAP_ROUTER), abi=router_abi)
        token_address = Web3.to_checksum_address(token_address)
        
        amount_in = w3.to_wei(1, "ether")
        path = [
            token_address,
            Web3.to_checksum_address(WBNB_ADDRESS),
            Web3.to_checksum_address(USDT_ADDRESS)
        ]
        
        amounts = router.functions.getAmountsOut(amount_in, path).call()
        if len(amounts) >= 3:
            usdt_amount = amounts[2]
            price = w3.from_wei(usdt_amount, "ether")
            return float(price)
        
        return None
    except Exception as e:
        logger.warning(f"Failed to get price for {token_address} from PancakeSwap: {e}")
        return None


async def limit_order_loop(user_id: int, order_id: str, token_id: int, action: str, token_address: str, amount: str, target_price: float, bot, chat_id: int, payment_currency: str = "BNB", amount_original: str = None):
    """
    Async loop that checks token price periodically and executes limit order when target price is reached.
    For buy_limit: executes when current_price <= target_price (price drops to target)
    For sell_limit: executes when current_price >= target_price (price rises to target)
    """
    logger.info(f"Limit order loop started for user {user_id} (Order {order_id}): {action} {amount} BNB at {target_price} USDT/token")
    
    try:
        check_interval = 30  # Check price every 30 seconds
        initial_price_checked = False
        initial_price = None
        
        while user_id in active_limit_orders:
            # Check if this order still exists
            order_exists = False
            for order in active_limit_orders.get(user_id, []):
                if order.get("order_id") == order_id:
                    order_exists = True
                    break
            if not order_exists:
                logger.info(f"Limit order {order_id} removed from list, stopping loop")
                break
            
            # Get current price
            current_price = get_token_price(token_address)
            
            if current_price is None:
                logger.warning(f"Could not get price for {token_address}, retrying in {check_interval}s")
                await asyncio.sleep(check_interval)
                continue
            
            # Store initial price on first check
            if not initial_price_checked:
                initial_price = current_price
                initial_price_checked = True
                logger.info(f"Initial price for {order_id}: {initial_price:.2f} USDT, target: {target_price:.2f} USDT")
            
            should_execute = False
            if action == "buy_token":
                # Buy_limit: execute when price DROPS to or below target
                # Only execute if price was initially ABOVE target and now dropped to/below target
                # OR if price is already below target and we're waiting for it to go back up (but that's not a buy_limit)
                # Actually, for buy_limit: we want to buy when price drops TO the target from above
                # If price is already below target, we should wait for it to go back up first, then drop again
                # But simpler logic: buy when current_price <= target_price AND (initial_price was None or initial_price >= target_price)
                if initial_price is not None:
                    # Only execute if price was initially at or above target and now dropped to/below
                    should_execute = (initial_price >= target_price) and (current_price <= target_price)
                else:
                    # Fallback: if we can't track initial price, use simple check
                    should_execute = current_price <= target_price
            else:  # sell_token
                # Sell_limit: execute when price RISES to or above target
                # Only execute if price was initially BELOW target and now rose to/above target
                if initial_price is not None:
                    should_execute = (initial_price <= target_price) and (current_price >= target_price)
                else:
                    should_execute = current_price >= target_price
            
            if should_execute:
                logger.info(f"Limit order {order_id} triggered: current_price={current_price}, target_price={target_price}")
                
                # Execute transaction
                try:
                    amount_wei = w3.to_wei(float(amount), "ether")
                    slippage_bps = 0
                    payload = abi_encode(
                        ["address", "uint256", "uint256"],
                        [token_address, amount_wei, slippage_bps],
                    )
                    tx_hash = send_transaction(token_id, action, payload, "B")
                    
                    # Notify user
                    amount_display = f"{amount} BNB"
                    if payment_currency == "USDT" and amount_original:
                        amount_display = f"{amount_original} {payment_currency} (~{amount} BNB)"
                    
                    await bot.send_message(
                        chat_id=chat_id,
                        text=(
                            f"🎯 **Limit Order Executed!**\n"
                            f"🔄 Action: {action.replace('_', ' ').title()}\n"
                            f"💰 Amount: {amount_display}\n"
                            f"📊 Price: {current_price:.2f} USDT/token (target: {target_price:.2f} USDT)\n"
                            f"🔗 [View on BscScan](https://bscscan.com/tx/{tx_hash})"
                        ),
                        parse_mode="Markdown"
                    )
                    
                    # Remove order from list
                    if user_id in active_limit_orders:
                        active_limit_orders[user_id] = [o for o in active_limit_orders[user_id] if o.get("order_id") != order_id]
                        if not active_limit_orders[user_id]:
                            del active_limit_orders[user_id]
                    
                    logger.info(f"Limit order {order_id} executed and removed")
                    break
                    
                except Exception as e:
                    logger.error(f"Limit order execution failed for user {user_id} (Order {order_id}): {e}")
                    try:
                        await bot.send_message(chat_id=chat_id, text=f"❌ Limit order execution failed: {str(e)}")
                    except:
                        pass
                    # Continue checking in case it was a temporary error
            
            # Wait before next check
            try:
                await asyncio.sleep(check_interval)
            except asyncio.CancelledError:
                logger.info(f"Limit order loop cancelled for user {user_id} (Order {order_id})")
                raise
    
    except asyncio.CancelledError:
        logger.info(f"Limit order loop stopped for user {user_id} (Order {order_id})")
        try:
            if user_id in active_limit_orders and active_limit_orders[user_id]:
                active_limit_orders[user_id] = [o for o in active_limit_orders[user_id] if o.get("order_id") != order_id]
                if not active_limit_orders[user_id]:
                    del active_limit_orders[user_id]
        except Exception as e:
            logger.warning(f"Error cleaning up limit order {order_id}: {e}")
        raise
    except Exception as e:
        logger.exception(f"Limit order loop error for user {user_id} (Order {order_id}): {e}")
        try:
            if user_id in active_limit_orders and active_limit_orders[user_id]:
                active_limit_orders[user_id] = [o for o in active_limit_orders[user_id] if o.get("order_id") != order_id]
                if not active_limit_orders[user_id]:
                    del active_limit_orders[user_id]
        except Exception as cleanup_error:
            logger.warning(f"Error cleaning up limit order {order_id}: {cleanup_error}")
        try:
            await bot.send_message(chat_id=chat_id, text=f"❌ Limit order stopped due to error: {str(e)}")
        except:
            pass


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