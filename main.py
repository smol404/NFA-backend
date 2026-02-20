import os
import re
import json
import logging
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
    """Contract instance for the given agent type (A = Echo, B = Trader)."""
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
# Format: { user_id: { "type": "A"|"B", "tokenId": int, "data": { "action": str, "token": str, "amount": str } } }
sessions: Dict[int, Any] = {}

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
    Uses Claude to understand user intent. agent_type is "A" or "B" (passed so Claude knows allowed actions).
    Returns either {"understood": True, "action": str, "token": str, "amount": str|None} or {"understood": False, "message": str}.
    """
    api_key = os.getenv("CLAUDE_API_KEY")
    if not api_key:
        return {"understood": False, "message": "Bot is not configured with an API key for understanding messages."}

    allowed = (
        "Only allowed action: echo_message (write the user's message on-chain)."
        if agent_type == "A"
        else "Allowed actions: buy_token, sell_token, check_balance. For buy_token/sell_token you need a token (BSC address 0x... or symbol like CAKE, BNB) and an amount in BNB. For check_balance only the token."
    )
    system = (
        f"You are a blockchain bot. Agent type is {agent_type}. {allowed}\n"
        "Understand the user in ANY language (French, English, slang, etc.): e.g. 'achete 0.001 bnb de cake' = buy 0.001 BNB of CAKE.\n"
        "Token: accept symbol (CAKE, cake, BNB...) or full address 0x.... If the user only gives a name/symbol you don't recognize as a standard token, set understood: false and ask for the token address (0x...) in the same language as the user.\n"
        "Reply ONLY with a single JSON object, no markdown or extra text. "
        "If you understand: {\"understood\": true, \"action\": \"buy_token\"|\"sell_token\"|\"check_balance\", \"token\": \"...\", \"amount\": \"...\" (only for buy/sell)}\n"
        "If not: {\"understood\": false, \"message\": \"Short reply in the user's language (e.g. ask for token address or rephrase).\"}"
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
            return {
                "understood": True,
                "action": (data.get("action") or "").strip(),
                "token": (data.get("token") or "").strip() or None,
                "amount": (data.get("amount") or "").strip() or None,
            }
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
        "👉 **B-XXX** — Trader (buy, sell, check balance)\n\n"
        "Example: `A-1` or `B-123`"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text.strip()

    # 1. AUTHENTICATION (If user is not logged in)
    if user_id not in sessions:
        match = re.match(r"^([AB])-(\d+)$", text.upper())
        if match:
            code_type, token_id = match.groups()
            sessions[user_id] = {
                "type": code_type,
                "tokenId": int(token_id),
                "data": {"action": None, "token": None, "amount": None},
            }
            role_name = "Echo" if code_type == "A" else "Trader"
            await update.message.reply_text(
                f"✅ Authenticated as **{role_name}** (ID: {token_id}).\n"
                f"{'Send any text to write on-chain.' if code_type == 'A' else 'Tell me what to buy, sell, or check balance (e.g. "Buy 0.001 BNB of CAKE").'}"
            )
        else:
            await update.message.reply_text("❌ Invalid format. Send a code like `A-1` or `B-123`.")
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
    Formats token balance. For now, displays in wei format.
    TODO: Could fetch token decimals from ERC20 contract for better formatting.
    """
    # Try to convert to a more readable format
    # Most tokens use 18 decimals, but we'll display raw for now
    if balance_wei == 0:
        return "0"
    
    # Try with 18 decimals (common case)
    try:
        balance_formatted = balance_wei / (10 ** 18)
        if balance_formatted < 0.000001:
            return f"{balance_wei} (raw)"
        return f"{balance_formatted:.6f}"
    except:
        return str(balance_wei)


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