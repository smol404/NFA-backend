import os
import re
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
# The Smart Contract Address
CONTRACT_ADDRESS = "0x424621D3Efa7bB7214D11f95B6Aa04D9CE6AEBeF" 

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

contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)

# --- SESSION STORAGE ---
# Format: { user_id: { "type": "A"|"B", "tokenId": int, "data": { "action": str, "token": str, "amount": str } } }
sessions: Dict[int, Any] = {}

# --- HELPER FUNCTIONS ---

def extract_intent(text: str) -> Optional[str]:
    """
    Determines if the user wants to BUY, SELL, or CHECK BALANCE based on keywords.
    """
    text_lower = text.lower()
    
    # Keywords for BUY
    if any(word in text_lower for word in ["buy", "swap", "purchase", "ape", "long"]):
        return "buy_token"
    
    # Keywords for SELL
    if any(word in text_lower for word in ["sell", "dump", "exit", "short"]):
        return "sell_token"
    
    # Keywords for CHECK BALANCE
    if any(word in text_lower for word in ["balance", "check balance", "check", "what is the balance", "show balance"]):
        return "check_balance"
        
    return None

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
        "Please authenticate using your access code format:\n"
        "👉 **A-XXX** (for Echo Agent)\n"
        "👉 **B-XXX** (for Trader Agent)\n\n"
        "Example: `B-123`"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text.strip()

    # 1. AUTHENTICATION (If user is not logged in)
    if user_id not in sessions:
        # Regex to match A-123 or B-456
        match = re.match(r"^([AB])-(\d+)$", text.upper())
        if match:
            agent_type, token_id = match.groups()
            sessions[user_id] = {
                "type": agent_type, 
                "tokenId": int(token_id), 
                "data": {"action": None, "token": None, "amount": None}
            }
            
            role_name = "Echo" if agent_type == "A" else "Trader"
            await update.message.reply_text(
                f"✅ Authenticated as **{role_name}** (ID: {token_id}).\n"
                f"{'Send any text to echo.' if agent_type == 'A' else 'Tell me what to buy, sell, or check balance.'}"
            )
        else:
            await update.message.reply_text("❌ Invalid format. Please send a code like `A-1` or `B-10`.")
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
            tx_hash = send_transaction(session["tokenId"], text, payload)
            await update.message.reply_text(f"✅ Message sent!\nHash: {tx_hash}")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
        return

    # ---------------------------------------------------------
    # AGENT TYPE B: TRADER (The Logic You Requested)
    # ---------------------------------------------------------
    elif session["type"] == "B":
        data = session["data"]
        
        # --- STEP 1: UNDERSTAND INTENT (BUY/SELL/CHECK_BALANCE) ---
        # If we don't know the action yet, try to find it
        if not data["action"]:
            intent = extract_intent(text)
            if intent:
                data["action"] = intent
            # If still no action and previous data is empty, we must ask
            elif not data["token"] and not data["amount"]:
                await update.message.reply_text("🤖 Do you want to **Buy**, **Sell**, or **Check Balance**?")
                return

        # --- STEP 2: EXTRACT PARAMETERS (Token & Amount) ---
        # Try to extract address if missing
        if not data["token"]:
            address = extract_address(text)
            if address:
                data["token"] = address

        # Try to extract amount if missing (only for buy/sell, not for check_balance)
        if data["action"] != "check_balance" and not data["amount"]:
            amount = extract_amount(text, session["tokenId"])
            if amount:
                data["amount"] = amount

        # --- STEP 3: CHECK FOR MISSING INFO ---
        missing_fields = []
        if not data["action"]: 
            missing_fields.append("Action (Buy/Sell/Check Balance)")
        
        if not data["token"]: 
            missing_fields.append("Token Address (0x...)")
        
        # Amount is only required for buy/sell, not for check_balance
        if data["action"] in ["buy_token", "sell_token"] and not data["amount"]:
            missing_fields.append("Amount (in BNB)")

        # If anything is missing, ask the user specifically for it
        if missing_fields:
            current_status = (
                f"📝 **Current Status:**\n"
                f"• Action: {data['action'] or '❓'}\n"
                f"• Token: {data['token'] or '❓'}\n"
            )
            if data["action"] in ["buy_token", "sell_token"]:
                current_status += f"• Amount: {data['amount'] or '❓'}\n"
            current_status += "\n"
            
            await update.message.reply_text(
                f"{current_status}"
                f"❌ I am missing: **{', '.join(missing_fields)}**.\n"
                f"Please provide the missing information."
            )
            return

        # --- STEP 4: EXECUTE ACTION ---
        # Prepare message based on action type
        if data["action"] == "check_balance":
            await update.message.reply_text(
                f"✅ **Checking balance...**\n"
                f"🪙 Token: {data['token']}\n\n"
                f"⏳ Querying contract..."
            )
        else:
            await update.message.reply_text(
                f"✅ **Ready to execute!**\n"
                f"🚀 {data['action'].upper().replace('_', ' ')}\n"
                f"🪙 Token: {data['token']}\n"
                f"💰 Amount: {data['amount']} BNB\n\n"
                f"⏳ Encoding payload and sending transaction..."
            )

        try:
            # 1. Format the data for the Smart Contract
            token_address = w3.to_checksum_address(data["token"])
            
            # 2. Calculate Payload based on action type
            if data["action"] == "check_balance":
                # For check_balance, payload is just the token address
                # Solidity: abi.encode(address)
                payload = abi_encode(
                    ['address'],  # Types
                    [token_address]  # Values
                )
            else:
                # For buy_token and sell_token, payload includes amount and slippage
                # Solidity: abi.encode(token_address, amountBNB, slippageBps)
                amount_wei = w3.to_wei(float(data["amount"]), 'ether')
                slippage_bps = 0  # Default slippage (0%)
                payload = abi_encode(
                    ['address', 'uint256', 'uint256'],  # Types
                    [token_address, amount_wei, slippage_bps]  # Values
                )

            # 3. Call the Smart Contract function
            # function handleAction(uint256 tokenId, string action, bytes payload)
            if data["action"] == "check_balance":
                # For check_balance, we use call() to get the result without sending a transaction
                bnb_balance, token_balance = call_check_balance(session["tokenId"], payload)
                
                # Format balances for display
                bnb_balance_ether = w3.from_wei(bnb_balance, 'ether')
                token_balance_formatted = format_token_balance(token_balance, token_address)
                
                await update.message.reply_text(
                    f"💰 **Balance Check Results:**\n\n"
                    f"🟡 BNB Balance: {bnb_balance_ether:.6f} BNB\n"
                    f"🪙 Token Balance ({token_address[:10]}...): {token_balance_formatted}\n"
                )
            else:
                # For buy/sell, send actual transaction
                tx_hash = send_transaction(session["tokenId"], data["action"], payload)

                await update.message.reply_text(
                    f"🎉 **Transaction Successful!**\n"
                    f"🔗 [View on BscScan](https://bscscan.com/tx/{tx_hash})"
                )

            # 4. Reset session data for the next action
            session["data"] = {"action": None, "token": None, "amount": None}

        except Exception as e:
            logger.error(f"Transaction failed: {e}")
            await update.message.reply_text(f"❌ Transaction failed: {str(e)}")


def call_check_balance(token_id: int, payload_bytes: bytes) -> tuple:
    """
    Calls handleAction with check_balance action and decodes the result.
    Returns (bnb_balance, token_balance) as integers (wei).
    """
    func = contract.functions.handleAction(token_id, "check_balance", payload_bytes)
    
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


def send_transaction(token_id: int, action_str: str, payload_bytes: bytes) -> str:
    """
    Constructs and sends the transaction to the BSC blockchain.
    """
    # 1. Prepare transaction data
    func = contract.functions.handleAction(token_id, action_str, payload_bytes)
    
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