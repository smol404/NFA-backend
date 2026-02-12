# 🤖 BAP Agents NFA - Telegram Bot Backend

<div align="center">

**Intelligent Telegram bot for managing blockchain agents on BNB Smart Chain**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Telegram](https://img.shields.io/badge/Telegram-Bot-blue.svg)](https://telegram.org/)
[![BSC](https://img.shields.io/badge/BSC-Mainnet-yellow.svg)](https://www.bnbchain.org/)
[![Web3](https://img.shields.io/badge/Web3.py-Latest-green.svg)](https://web3py.readthedocs.io/)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Agent Types](#-agent-types)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Usage Guide](#-usage-guide)
- [API Reference](#-api-reference)
- [Smart Contracts](#-smart-contracts)
- [Architecture](#-architecture)
- [Troubleshooting](#-troubleshooting)

---

## 🎯 Overview

BAP Agents NFA is a sophisticated Telegram bot that enables users to interact with blockchain agents on the BNB Smart Chain (BSC). The bot supports multiple agent types, each with specialized capabilities for different blockchain operations.

### Key Capabilities

- 🔐 **Secure Authentication** - Access code-based agent authentication
- 💬 **Echo Agent** - Simple message broadcasting to blockchain
- 📈 **Trader Agent** - AI-powered token trading with natural language
- 💰 **Balance Checking** - Real-time token and BNB balance queries
- 🔗 **Smart Contract Integration** - Direct interaction with BSC smart contracts

---

## ✨ Features

### Core Features

- ✅ **Multi-Agent Support** - Echo (Type A) and Trader (Type B) agents
- ✅ **Natural Language Processing** - Understand trading commands in plain English
- ✅ **Blockchain Integration** - Direct BSC smart contract interaction
- ✅ **Transaction Management** - Automatic gas estimation and transaction signing
- ✅ **Balance Queries** - Check balances without sending transactions
- ✅ **Error Handling** - Comprehensive error messages and recovery
- ✅ **Session Management** - Persistent user sessions and context

### Trading Features

- 🛒 **Buy Tokens** - Purchase tokens with BNB
- 💸 **Sell Tokens** - Sell tokens for BNB
- 💵 **Check Balance** - Query token and BNB balances
- 📊 **Price Queries** - Get token prices (via smart contract)
- ⚡ **Slippage Protection** - Configurable slippage tolerance
- 🔄 **Automatic Deposits** - Auto-deposit BNB to agent vault when needed

---

## 🤖 Agent Types

### Type A: Echo Agent

**Purpose:** Simple message broadcasting to blockchain

**Features:**
- Send any text message to blockchain
- Messages are stored on-chain via smart contract
- Perfect for logging, announcements, or simple data storage

**Usage:**
```
Authenticate: A-123
Send: "Hello World"
Result: Message stored on blockchain with transaction hash
```

### Type B: Trader Agent

**Purpose:** AI-powered token trading on BSC

**Features:**
- Natural language trading commands
- Automatic token address resolution
- Balance checking (on-chain queries)
- Buy/Sell operations
- Smart contract vault management

**Usage:**
```
Authenticate: B-456
Commands:
- "Buy 0.001 BNB of CAKE"
- "Check balance of 0x..."
- "Sell token 0x... with 0.001"
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.11+**
- **Telegram Bot Token** (from [@BotFather](https://t.me/BotFather))
- **BSC Wallet** with BNB for gas fees
- **Private Key** (keep it secure!)

### Installation

#### 1. Clone Repository

```bash
git clone <repository-url>
cd BAP_offchain
```

#### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

**For macOS with Apple Silicon:**
```bash
python3 -m pip install --user --break-system-packages -r requirements.txt
```

#### 3. Configure Environment

```bash
cp env.example .env
```

Edit `.env` with your credentials:
```env
TELEGRAM_BOT_TOKEN=your_telegram_bot_token_here
PRIVATE_KEY=your_private_key_without_0x
CLAUDE_API_KEY=your_anthropic_api_key_here
```

#### 4. Start the Bot

**Option A: Using startup script**
```bash
chmod +x start_bot.sh
./start_bot.sh
```

**Option B: Direct execution**
```bash
python3 main.py
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `TELEGRAM_BOT_TOKEN` | Telegram bot token from @BotFather | ✅ Yes |
| `PRIVATE_KEY` | BSC wallet private key (without 0x) | ✅ Yes |
| `CLAUDE_API_KEY` | Anthropic Claude API key for AI | ✅ Yes |

### Network Configuration

**Mainnet (Default):**
```python
RPC_URL = "https://bsc-dataseed.binance.org/"
```

**Testnet:**
```python
RPC_URL = "https://data-seed-prebsc-1-s1.binance.org:8545/"
```

### Smart Contract Addresses

- **Echo Agent:** `0xC0AD345393752506Eb63A627a124646645f8267f`
- **Trader Agent:** `0x424621D3Efa7bB7214D11f95B6Aa04D9CE6AEBeF`

---

## 📖 Usage Guide

### Authentication

1. Start a conversation with your bot on Telegram
2. Send your access code:
   - **Echo Agent:** `A-123` (where 123 is your token ID)
   - **Trader Agent:** `B-456` (where 456 is your token ID)

### Echo Agent Commands

```
A-123                    # Authenticate as Echo Agent
Hello World              # Send message to blockchain
```

**Response:**
```
✅ Message sent!
Hash: 0x...
🔗 View on BscScan: https://bscscan.com/tx/0x...
```

### Trader Agent Commands

#### Buy Token

```
B-456                    # Authenticate as Trader Agent
Buy 0.001 BNB of CAKE    # Natural language command
```

**Or with token address:**
```
Buy 0.001 BNB of token 0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82
```

#### Check Balance

```
Check balance of 0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82
```

**Response:**
```
💰 Balance Check Results:

🟡 BNB Balance: 0.028212 BNB
🪙 Token Balance (0x0E09FaBB...): 0.000000
```

#### Sell Token

```
Sell token 0x... with 0.001 BNB
```

---

## 🔌 API Reference

### Smart Contract Function

**Function:** `handleAction(uint256 tokenId, string action, bytes payload)`

**Parameters:**
- `tokenId` - Agent token ID (from access code)
- `action` - Action string (e.g., "buy_token", "check_balance")
- `payload` - ABI-encoded parameters

**Returns:**
- `success` - Boolean indicating success
- `result` - Bytes containing result data (for queries)

### Action Types

#### `buy_token` / `sell_token`

**Payload Encoding:**
```python
abi_encode(
    ['address', 'uint256', 'uint256'],
    [token_address, amount_wei, slippage_bps]
)
```

**Parameters:**
- `token_address` - Token contract address (20 bytes)
- `amount_wei` - Amount in BNB (wei)
- `slippage_bps` - Slippage in basis points (default: 0)

#### `check_balance`

**Payload Encoding:**
```python
abi_encode(
    ['address'],
    [token_address]
)
```

**Result Decoding:**
```python
bnb_balance, token_balance = abi_decode(
    ['uint256', 'uint256'],
    result_bytes
)
```

---

## 🏗️ Smart Contracts

### Contract Addresses

| Agent Type | Contract Address | Network |
|------------|-----------------|---------|
| Echo | `0xC0AD345393752506Eb63A627a124646645f8267f` | BSC Mainnet |
| Trader | `0x424621D3Efa7bB7214D11f95B6Aa04D9CE6AEBeF` | BSC Mainnet |

### Key Functions

#### `handleAction`

```solidity
function handleAction(
    uint256 tokenId,
    string calldata action,
    bytes calldata payload
) external onlyAuthorized whenNotPaused nonReentrant 
returns (bool success, bytes memory result);
```

#### `depositBNB` (Trader Agent)

```solidity
function depositBNB(uint256 tokenId) external payable;
```

#### `agentBNBBalance` (View)

```solidity
mapping(uint256 => uint256) public agentBNBBalance;
```

---

## 🏛️ Architecture

### System Components

```
┌─────────────┐
│   Telegram  │
│     Bot     │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Python    │
│   Backend   │
│  (main.py)  │
└──────┬──────┘
       │
       ├──► Web3.py ──► BSC Network
       │
       ├──► Anthropic ──► AI Processing
       │
       └──► Smart Contract ──► handleAction()
```

### Data Flow

1. **User Input** → Telegram message
2. **Authentication** → Access code validation
3. **Intent Detection** → Natural language processing
4. **Parameter Extraction** → Token address, amount, etc.
5. **Payload Encoding** → ABI encoding for smart contract
6. **Transaction** → Sign and send to BSC
7. **Response** → Transaction hash or query result

### Session Management

```python
sessions = {
    user_id: {
        "type": "A" | "B",
        "tokenId": int,
        "data": {
            "action": str,
            "token": str,
            "amount": str
        }
    }
}
```

---

## 📁 Project Structure

```
BAP_offchain/
├── main.py              # Main bot application
├── requirements.txt     # Python dependencies
├── env.example         # Environment template
├── .env                # Your credentials (not in git)
├── .gitignore         # Git ignore rules
├── start_bot.sh       # Startup script
├── tokens.json        # Token whitelist (optional)
└── README.md          # This file
```

---

## 🔧 Troubleshooting

### Bot Not Responding

**Problem:** Bot doesn't respond to messages

**Solutions:**
- Verify bot token is correct in `.env`
- Check bot is running: `ps aux | grep main.py`
- Restart bot: `./start_bot.sh`
- Check for multiple instances (409 Conflict error)

---

### Transaction Failures

**Problem:** "Insufficient BNB balance"

**Solutions:**
1. **Check Agent Vault Balance:**
   - The contract uses internal vault (`agentBNBBalance`)
   - Not the EOA wallet balance

2. **Auto-Deposit:**
   - Bot automatically deposits from wallet to vault
   - Ensure wallet has enough for trade + gas

3. **Manual Deposit:**
   - Use contract `depositBNB(tokenId)` function
   - Send BNB to contract address

**Error Message:**
```
❌ Insufficient BNB balance in the agent wallet
💰 Current wallet balance: 0.028212 BNB
📍 Wallet: 0xFA20ed50...063c782b
```

---

### Gas Estimation Failed

**Problem:** Gas estimation errors

**Solutions:**
- Verify contract address is correct
- Check RPC endpoint is accessible
- Ensure contract function exists
- Verify payload encoding is correct

---

### AI Not Understanding Commands

**Problem:** Bot doesn't understand trading requests

**Solutions:**
- Use clear format: "Buy 0.001 BNB of TOKEN"
- Include token address if token not in whitelist
- Check Claude API key is valid
- Review error logs for API issues

**Example Formats:**
```
✅ Good: "Buy CAKE with 0.001 BNB"
✅ Good: "Buy 0.001 BNB of 0x..."
✅ Good: "Check balance of CAKE"
❌ Bad: "I want cake"
```

---

### Port Conflicts (macOS)

**Problem:** Port 5000 already in use

**Solution:**
```bash
# Disable AirPlay Receiver
System Preferences → General → AirDrop & Handoff
→ Uncheck "AirPlay Receiver"
```

---

### Import Errors

**Problem:** `ModuleNotFoundError`

**Solutions:**
```bash
# Reinstall dependencies
pip install -r requirements.txt

# For macOS
python3 -m pip install --user --break-system-packages -r requirements.txt
```

---

## 🔒 Security Best Practices

### ⚠️ Critical Security Notes

1. **Never Commit `.env`**
   - Add `.env` to `.gitignore`
   - Never share private keys

2. **Use Dedicated Wallet**
   - Don't use main wallet
   - Limit funds in bot wallet
   - Monitor transactions regularly

3. **Protect Private Key**
   - Store securely
   - Use environment variables
   - Never log or print private keys

4. **API Keys**
   - Rotate keys regularly
   - Use separate keys for dev/prod
   - Monitor API usage

---

## 📊 Monitoring & Logging

### Log Levels

- **INFO** - Normal operations
- **WARNING** - Non-critical issues
- **ERROR** - Errors requiring attention

### Key Logs

```
Transaction parameters logged:
- Action, Token, Amount, Slippage
- Token ID, Encoded Payload
- Transaction: from, to, gas, gasPrice, nonce, value, data
```

### Health Checks

Use `/status` command in Telegram to check:
- BSC connection status
- Wallet balance
- Contract accessibility

---

## 🚀 Advanced Usage

### Custom Token Whitelist

Edit `tokens.json`:
```json
{
  "CAKE": "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82",
  "BNB": "0x..."
}
```

### Direct Contract Calls

For advanced users, you can call contract functions directly:

```python
from web3 import Web3
from eth_abi import encode

# Encode payload
payload = encode(
    ['address', 'uint256', 'uint256'],
    [token_address, amount_wei, slippage_bps]
)

# Call handleAction
result = contract.functions.handleAction(
    token_id,
    "buy_token",
    payload
).call()
```

---

## 📝 License

This project is provided as-is for development purposes.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## 📞 Support

For issues or questions:
- Check [Troubleshooting](#-troubleshooting) section
- Review transaction logs
- Check BscScan for transaction details
- Verify smart contract status

---

<div align="center">

**Built for the BAP (Blockchain Agent Protocol) ecosystem**

**Made with ❤️ for decentralized agent management**

</div>
