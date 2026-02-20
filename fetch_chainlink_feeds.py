#!/usr/bin/env python3
"""
Script to fetch all Chainlink Price Feed addresses for BSC (BNB Chain).
This script retrieves feed addresses from Chainlink's data API and updates the CHAINLINK_FEEDS dictionary.
"""

import requests
import json
import re
from typing import Dict, Optional

def load_feeds_from_file() -> Dict[str, str]:
    """Load feeds from chainlink_feeds_bsc.json if it exists"""
    feeds = {}
    try:
        with open("chainlink_feeds_bsc.json", "r") as f:
            feeds = json.load(f)
        print(f"Loaded {len(feeds)} feeds from chainlink_feeds_bsc.json")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"Error loading chainlink_feeds_bsc.json: {e}")
    return feeds

def fetch_all_bsc_feeds() -> Dict[str, str]:
    """
    Fetch all Chainlink price feed addresses for BSC mainnet.
    Returns a dictionary mapping token symbols to feed addresses.
    """
    # Start with feeds from file if available
    feeds = load_feeds_from_file()
    
    # Try to fetch all feeds from Chainlink's API
    base_url = "https://data.chain.link/v1/feeds"
    
    print("Fetching ALL Chainlink feeds from data.chain.link...")
    
    # Try scraping the Chainlink documentation page
    try:
        print("Scraping Chainlink documentation page...")
        doc_url = "https://docs.chain.link/data-feeds/price-feeds/addresses?network=bnb-chain&showDetails=true"
        response = requests.get(doc_url, timeout=20, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        if response.status_code == 200:
            # Try to find addresses in the HTML
            html = response.text
            # Look for addresses in format 0x followed by 40 hex characters
            addresses_found = re.findall(r'0x[a-fA-F0-9]{40}', html, re.IGNORECASE)
            
            # Extract token-address pairs using regex
            # Look for patterns like "BTC/USD" or "BTC-USD" followed by an address
            # Pattern: token name (2-10 chars) followed by /USD or -USD, then address
            patterns = [
                r'([A-Z]{2,10})\s*[/-]\s*USD[^0-9a-fA-F]*?(0x[a-fA-F0-9]{40})',
                r'(0x[a-fA-F0-9]{40})[^A-Z]*?([A-Z]{2,10})\s*[/-]\s*USD',
            ]
            
            for pattern in patterns:
                matches = re.finditer(pattern, html, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    if len(match.groups()) == 2:
                        token_symbol = match.group(1).upper()
                        address = match.group(2)
                        # Validate address format
                        if re.match(r'^0x[a-fA-F0-9]{40}$', address, re.IGNORECASE):
                            if token_symbol not in feeds:
                                feeds[token_symbol] = address
                                print(f"✓ Found {token_symbol}/USD: {address}")
            
            # Also try to find addresses near token names in table structures
            # Look for addresses that appear in table cells
            table_sections = re.findall(r'<t[dh][^>]*>.*?</t[dh]>', html, re.DOTALL | re.IGNORECASE)
            for cell in table_sections:
                addr_match = re.search(r'0x[a-fA-F0-9]{40}', cell, re.IGNORECASE)
                if addr_match:
                    address = addr_match.group(0)
                    # Look for token symbol nearby
                    token_match = re.search(r'\b([A-Z]{2,10})\b', cell, re.IGNORECASE)
                    if token_match:
                        token_symbol = token_match.group(1).upper()
                        # Skip common words
                        if token_symbol not in ['USD', 'USD', 'THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL', 'CAN', 'HER', 'WAS', 'ONE', 'OUR', 'OUT', 'DAY', 'GET', 'HAS', 'HIM', 'HIS', 'HOW', 'ITS', 'MAY', 'NEW', 'NOW', 'OLD', 'SEE', 'TWO', 'WAY', 'WHO', 'BOY', 'DID', 'ITS', 'LET', 'PUT', 'SAY', 'SHE', 'TOO', 'USE']:
                            if token_symbol not in feeds:
                                feeds[token_symbol] = address
                                print(f"✓ Found {token_symbol}/USD: {address}")
    except Exception as e:
        print(f"Scraping failed: {e}")
    
    # Try to fetch from Chainlink's public API that lists all feeds
    try:
        # Try the feeds endpoint with pagination
        print("Fetching all feeds from Chainlink API...")
        page = 1
        per_page = 100
        
        while True:
            try:
                # Try different API endpoints
                api_urls = [
                    f"https://api.chain.link/v1/feeds?network=bsc&network_type=mainnet&page={page}&per_page={per_page}",
                    f"https://data.chain.link/v1/feeds?network=bsc&page={page}&per_page={per_page}",
                ]
                
                found_any = False
                for api_url in api_urls:
                    try:
                        response = requests.get(api_url, timeout=15, headers={
                            'Accept': 'application/json',
                            'User-Agent': 'Mozilla/5.0'
                        })
                        
                        if response.status_code == 200:
                            data = response.json()
                            
                            # Handle different response formats
                            feed_list = []
                            if isinstance(data, list):
                                feed_list = data
                            elif isinstance(data, dict):
                                if 'data' in data:
                                    feed_list = data['data']
                                elif 'feeds' in data:
                                    feed_list = data['feeds']
                                elif 'results' in data:
                                    feed_list = data['results']
                            
                            if feed_list:
                                print(f"Page {page}: Found {len(feed_list)} feeds")
                                for feed_info in feed_list:
                                    try:
                                        if isinstance(feed_info, dict):
                                            # Try different field names
                                            pair_name = None
                                            address = None
                                            
                                            if 'name' in feed_info:
                                                pair_name = feed_info['name']
                                            elif 'pair' in feed_info:
                                                pair_name = feed_info['pair']
                                            elif 'symbol' in feed_info:
                                                pair_name = feed_info['symbol'] + '-usd'
                                            
                                            if 'addresses' in feed_info:
                                                if isinstance(feed_info['addresses'], dict) and 'standard' in feed_info['addresses']:
                                                    address = feed_info['addresses']['standard']
                                                elif isinstance(feed_info['addresses'], str):
                                                    address = feed_info['addresses']
                                            
                                            if 'address' in feed_info:
                                                address = feed_info['address']
                                            
                                            if pair_name and address:
                                                token_symbol = pair_name.split('-')[0].upper()
                                                if token_symbol not in feeds:
                                                    feeds[token_symbol] = address
                                                    print(f"✓ Found {token_symbol}/USD: {address}")
                                                    found_any = True
                                    except Exception as e:
                                        continue
                                
                                # Check if there are more pages
                                if isinstance(data, dict):
                                    if 'has_more' in data and data['has_more']:
                                        page += 1
                                        continue
                                    elif 'next' in data and data['next']:
                                        page += 1
                                        continue
                                
                                if not found_any:
                                    break
                                
                                if found_any:
                                    page += 1
                                    continue
                    except Exception as e:
                        continue
                
                if not found_any:
                    break
                    
            except Exception as e:
                print(f"Error fetching page {page}: {e}")
                break
                
    except Exception as e:
        print(f"Note: Could not fetch feeds list from API: {e}")
        print("Trying comprehensive token list...")
    
    # Load tokens from tokens.json to find their Chainlink feeds
    try:
        with open("tokens.json", "r") as f:
            tokens_data = json.load(f)
        
        print(f"\nChecking feeds for {len(tokens_data)} tokens from tokens.json...")
        for symbol, address in tokens_data.items():
            if symbol.upper() in feeds:
                continue  # Already found
            
            pair_name = f"{symbol.lower()}-usd"
            try:
                url = f"{base_url}/bsc/mainnet/{pair_name}"
                response = requests.get(url, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, dict) and 'addresses' in data and 'standard' in data['addresses']:
                        feed_address = data['addresses']['standard']
                        feeds[symbol.upper()] = feed_address
                        print(f"✓ Found {symbol.upper()}/USD: {feed_address}")
            except Exception as e:
                # Silently skip if feed doesn't exist
                pass
    except FileNotFoundError:
        print("tokens.json not found, skipping...")
    except Exception as e:
        print(f"Error loading tokens.json: {e}")
    
    # Comprehensive list of ALL possible tokens that might have Chainlink feeds on BSC
    # This is an extensive list covering major cryptocurrencies, DeFi tokens, and more
    all_possible_tokens = [
        # Major cryptocurrencies
        "bnb", "btc", "btcb", "eth", "usdt", "busd", "usdc", "dai",
        # DeFi tokens
        "cake", "uni", "aave", "sushi", "comp", "mkr", "crv", "snx", "yfi", "bal", "ren", "knc",
        # Layer 1 & Layer 2
        "ada", "dot", "link", "matic", "avax", "sol", "near", "ftm", "algo", "atom", "luna", "terra",
        # Other popular tokens
        "xrp", "doge", "shib", "ltc", "bch", "xlm", "eos", "trx", "fil", "icp", "xmr", "etc", 
        "zec", "dash", "xem", "vet", "theta", "egld", "hbar", "xtz", "xdc", "qnt",
        # Gaming & Metaverse
        "axs", "sand", "mana", "enj", "gala", "chz", "flow", "waxp", "ilv", "rndr",
        # Stablecoins
        "tusd", "usdp", "frax", "lusd", "mim", "usdd",
        # BSC native tokens
        "alpaca", "auto", "belt", "bunny", "venus", "xvs", "pancake", "bsw", "tlos",
        # Additional tokens
        "aave", "bat", "bch", "bnb", "btc", "busd", "comp", "dai", "doge", "dot", "eos", 
        "etc", "eth", "fil", "link", "ltc", "matic", "mkr", "shib", "snx", "trx", "uni", 
        "usdc", "usdt", "xlm", "xrp", "xtz", "yfi", "zec",
    ]
    
    # Remove duplicates while preserving order
    seen = set()
    unique_tokens = []
    for token in all_possible_tokens:
        token_upper = token.upper()
        if token_upper not in seen:
            seen.add(token_upper)
            unique_tokens.append(token)
    
    print(f"\nSystematically checking {len(unique_tokens)} possible token feeds...")
    print("This may take a while, please wait...")
    found_count = 0
    
    import concurrent.futures
    
    def check_token_feed(token):
        """Check if a token has a Chainlink feed"""
        if token.upper() in feeds:
            return None
            
        pair_name = f"{token.lower()}-usd"
        try:
            url = f"{base_url}/bsc/mainnet/{pair_name}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict) and 'addresses' in data and 'standard' in data['addresses']:
                    address = data['addresses']['standard']
                    token_symbol = token.upper()
                    return (token_symbol, address)
        except:
            pass
        return None
    
    # Check feeds in parallel (10 at a time)
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_token = {executor.submit(check_token_feed, token): token for token in unique_tokens}
        
        for future in concurrent.futures.as_completed(future_to_token):
            result = future.result()
            if result:
                token_symbol, address = result
                feeds[token_symbol] = address
                found_count += 1
                print(f"✓ Found {token_symbol}/USD: {address}")
    
    print(f"\nFound {found_count} additional feeds from comprehensive list")
    
    # Also add known addresses from documentation
    known_feeds = {
        "BTC": "0x264990fbd0A4796A3E3d8E37C4d5F87a3aCa5Ebf",
        "BTCB": "0x264990fbd0A4796A3E3d8E37C4d5F87a3aCa5Ebf",
        "ETH": "0x9ef1B8c0E4F7dc8bF5719Ea496883DC6401d5b2e",
        "BNB": "0x0567F2323251f0Aab15c8dFb1967E4e8A7D42aeE",
        "USDT": "0xB97Ad0E74fa7d920791E90258A6E2085088b4320",
        "CAKE": "0xB6064eD41d4f67e353768aA239cA86f4F73665a1",
        "BUSD": "0xcBb98864Ef56E9042e7d2efEfE41dbEcFd1D86F1",
    }
    
    # Merge known feeds (they take precedence)
    feeds.update(known_feeds)
    
    return feeds


def update_main_py(feeds: Dict[str, str]):
    """
    Update the CHAINLINK_FEEDS dictionary in main.py
    """
    main_py_path = "main.py"
    
    try:
        with open(main_py_path, "r") as f:
            content = f.read()
        
        # Find the CHAINLINK_FEEDS dictionary
        pattern = r'CHAINLINK_FEEDS: Dict\[str, str\] = \{([^}]+)\}'
        match = re.search(pattern, content, re.DOTALL)
        
        if match:
            # Build new dictionary string
            feeds_str = "{\n"
            for symbol, address in sorted(feeds.items()):
                feeds_str += f'    "{symbol}": "{address}",  # {symbol}/USD\n'
            feeds_str += "}"
            
            # Replace the dictionary
            new_content = content[:match.start()] + f"CHAINLINK_FEEDS: Dict[str, str] = {feeds_str}" + content[match.end():]
            
            with open(main_py_path, "w") as f:
                f.write(new_content)
            
            print(f"\n✓ Updated {main_py_path} with {len(feeds)} feeds")
        else:
            print("✗ Could not find CHAINLINK_FEEDS dictionary in main.py")
            
    except Exception as e:
        print(f"✗ Error updating main.py: {e}")


if __name__ == "__main__":
    print("Fetching all Chainlink Price Feeds for BSC...\n")
    feeds = fetch_all_bsc_feeds()
    
    # Save to JSON file for future reference
    try:
        with open("chainlink_feeds_bsc.json", "w") as f:
            json.dump(feeds, f, indent=2)
        print(f"\n✓ Saved {len(feeds)} feeds to chainlink_feeds_bsc.json")
    except Exception as e:
        print(f"Warning: Could not save to JSON file: {e}")
    
    print(f"\nFound {len(feeds)} feeds:")
    for symbol, address in sorted(feeds.items()):
        print(f"  {symbol}: {address}")
    
    print("\nUpdating main.py...")
    update_main_py(feeds)
    
    print("\nDone!")
    print("\nNote: Chainlink currently has limited feeds on BSC.")
    print("If you know of additional feeds, add them to chainlink_feeds_bsc.json and run this script again.")
