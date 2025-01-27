import os
import sys
import subprocess
import warnings
import importlib.util
import logging
import asyncio
import aiohttp
import re
import time
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime, timezone, timedelta

# Set up logging configuration with log file named 'adblock_rule_downloader.log' and log level INFO
logging.basicConfig(filename='adblock_rule_downloader.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def install_packages(packages):
    # Check and install the required Python packages
    for package in packages:
        if importlib.util.find_spec(package) is None:
            logging.info(f"Package '{package}' is not installed. Installing...")
            subprocess.run([sys.executable, "-m", "pip", "install", package], check=True)
            logging.info(f"Package '{package}' installed successfully.")
        else:
            logging.info(f"Package '{package}' is already installed.")

# Ensure the required package list is installed
required_packages = ["aiohttp", "urllib3", "certifi"]

install_packages(required_packages)

warnings.simplefilter('ignore', InsecureRequestWarning)

# Check if the line is a valid rule by removing comments and blank lines
def is_valid_rule(line):
    line = line.strip()
    if not line or line.startswith(('!', '#', '[', ';', '//', '/*', '*/')):
        return False
    return True

# Check if it's an IPv4 mapping rule
def is_ip_domain_mapping(line):
    return re.match(r'^\d{1,3}(\.\d{1,3}){3}\s+\S+', line) is not None

# Check if it's a pure IPv4 address
def is_ip_address(line):
    return re.match(r'^\d{1,3}(\.\d{1,3}){3}$', line) is not None

# Check if it's an IPv6 mapping rule
def is_ipv6_domain_mapping(line):
    return re.match(r'^[\da-fA-F:]+\s+\S+', line) is not None

# Check if it's a pure IPv6 address
def is_ipv6_address(line):
    return re.match(r'^[\da-fA-F:]+$', line) is not None

# Check if it's a pure domain name
def is_domain(line):
    # Check if it is a valid domain name
    domain_pattern = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    return re.match(domain_pattern, line) is not None

# Process each rule line and convert it to a unified format
def process_line(line):
    line = line.strip()
    
    if not is_valid_rule(line):
        return None

    # Process IPv4 address mapping: 0.0.0.0 and 127.0.0.1
    if line.startswith('0.0.0.0') or line.startswith('127.0.0.1'):
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1].split('#')[0].strip()
            return f"||{domain}^"
    
    # Process IPv6 address mapping: :: and ::1
    if line.startswith('::') or line.startswith('::1'):
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1].split('#')[0].strip()
            return f"||{domain}^"

    # Ignore other IPv4 and IPv6 domain mappings
    if is_ip_domain_mapping(line) or is_ipv6_domain_mapping(line):
        return None

    # Process pure IPv4 address
    if is_ip_address(line):
        return f"||{line}^"
    
    # Process pure IPv6 address
    if is_ipv6_address(line):
        return f"||{line}^"

    # Process Dnsmasq rules, address= and server=, adding support for IPv4 and IPv6
    if line.startswith('address='):
        parts = line.split('=')  
        if len(parts) == 3:
            domain = parts[1].strip()
            target_ip = parts[2].strip()
            if target_ip in ['127.0.0.1', '0.0.0.0', '::1', '::']:
                return f"||{domain}^"

    elif line.startswith('server='):
        parts = line.split('=', 1)
        if len(parts) == 2:
            server_info = parts[1].split('/')
            if len(server_info) == 3:
                domain = server_info[1].strip()
                target_ip = server_info[2].strip()
                if target_ip in ['127.0.0.1', '0.0.0.0', '::1', '::']:
                    return f"||{domain}^"
    
    # Process pure domain
    if is_domain(line):
        return f"||{line}^"
    
    return line


# Asynchronously download filter rules
async def download_filter(session, url, retries=5):
    rules = set()
    attempt = 0
    while attempt < retries:
        try:
            async with session.get(url, ssl=False) as response:
                logging.info(f"Downloading from {url}, attempt {attempt + 1}")
                if response.status == 200:
                    logging.info(f"Successfully downloaded from {url}")
                    text = await response.text()
                    lines = text.splitlines()
                    for line in lines:
                        line = line.strip()
                        if is_valid_rule(line):
                            processed_line = process_line(line)
                            if processed_line is not None:
                                rules.add(processed_line)
                    break
                else:
                    logging.error(f"Failed to download from {url} with status code {response.status}")
        except Exception as e:
            logging.error(f"Error downloading {url}: {e}")
        attempt += 1
        if attempt < retries:
            wait_time = 2 ** attempt
            logging.info(f"Retrying in {wait_time} seconds...")
            await asyncio.sleep(wait_time)
        else:
            logging.error(f"Max retries reached for {url}")
    return rules

# Asynchronously download multiple filter rules
async def download_filters(urls):
    async with aiohttp.ClientSession() as session:
        tasks = [download_filter(session, url) for url in urls]
        all_rules = set()
        for future in asyncio.as_completed(tasks):
            rules = await future
            all_rules.update(rules)
    return all_rules

# Validate the rules' validity
def validate_rules(rules):
    validated_rules = set()
    for rule in rules:
        if is_valid_rule(rule):
            validated_rules.add(rule)
    return validated_rules

# Write rules to a file
def write_rules_to_file(rules, save_path):
    now = datetime.now(timezone(timedelta(hours=8)))
    timestamp = now.strftime('%Y-%m-%d %H:%M:%S %Z')
    header = f"""
!Title: Adblock-Rule-Collection
!Description: An ad filter subscription that summarizes multiple ad-blocking filter rules, updated every 20 minutes to ensure timely synchronization with upstream to reduce false positives.
!Homepage: https://github.com/REIJI007/Adblock-Rule-Collection
!LICENSE1: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL 3.0
!LICENSE2: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC-BY-NC-SA 4.0
!Generated on: {timestamp}
!Number of valid rules: {len(rules)}
"""
    with open(save_path, 'w', encoding='utf-8') as f:
        logging.info(f"Writing {len(rules)} rules to file {save_path}")
        f.write(header)
        f.write('\n')
        f.writelines(f"{rule}\n" for rule in sorted(rules) if rule is not None)
    logging.info(f"Successfully wrote rules to {save_path}")
    print(f"Successfully wrote rules to {save_path}")
    print(f"Number of valid rules: {len(rules)}")

# Main function
def main():
    logging.info("Starting to download filters...")
    print("Starting to download filters...")

    filter_urls = [
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_4_Social/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_18_Annoyances_Cookies/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_19_Annoyances_Popups/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_20_Annoyances_MobileApp/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_21_Annoyances_Other/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_22_Annoyances_Widgets/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_101_EasyList/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_104_EasyListChina/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_118_EasyPrivacy/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_122_FanboysAnnoyances/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_123_FanboysSocialBlockingList/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_201_WebAnnoyancesUltralist/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_204_PeterLowesList/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_207_AdblockWarningRemovalList/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_208_Online_Malicious_URL_Blocklist/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_209_ADgkMobileChinalist/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_210_Spam404/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_211_AntiAdblockKillerReek/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_219_ChinaListAndEasyList/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_220_CJXsAnnoyanceList/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_228_xinggsf/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_229_IdontCareAboutCookies/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_239_FanboyAntifonts/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_240_BarbBlock/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_241_FanboyCookiemonster/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_242_NoCoin/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_250_DandelionSproutAnnoyances/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_251_LegitimateURLShortener/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_255_Phishing_URL_Blocklist/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_256_Scam_Blocklist/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_257_uBlock_Origin_Badware_risks/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/adservers_firstparty.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/foreign.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/cryptominers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/adservers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/adservers_firstparty.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/allowlist_stealth.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/antiadblock.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/replace.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/content_blocker.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/exclusions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/exceptions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/rules.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/tracking_servers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/mobile.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/general_elemhide.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/general_extensions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/general_url.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/popups.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/social_trackers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/antiadblock.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/popups_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/popups_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Widgets/sections/widgets.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_microsites.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_mail_trackers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/adservers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/adservers_firstparty.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/antiadblock.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/general_elemhide.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/general_extensions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/general_url.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/replace.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/adservers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/allowlist_app.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/allowlist_web.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/antiadblock.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/general_elemhide.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/general_extensions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/general_url.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/replace.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/cookies_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/cookies_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/cookies_specific.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/general_elemhide.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/general_extensions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/general_url.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/mobile.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/mobile_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/tracking_servers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/TrackParamFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/TrackParamFilter/sections/general_url.txt"
    ]

    save_path = os.path.join(os.getcwd(), 'ADBLOCK_RULE_COLLECTION.txt')
    rules = asyncio.run(download_filters(filter_urls))
    validated_rules = validate_rules(rules)
    write_rules_to_file(validated_rules, save_path)

if __name__ == '__main__':
    main()
    if sys.stdin.isatty():
        input("Press Enter to exit...")
    else:
        print("Non-interactive mode, exiting...")