#!/usr/bin/python3

class Color:
    BLUE = '\033[94m'
    GREEN = '\033[1;92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNBOLD = '\033[22m'
    ITALIC = '\033[3m'
    UNITALIC = '\033[23m'

import logging
import os
import random
import re
import subprocess
import sys
import textwrap
import threading
import time
from time import sleep
from urllib.parse import urlparse, urlunparse, quote
from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit
import requests
import urllib3
from colorama import Fore, Style, init
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from rich import print as rich_print
from rich.panel import Panel
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager

from scan_config import SCAN_DICTS

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.2 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.70",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36",
]

init(autoreset=True)

def check_and_install_packages(packages):
    for package, version in packages.items():
        try:
            __import__(package)
        except ImportError:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', f"{package}=={version}"])

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_menu():
    title = r"""
__  __ ____                  
|  \/  / ___|  ___ __ _ _ __  
| |\/| \___ \ / __/ _` | '_ \ 
| |  | |___) | (_| (_| | | | |
|_|  |_|____/ \___\__,_|_| |_|                                                                                
"""
    print(Color.GREEN + Style.BRIGHT + title.center(63))
    print(Fore.WHITE + Style.BRIGHT + "─" * 63)
    border_color = Color.BLUE + Style.BRIGHT
    option_color = Fore.WHITE + Style.BRIGHT

    print(border_color + "┌" + "─" * 61 + "┐")

    options = [
        "1] LFI Scanner",
        "2] Path Traversal Scanner",
        "3] SQLi Scanner",
        "4] XSS Scanner",
        "5] Exit"
    ]

    for option in options:
        print(border_color + "│" + option_color + option.ljust(61) + border_color + "│")

    print(border_color + "└" + "─" * 61 + "┘")
    authors = "Created by: MaiCT"
    instructions = "Select an option by entering the corresponding number:"

    print(Fore.WHITE + Style.BRIGHT + "─" * 63)
    print(Fore.WHITE + Style.BRIGHT + authors.center(63))
    print(Fore.WHITE + Style.BRIGHT + "─" * 63)
    print(Fore.WHITE + Style.BRIGHT + instructions.center(63))
    print(Fore.WHITE + Style.BRIGHT + "─" * 63)

def print_exit_menu():
    clear_screen()

    panel = Panel(r"""
____               _ 
| __ ) _   _  ___  | |
|  _ \| | | |/ _ \ | |
| |_) | |_| |  __/ |_|
|____/ \__, |\___| (_)
       |___/          
Credit: MaiCT
        """,
        style="bold green",
        border_style="blue",
        expand=False
    )

    rich_print(panel)
    print(Color.RED + "\n\nSession Off..\n")
    exit(0)

def print_scan_summary(total_found, total_scanned, time_taken):
    def strip_colors(s):
        """Loại bỏ mã màu để tính độ dài thực."""
        return s.replace(Fore.GREEN, '').replace(Fore.YELLOW, '').replace(Fore.RESET, '')

    summary = [
        "→ Scanning finished.",
        f"• Total found: {Fore.GREEN}{total_found}{Fore.YELLOW}",
        f"• Total scanned: {total_scanned}",
        f"• Time taken: {time_taken} seconds"
    ]
    max_length = max(len(strip_colors(line)) for line in summary)

    top_border = "┌" + "─" * (max_length + 2) + "┐"
    bot_border = "└" + "─" * (max_length + 2) + "┘"

    print(Fore.YELLOW + f"\n{top_border}")
    for line in summary:
        raw_line = strip_colors(line)
        padding = max_length - len(raw_line)
        print(Fore.YELLOW + f"│ {line}{' ' * padding} │")
    print(Fore.YELLOW + bot_border)

def generate_pdf_report(output_file, scan_type, total_found, total_scanned, time_taken, vulnerable_urls):
    doc = SimpleDocTemplate(
        output_file,
        pagesize=letter,
        topMargin=40,
        bottomMargin=40,
        leftMargin=40,
        rightMargin=40,
    )
    styles = getSampleStyleSheet()
    content = []
    logo_path = "./mscan/logo.png"
    logo = Image(logo_path, width=100, height=100)
    logo.hAlign = 'LEFT'
    title = Paragraph("<b>Security Scan Report</b>", styles["Title"])
    header_data = [
        [logo, title]
    ]
    header_table = Table(header_data, colWidths=[100, 400])
    header_table.setStyle(
        TableStyle(
            [
                ("ALIGN", (0, 0), (0, 0), "LEFT"),
                ("ALIGN", (1, 0), (1, 0), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 0, colors.white),
            ]
        )
    )
    content.append(header_table)
    content.append(Spacer(1, 12))

    scan_type_wrapped = textwrap.fill(SCAN_DICTS[scan_type]['fullName'], width=15)
    total_found_wrapped = textwrap.fill(str(total_found), width=10)
    total_scanned_wrapped = textwrap.fill(str(total_scanned), width=10)
    time_taken_wrapped = textwrap.fill(str(time_taken), width=10)

    summary_data = [
        ["Scan Type", "Open Vulnerabilities", "Total URLs Scanned", "Time taken"],
        [
            scan_type_wrapped,
            total_found_wrapped,
            total_scanned_wrapped,
            time_taken_wrapped,
        ],
    ]
    summary_table = Table(summary_data, colWidths=[120, 120, 120, 120])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.black),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]
        )
    )
    content.append(summary_table)
    content.append(Spacer(1, 20))

    # Danh sách URL
    content.append(Paragraph("<b>Vulnerable URLs</b>", styles["Heading2"]))
    for url in vulnerable_urls:
        wrapped_url = textwrap.fill(url, width=60)
        content.append(Paragraph(f"<a href=\"{url}\" color='red'>{wrapped_url}</a>", styles["BodyText"]))
        content.append(Spacer(1, 5))
    # Recommendation
    content.append(Spacer(1, 20))
    content.append(Paragraph("<b>Recommendation</b>", styles["Heading2"]))
    content.append(Paragraph(SCAN_DICTS[scan_type]['recommendation'], styles["BodyText"]))
    doc.build(content)

def save_results(scan_type, vulnerable_urls, total_found, total_scanned, time_taken):
    generate_report = input(f"{Fore.BLUE}\n[?] Do you want to generate an PDF report? (y/n): ").strip().lower()
    if generate_report == 'y':
        filename = input(f"{Fore.BLUE}[?] Enter the filename for the PDF report: ").strip()
        if not filename.lower().endswith('.pdf'):
            filename += '.pdf'
        generate_pdf_report(
            filename,
            scan_type=scan_type,
            total_found=total_found,
            total_scanned=total_scanned,
            time_taken=time_taken,
            vulnerable_urls=vulnerable_urls
        )

def get_file_path(prompt_text):
    completer = PathCompleter()
    return prompt(prompt_text, completer=completer).strip()

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def prompt_for_urls(scan_type):
    while True:
        # Yêu cầu nhập đường dẫn file URL (hoặc nhấn Enter để nhập 1 URL)
        url_input = get_file_path(
            "[?] Enter the path to the input file containing the URLs "
            "(or press Enter to input a single URL): "
        )

        if not url_input:
            single_url = input(Fore.BLUE + "[?] Enter a single URL to scan: ").strip()
            if single_url:
                return [single_url]
            else:
                print(Fore.RED + "[!] You must provide either a file with URLs or a single URL.")
        else:
            # Nếu có đường dẫn file -> đọc file
            try:
                if not os.path.isfile(url_input):
                    raise FileNotFoundError(f"File not found: {url_input}")
                with open(url_input, 'r') as file:
                    urls = [line.strip() for line in file if line.strip()]
                if urls:
                    return urls
                else:
                    raise ValueError(f"File is empty or has no valid URLs: {url_input}")
            except Exception as e:
                print(Fore.RED + f"[!] Error reading input file: {url_input}. Exception: {str(e)}")

        # Nếu có lỗi hoặc không đủ điều kiện -> yêu cầu nhấn Enter và clear màn hình
        input(Fore.YELLOW + "\n[i] Press Enter to try again...")
        clear_screen()
        print(Fore.GREEN + f"Welcome to the {SCAN_DICTS[scan_type]['name']} Testing Tool!\n")

def prompt_for_payloads(scan_type):
    while True:
        try:
            payload_input = get_file_path("[?] Enter the path to the payloads file: ")
            if not os.path.isfile(payload_input):
                raise FileNotFoundError(f"File not found: {payload_input}")
            with open(payload_input, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip()]
            return payloads
        except Exception as e:
            print(Fore.RED + f"[!] Error reading payload file: {payload_input}. Exception: {str(e)}")
            input(Fore.YELLOW + "[i] Press Enter to try again...")
            clear_screen()
            print(Fore.GREEN + f"Welcome to the {SCAN_DICTS[scan_type]['name']} Testing Tool!\n")

def inject_payload(url, payload, encode=True):
    encoded_payload = quote(payload.strip()) if encode else payload.strip()
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query, keep_blank_values=True)
    for param in query_params:
        query_params[param] = [encoded_payload]
    encoded_query = urlencode(query_params, doseq=True)
    final_url = urlunparse(parsed_url._replace(query=encoded_query))
    return final_url

def run_scanner(scan_type, scan_state=None):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from queue import Queue
    from threading import Lock

    driver_pool = Queue()
    driver_lock = Lock()
    stop_scanning = threading.Event()
    pause_event = threading.Event()  # Event để kiểm soát việc tạm dừng
    pause_event.set()
    
    def create_driver():
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-browser-side-navigation")
        chrome_options.add_argument("--disable-infobars")
        chrome_options.add_argument("--disable-notifications")
        chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
        chrome_options.page_load_strategy = 'eager'
        logging.disable(logging.CRITICAL)

        driver_service = Service(ChromeDriverManager().install())
        return webdriver.Chrome(service=driver_service, options=chrome_options)

    def get_driver():
        try:
            return driver_pool.get_nowait()
        except:
            with driver_lock:
                return create_driver()

    def return_driver(driver):
        driver_pool.put(driver)

    def scan_url(url, payloads, cookie=None, success_criteria=None, timeout=None, max_threads=5):
        def check_payload(payload):
            """Gửi request GET với payload, trả về kết quả và (nếu có) cập nhật scan_state."""
            if stop_scanning.is_set():
                return None, False

            target_url = inject_payload(url, payload)
            headers = {'User-Agent': get_random_user_agent()}
            try:
                start_time = time.time()
                response = requests.get(
                    target_url,
                    headers=headers,
                    cookies={'cookie': cookie} if cookie else None
                )
                response_time = round(time.time() - start_time, 2)
                result = None
                is_vulnerable = False
                if response.status_code == 200:
                    vulnerability_detected = (response_time >= 10)
                    if scan_type == 'sqli':
                        is_vulnerable = response_time >= 10
                    else:
                        is_vulnerable = any(re.search(pattern, response.text) for pattern in success_criteria)

                if is_vulnerable:
                    result = Fore.RED + f"[✓]{Fore.RED} Vulnerable: {Fore.RED} {target_url} {Fore.RED} - Response Time: {response_time} seconds"
                else:
                    result = Fore.GREEN + f"[✗]{Fore.GREEN} Not Vulnerable: {Fore.GREEN} {target_url} {Fore.GREEN} - Response Time: {response_time} seconds"
                pause_event.wait()
                if stop_scanning.is_set():
                    return None, False

                if is_vulnerable and scan_state:
                    scan_state['vulnerability_found'] = True
                    scan_state['vulnerable_urls'].append(target_url)
                    scan_state['total_found'] += 1
                if scan_state:
                    scan_state['total_scanned'] += 1
                return result, is_vulnerable

            except requests.exceptions.RequestException as e:
                print(Fore.RED + f"[!] Error accessing {target_url}: {str(e)}")
                return None, False

        def check_vulnerability(payload):
            print("start")
            if stop_scanning.is_set():
                return None, False
            driver = get_driver()
            is_vulnerable = False
            result = None
            try:
                target_url = inject_payload(url, payload, encode=False)
                if not target_url:
                    return
                try:
                    driver.get(target_url)

                    try:
                        alert = WebDriverWait(driver, timeout).until(EC.alert_is_present())
                        alert_text = alert.text

                        if alert_text:
                            is_vulnerable = True
                            result = Fore.RED + f"[✓]{Fore.RED} Vulnerable:{Fore.RED} {target_url} {Fore.RED} - Alert Text: {alert_text}"
                            vulnerable_urls.append(target_url)
                            pause_event.wait()
                            if stop_scanning.is_set():
                                return None, False
                            if scan_state:
                                scan_state['vulnerability_found'] = True
                                scan_state['vulnerable_urls'].append(target_url)
                                scan_state['total_found'] += 1
                            alert.accept()
                        else:
                            result = Fore.GREEN + f"[✗]{Fore.GREEN} Not Vulnerable:{Fore.GREEN} {target_url}"
                        if scan_state:
                            scan_state['total_scanned'] += 1
                    except TimeoutException:
                        result = Fore.GREEN + f"[✗]{Fore.GREEN} Not Vulnerable:{Fore.GREEN} {target_url}"

                except UnexpectedAlertPresentException:
                    pass
            finally:
                return_driver(driver)
                return result, is_vulnerable

        found_vulnerabilities = 0
        vulnerable_urls = []
        first_error_prompt = True
        check_func = check_payload if scan_type != 'xss' else check_vulnerability
        if scan_type == 'xss':
            for _ in range(3):
                driver_pool.put(create_driver())
        
        try:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                future_to_payload = {executor.submit(check_func, payload): payload for payload in payloads}
                for future in as_completed(future_to_payload):
                    if stop_scanning.is_set():
                        break

                    payload = future_to_payload[future]
                    try:
                        result, is_vulnerable = future.result()
                        if result:
                            print(Fore.YELLOW + f"[→] Scanning with payload: {payload.strip()}")
                            print(result)
                            if is_vulnerable:
                                found_vulnerabilities += 1
                                vulnerable_urls.append(url + quote(payload.strip()))
                                if first_error_prompt:
                                    pause_event.clear()
                                    first_error_prompt = False
                                    choice = input(
                                        f"{Fore.RED}\n[?] Vulnerability found. Continue testing other payloads? (y/n, Enter=n): "
                                    ).strip().lower()
                                    if choice != 'y':
                                        stop_scanning.set()
                                    pause_event.set()

                    except Exception as e:
                        print(Fore.RED + f"[!] Exception occurred for payload {payload}: {str(e)}")
                        if first_error_prompt:
                            pause_event.clear()
                            choice = input(
                                f"{Fore.RED}[?] Error occurred. Continue testing other payloads? (y/n, Enter=n): "
                            ).strip().lower()
                            if choice != 'y':
                                stop_scanning.set()
                            pause_event.set()
                            first_error_prompt = False
        finally:
            if scan_type == 'xss':
                while not driver_pool.empty():
                    driver = driver_pool.get()
                    driver.quit()
        return stop_scanning.is_set()


    init(autoreset=True)

    clear_screen()
    required_packages = {
        'requests': '2.28.1',
        'prompt_toolkit': '3.0.36',
        'colorama': '0.4.6'
    }
    check_and_install_packages(required_packages)
    time.sleep(1)
    clear_screen()
    panel = Panel(
        SCAN_DICTS[scan_type]['art'],
        style="bold green",
        border_style="blue",
        expand=False
    )
    rich_print(panel, "\n")
    print(Fore.GREEN + f"Welcome to the {SCAN_DICTS[scan_type]['name']} Testing Tool!\n")

    urls = prompt_for_urls(scan_type)
    payloads = prompt_for_payloads(scan_type)
    cookie = None
    success_criteria = None
    timeout = None
    if scan_type == 'sqli':
        cookie = input("[?] Enter the cookie to include in the GET request (press Enter if none): ").strip() or None
    elif scan_type in  ['pt', 'lfi'] :
        success_criteria_input = input("[?] Enter the success criteria patterns (comma-separated, e.g: 'root:,admin:', press Enter for 'root:x:0:'): ").strip()
        success_criteria = [pattern.strip() for pattern in success_criteria_input.split(',')] if success_criteria_input else ['root:x:0:']
    else:
        try:
            timeout = float(input(Fore.BLUE + "Enter the timeout duration for each request (Press Enter for 0.5): "))
        except ValueError:
            timeout = 0.5
        pass
    max_threads_input = input("[?] Enter the number of concurrent threads (0-10, press Enter for 5): ").strip()
    max_threads = int(max_threads_input) if max_threads_input.isdigit() and 0 <= int(max_threads_input) <= 10 else 5
    print(f"\n{Fore.YELLOW}[i] Loading, Please Wait...")
    time.sleep(1)
    clear_screen()
    print(f"{Fore.BLUE}[i] Starting scan...\n")
    start_time = time.time()

    if scan_state is None:
        scan_state = {
            'vulnerability_found': False,
            'vulnerable_urls': [],
            'total_found': 0,
            'total_scanned': 0
        }

    try:
        for url in urls:
            box_content = f" → Scanning URL: {url} "
            box_width = max(len(box_content) + 2, 40)
            print(Fore.YELLOW + "\n┌" + "─" * (box_width - 2) + "┐")
            print(Fore.YELLOW + f"│{box_content.center(box_width - 2)}│")
            print(Fore.YELLOW + "└" + "─" * (box_width - 2) + "┘\n")

            stopped = scan_url(url, payloads, cookie=cookie, success_criteria=success_criteria, timeout=timeout, max_threads=max_threads)
            if stopped:
                break
    except KeyboardInterrupt:
        stop_scanning.set()
        print(Fore.RED + "\n[!] Scan interrupted by the user.")
        os._exit(0)

    time_taken = int(time.time() - start_time)
    total_found = scan_state['total_found']
    total_scanned = scan_state['total_scanned']
    vulnerable_urls = scan_state['vulnerable_urls']
    print_scan_summary(total_found, total_scanned, time_taken)
    save_results(scan_type, vulnerable_urls, total_found, total_scanned, time_taken)
    os._exit(0)

def handle_selection(selection):
    scan_type_index = {
        1: 'lfi',
        2: 'pt',
        3: 'sqli',
        4: 'xss',
    }
    if selection in scan_type_index.keys():
        clear_screen()
        run_scanner(scan_type_index[selection])
    else:
        print_exit_menu()

def main():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    clear_screen()
    sleep(0.1)
    clear_screen()

    while True:
        try:
            display_menu()
            choice = input(f"\n{Fore.BLUE}[?] Select an option (1-5): {Style.RESET_ALL}").strip()
            handle_selection(int(choice))
        except KeyboardInterrupt:
            print_exit_menu()
            os._exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_exit_menu()
        os._exit(0)