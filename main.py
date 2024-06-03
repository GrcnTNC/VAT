import socket
import argparse
import requests
from bs4 import BeautifulSoup
import concurrent.futures

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            return port
    except Exception as e:
        print(f"Error scanning port {port} on {ip}: {e}")
    finally:
        sock.close()

def scan_ip(ip, start_port, end_port):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_port, ip, port): port for port in range(start_port, end_port+1)}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result() is not None:
                    open_ports.append(port)
            except Exception as e:
                print(f"Error scanning port {port} on {ip}: {e}")
    return open_ports

def check_xss(url):
    xss_test_script = "<script>alert('XSS')</script>"
    response = requests.get(url, params={"q": xss_test_script})

    soup = BeautifulSoup(response.text, 'html.parser')
    if soup.find(text=xss_test_script):
        print(f"Potential XSS vulnerability found at {url}")
    else:
        print(f"No XSS vulnerability found at {url}")

def check_sql_injection(url):
    sql_test_script = "' OR '1'='1"
    response = requests.get(url, params={"q": sql_test_script})

    if sql_test_script in response.text:
        print(f"Potential SQL Injection vulnerability found at {url}")
    else:
        print(f"No SQL Injection vulnerability found at {url}")

def main(start_ip, end_ip, start_port, end_port, urls):
    for i in range(start_ip, end_ip+1):
        ip = f"192.168.1.{i}"  # replace with your subnet
        open_ports = scan_ip(ip, start_port, end_port)
        if open_ports:
            print(f"Open ports on {ip} are: {open_ports}")
        else:
            print(f"No open ports found on {ip} within the range {start_port}-{end_port}.")

    for url in urls:
        check_xss(url)
        check_sql_injection(url)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A simple vulnerability scanner")
    parser.add_argument("--start_ip", type=int, default=1, help="The first IP to scan in the subnet")
    parser.add_argument("--end_ip", type=int, default=254, help="The last IP to scan in the subnet")
    parser.add_argument("--start_port", type=int, default=1, help="The first port to scan")
    parser.add_argument("--end_port", type=int, default=1024, help="The last port to scan")
    parser.add_argument("--urls", type=str, nargs='+', help="The URLs to check for XSS and SQL Injection vulnerabilities")
    args = parser.parse_args()

    main(args.start_ip, args.end_ip, args.start_port, args.end_port, args.urls)