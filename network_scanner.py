import socket
import requests
from concurrent.futures import ThreadPoolExecutor

CVE_API_URL = "https://cve.circl.lu/api/search/"
WEAK_PASSWORDS = ["123456", "password", "123456789", "12345678", "12345", "1234567", "1234567890"]

def scan_open_ports(target, ports):
    open_ports =[]
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
            sock.close()
        return open_ports
    
if __name__ == "__main__":
    target = "127.0.0.1"
    ports = list(range(1, 1025))
    open_ports = scan_open_ports(target, ports)
    print(f"Open ports: {open_ports}")

def check_software_version(software, version):
    response = requests.get(f"{CVE_API_URL}{software}/{version}")
    if response.status_code == 200:
        return response.json()
    return []

if __name__ == "__main__":
    software = "apache"
    version = "2.4.49"
    vulnerabilities = check_software_version(software, version)
    print(f"Vulnerabilities: {vulnerabilities}")

def ideantify_weak_password(password):
    return password in WEAK_PASSWORDS

if __name__ == "__main__":
    password = "123456"
    is_weak = ideantify_weak_password(password)
    print(f"Is the password weak? {is_weak}")

    def main():
        target = input("Enter Target IP or Hostname ")
        ports = list(range(1, 1025))

        print("Scanning for open ports")
        with ThreadPoolExecutor(max_workers=100) as executor:
            future = executor.submit(scan_open_ports, target, ports)
            open_ports = future.result()

        if open_ports:
            print(f"Open ports found: {open_ports}")
        else:
            print("no open ports found.")

        software = input("Enter the software name for avaliable vulnerabilities: ")
        version = input("Enter the software version: ")
        print("Checking for known vulnerabilities")
        vulnerabilities = check_software_version(software, version)

        if vulnerabilities:
            print(f" Vulnerabilities found for {software} version {version}:")
            for vuln in vulnerabilities:
                print(f"CVE ID: {vuln['id']}, Summary: {vuln['summary']}")

        else:
            print(f"No known vulnerabilities found for {software} version {version}.")

        password = input("Enter a password to check weakness: ")
        if ideantify_weak_password(password):
            print("The password is weak")
        else:
            print("The password is strong")

if __name__ == "__main__":
    main()