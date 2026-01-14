import requests
from models.models import ShodanHost, AbuseDBHost
import os
from dotenv import load_dotenv

load_dotenv()

shodanurl = "https://api.shodan.io/shodan/"
shodan_key = os.getenv("SHODAN_KEY")

abusedb_url = "https://api.abuseipdb.com/api/v2/"
abusedb_key = os.getenv("ABUSE_KEY")


def shodan_lookup(ip):
    url = f"{shodanurl}host/{ip}?key={shodan_key}"
    response = requests.get(url)

    if response.status_code == 200:
        # Parse JSON into Pydantic model
        shodan_data = ShodanHost(**response.json())

        # Access data with type safety
        print(f"Host: {shodan_data.ip_str}")
        print(f"Organization: {shodan_data.org}")
        print(f"Country: {shodan_data.country_name}")
        print(f"Open Ports: {shodan_data.ports}")
        print(f"Hostnames: {shodan_data.hostnames}")
        print(f"\nNumber of services detected: {len(shodan_data.data) if shodan_data.data else 0}")

        if shodan_data.data:
            for service in shodan_data.data:
                print(f"\n  Port {service.port}/{service.transport}")
                if service.http:
                    print(f"    HTTP Title: {service.http.title}")
                if service.dns:
                    print(f"    DNS Recursive: {service.dns.recursive}")
    else:
        print(f"Error: {response.status_code}")

def abuseipcheck(ip):
    response = requests.get(f"{abusedb_url}check/")

    querystring = {
        "ipAddress": ip,
        "maxAgeInDays": "90"}
    
    headers = {
        'Accept': 'application/json',
        'Key': abusedb_key}
    

    response = requests.request(method='GET', url=f"{abusedb_url}check", headers=headers, params=querystring)

    ipabuse_data = AbuseDBHost(**response.json()['data'])

    print(f"IP Address: {ipabuse_data.ipAddress}")
    print(f"Abuse Score: {ipabuse_data.abuseConfidenceScore}")
    print(f"ISP: {ipabuse_data.isp}")

# Example usage
if __name__ == "__main__":
    print("=== Shodan Lookup ===")
    input_ip = input("Enter an IP address for Shodan lookup: ")
    shodan_lookup(input_ip)

    input_ip = input("Enter an IP address for AbuseIPDB check: ")
    print("\n=== AbuseIPDB Check ===")
    abuseipcheck(input_ip)