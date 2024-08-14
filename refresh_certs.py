import csv
import subprocess
from datetime import datetime, timedelta

CSV_FILE_PATH = '/home/jef/pebble/scripts/certificates_info.csv'
PEBBLE_CA_BUNDLE = '/home/jef/pebble/test/certs/pebble.minica.pem'
CERTBOT_CONFIG = '/home/jef/pebble/certbot-pebble.ini'

def parse_cert_date(cert_date_str):
    """Geef datum terug in JJJJmmddHHMMZ formaat"""
    return datetime.strptime(cert_date_str, '%Y%m%d%H%M%SZ')

def should_refresh_certificate(expiry_date):
    """Controleer of de vervaldatum binnen de 60 dagen valt"""
    now = datetime.now()
    refresh_threshold = now + timedelta(days=60)
    return expiry_date <= refresh_threshold

def refresh_certificate(host, port):
    """Refresh het certificaat voor de nginx en apache host"""
    if port == '443':
        command = f'sudo REQUESTS_CA_BUNDLE={PEBBLE_CA_BUNDLE} certbot certonly --standalone -d nginx.localhost --config {CERTBOT_CONFIG} -n'
    elif port == '8443':
        command = f'sudo REQUESTS_CA_BUNDLE={PEBBLE_CA_BUNDLE} certbot certonly --standalone -d apache.localhost --config {CERTBOT_CONFIG} -n'
    else:
        print(f"Unknown port {port} for host {host}. Skipping refresh.")
        return
    
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"Certificate for {host} on port {port} has been refreshed.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to refresh certificate for {host} on port {port}: {e}")

def main():
    with open(CSV_FILE_PATH, mode='r') as csvfile:
        # Lees certificates_info.csv uit
        reader = csv.DictReader(csvfile)
        # Haal voor iedere csv entry de host en port op om er een check op uit te voeren
        for row in reader:
            host = row['host']
            port = row['port']
            expiry_date_str = row['expiry_date']
            expiry_date = parse_cert_date(expiry_date_str)

            if should_refresh_certificate(expiry_date):
                refresh_certificate(host, port)

if __name__ == '__main__':
    main()
