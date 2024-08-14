import ssl
import socket
import OpenSSL
import csv

def get_ssl_certificate(host, port=443):
    context = ssl._create_unverified_context()
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert(True)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
            return x509

def extract_cert_info(cert):
    subject = cert.get_subject()
    issuer = cert.get_issuer()
    subject_dn = f"CN={subject.CN}, O={subject.O}, C={subject.C}"
    issuer_dn = f"CN={issuer.CN}, O={issuer.O}, C={issuer.C}"
    serial_number = cert.get_serial_number()
    start_date = cert.get_notBefore().decode('utf-8')
    expiry_date = cert.get_notAfter().decode('utf-8')
    cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert).decode('utf-8')
    return {
        "subject_dn": subject_dn,
        "issuer_dn": issuer_dn,
        "serial_number": serial_number,
        "start_date": start_date,
        "expiry_date": expiry_date,
        "cert_pem": cert_pem
    }

def main():
    input_list = input("Enter hosts and ports (host:port, host:port, ...): ")
    hosts = [h.strip() for h in input_list.split(',')]
    
    certs_info = []
    
    for host_port in hosts:
        if ':' in host_port:
            host, port = host_port.split(':')
            port = int(port)
        else:
            host = host_port
            port = 443
        
        try:
            cert = get_ssl_certificate(host, port)
            cert_info = extract_cert_info(cert)
            cert_info["host"] = host
            cert_info["port"] = port
            certs_info.append(cert_info)
        except Exception as e:
            print(f"Error retrieving certificate for {host}:{port} - {e}")
    
    with open('certificates_info.csv', 'w', newline='') as csvfile:
        fieldnames = ["host", "port", "subject_dn", "issuer_dn", "serial_number", "start_date", "expiry_date", "cert_pem"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for cert_info in certs_info:
            writer.writerow(cert_info)
    
    print("Certificate information saved to certificates_info.csv")

if __name__ == "__main__":
    main()
