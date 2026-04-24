#!/usr/bin/env python3
import socket
import uuid
import argparse
import time

PROBE = f'''<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:{uuid.uuid4()}</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ip")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)

    local_port = 0
    sock.bind(("", local_port))

    print(f"Enviando probe WS-Discovery direto para {args.ip}:3702...")

    sock.sendto(PROBE.encode("utf-8"), (args.ip, 3702))

    end = time.time() + args.timeout
    found = False

    while time.time() < end:
        try:
            data, addr = sock.recvfrom(65535)
            found = True
            print()
            print(f"Resposta de {addr[0]}:{addr[1]}")
            print(data.decode("utf-8", errors="ignore"))
        except socket.timeout:
            continue

    if not found:
        print("Nenhuma resposta WS-Discovery recebida desse IP.")

if __name__ == "__main__":
    main()
