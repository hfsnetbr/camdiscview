#!/usr/bin/env python3
import socket
import uuid
import time
import argparse
import re
import xml.etree.ElementTree as ET

PROBE_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:{message_id}</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>'''


def extract_tag_text(xml_text, tag_name):
    """
    Extrai conteúdo de tags ignorando namespace.
    Ex: XAddrs, Types, Scopes.
    """
    try:
        root = ET.fromstring(xml_text)
        for elem in root.iter():
            if elem.tag.endswith("}" + tag_name) or elem.tag == tag_name:
                return elem.text
    except ET.ParseError:
        pass

    # fallback simples via regex
    match = re.search(rf"<[^>]*{tag_name}[^>]*>(.*?)</[^>]*{tag_name}>", xml_text, re.DOTALL)
    if match:
        return match.group(1).strip()

    return None


def send_probe(target, timeout):
    message = PROBE_TEMPLATE.format(message_id=str(uuid.uuid4()))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    sock.bind(("", 0))

    if target == "multicast":
        addr = ("239.255.255.250", 3702)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    else:
        addr = (target, 3702)

    sock.sendto(message.encode("utf-8"), addr)

    end = time.time() + timeout
    results = {}

    while time.time() < end:
        try:
            data, remote = sock.recvfrom(65535)
            ip = remote[0]
            xml_text = data.decode("utf-8", errors="ignore")

            xaddrs = extract_tag_text(xml_text, "XAddrs")
            scopes = extract_tag_text(xml_text, "Scopes")
            types = extract_tag_text(xml_text, "Types")

            results[ip] = {
                "ip": ip,
                "xaddrs": xaddrs,
                "types": types,
                "scopes": scopes,
                "raw": xml_text,
            }

        except socket.timeout:
            continue

    return results


def main():
    parser = argparse.ArgumentParser(description="Descoberta ONVIF via WS-Discovery extraindo XAddrs")
    parser.add_argument(
        "target",
        help="IP da câmera ou 'multicast'. Ex: 192.168.1.16 ou multicast"
    )
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--raw", action="store_true", help="Mostra XML completo")

    args = parser.parse_args()

    print(f"Buscando ONVIF em: {args.target}")
    results = send_probe(args.target, args.timeout)

    if not results:
        print("Nenhum dispositivo ONVIF respondeu.")
        return

    print()
    print("=" * 80)
    print("DISPOSITIVOS ONVIF ENCONTRADOS")
    print("=" * 80)

    for ip, item in results.items():
        print()
        print(f"IP: {ip}")
        print(f"Endpoint ONVIF: {item['xaddrs']}")
        print(f"Types: {item['types']}")
        print(f"Scopes: {item['scopes']}")

        if args.raw:
            print()
            print("XML:")
            print(item["raw"])


if __name__ == "__main__":
    main()
