#!/usr/bin/env python3
import argparse
import re
import socket
import time
import uuid
import xml.etree.ElementTree as ET


PROBE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
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
</e:Envelope>"""

DEFAULT_PATHS = [
    "/",
    "/11",
    "/12",
    "/live.sdp",
    "/stream1",
    "/h264",
    "/cam/realmonitor?channel=1&subtype=00",
    "/cam/realmonitor?channel=1&subtype=01",
    "/Streaming/Channels/101",
    "/Streaming/Channels/102",
    "/media/video1",
    "/videoMain",
]


def extract_tag_text(xml_text: str, tag_name: str) -> str | None:
    try:
        root = ET.fromstring(xml_text)
        for elem in root.iter():
            if elem.tag.endswith("}" + tag_name) or elem.tag == tag_name:
                return elem.text
    except ET.ParseError:
        pass

    match = re.search(rf"<[^>]*{tag_name}[^>]*>(.*?)</[^>]*{tag_name}>", xml_text, re.DOTALL)
    if match:
        return match.group(1).strip()

    return None


def ws_discovery_probe(target: str, timeout: float) -> dict | None:
    message = PROBE_TEMPLATE.format(message_id=str(uuid.uuid4()))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    sock.bind(("", 0))

    try:
        sock.sendto(message.encode("utf-8"), (target, 3702))
        end = time.time() + timeout

        while time.time() < end:
            try:
                data, remote = sock.recvfrom(65535)
            except socket.timeout:
                continue

            if remote[0] != target:
                continue

            xml_text = data.decode("utf-8", errors="ignore")
            return {
                "ip": remote[0],
                "xaddrs": extract_tag_text(xml_text, "XAddrs"),
                "types": extract_tag_text(xml_text, "Types"),
                "scopes": extract_tag_text(xml_text, "Scopes"),
            }
    finally:
        sock.close()

    return None


def rtsp_describe(ip: str, port: int, path: str, timeout: float) -> dict:
    target = f"rtsp://{ip}:{port}{path}"
    request = (
        f"DESCRIBE {target} RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "User-Agent: Python RTSP Scanner\r\n"
        "Accept: application/sdp\r\n"
        "\r\n"
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((ip, port))
        sock.sendall(request.encode("utf-8"))

        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if b"\r\n\r\n" in b"".join(chunks):
                break

        response = b"".join(chunks).decode("utf-8", errors="ignore")
        lines = response.split("\r\n")
        status_line = lines[0] if lines else ""
        status_match = re.match(r"RTSP/\d+\.\d+\s+(\d+)\s+(.*)", status_line)

        status = None
        reason = ""
        if status_match:
            status = int(status_match.group(1))
            reason = status_match.group(2).strip()

        headers = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

        return {
            "path": path,
            "url": target,
            "status": status,
            "reason": reason,
            "www_authenticate": headers.get("www-authenticate"),
        }
    except OSError as exc:
        return {
            "path": path,
            "url": target,
            "status": None,
            "reason": str(exc),
            "www_authenticate": None,
        }
    finally:
        sock.close()


def scan_rtsp(ip: str, port: int, timeout: float, paths: list[str]) -> list[dict]:
    hits = []
    for path in paths:
        result = rtsp_describe(ip, port, path, timeout)
        if result["status"] in {200, 401, 403}:
            hits.append(result)
    return hits


def print_summary(ip: str, onvif: dict | None, rtsp_hits: list[dict]) -> None:
    print("=" * 80)
    print(f"IP: {ip}")

    if onvif:
        print("ONVIF: sim")
        print(f"XAddr: {onvif['xaddrs']}")
        print(f"Types: {onvif['types']}")
    else:
        print("ONVIF: sem resposta ao WS-Discovery direto")

    if not rtsp_hits:
        print("RTSP: nenhum path testado retornou 200/401/403")
        return

    print("RTSP detectado:")
    for hit in rtsp_hits:
        line = f"  {hit['status']} {hit['reason']} -> {hit['url']}"
        if hit["www_authenticate"]:
            line += f" | auth: {hit['www_authenticate']}"
        print(line)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Descobre ONVIF e testa paths RTSP comuns em uma ou mais cameras."
    )
    parser.add_argument("ips", nargs="+", help="IPs das cameras. Ex: 192.168.1.16 192.168.1.5")
    parser.add_argument("--rtsp-port", type=int, default=554)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument(
        "--paths",
        default=",".join(DEFAULT_PATHS),
        help="Lista de paths RTSP separados por virgula.",
    )
    args = parser.parse_args()

    paths = [path.strip() for path in args.paths.split(",") if path.strip()]

    for ip in args.ips:
        onvif = ws_discovery_probe(ip, args.timeout)
        rtsp_hits = scan_rtsp(ip, args.rtsp_port, args.timeout, paths)
        print_summary(ip, onvif, rtsp_hits)


if __name__ == "__main__":
    main()
