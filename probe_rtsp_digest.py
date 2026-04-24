#!/usr/bin/env python3
import argparse
import hashlib
import random
import re
import socket
import time
from urllib.parse import urlparse


DEFAULT_PATHS = [
    "/",
    "/11",
    "/12",
    "/0",
    "/1",
    "/live.sdp",
    "/stream1",
    "/h264",
    "/ch0_0.h264",
    "/ch0",
    "/cam1/h264",
    "/cam/realmonitor?channel=1&subtype=00",
    "/cam/realmonitor?channel=1&subtype=01",
    "/Streaming/Channels/101",
    "/Streaming/Channels/102",
    "/media/video1",
    "/videoMain",
]


def md5_hex(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def recv_all(sock: socket.socket) -> str:
    chunks = []
    while True:
        data = sock.recv(4096)
        if not data:
            break
        chunks.append(data)
        if b"\r\n\r\n" in b"".join(chunks):
            break
    return b"".join(chunks).decode("utf-8", errors="ignore")


def rtsp_request(ip: str, port: int, path: str, cseq: int, auth_header: str | None, timeout: float) -> str:
    url = f"rtsp://{ip}:{port}{path}"
    lines = [
        f"DESCRIBE {url} RTSP/1.0",
        f"CSeq: {cseq}",
        "User-Agent: RTSP Digest Probe",
        "Accept: application/sdp",
    ]
    if auth_header:
        lines.append(f"Authorization: {auth_header}")
    lines.append("")
    lines.append("")
    request = "\r\n".join(lines)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        sock.sendall(request.encode("utf-8"))
        return recv_all(sock)
    finally:
        sock.close()


def parse_status(response: str) -> tuple[int | None, str]:
    first_line = response.split("\r\n", 1)[0]
    match = re.match(r"RTSP/\d+\.\d+\s+(\d+)\s+(.*)", first_line)
    if not match:
        return None, first_line
    return int(match.group(1)), match.group(2).strip()


def parse_header(response: str, name: str) -> str | None:
    for line in response.split("\r\n")[1:]:
        if line.lower().startswith(name.lower() + ":"):
            return line.split(":", 1)[1].strip()
    return None


def parse_digest_challenge(header: str) -> dict[str, str]:
    parts = {}
    for key, value in re.findall(r'(\w+)="([^"]*)"', header):
        parts[key] = value
    return parts


def build_digest_auth(username: str, password: str, method: str, uri: str, challenge: dict[str, str]) -> str:
    realm = challenge["realm"]
    nonce = challenge["nonce"]
    qop = challenge.get("qop")
    opaque = challenge.get("opaque")
    algorithm = challenge.get("algorithm", "MD5")

    if algorithm.upper() != "MD5":
        raise ValueError(f"Algoritmo nao suportado: {algorithm}")

    ha1 = md5_hex(f"{username}:{realm}:{password}")
    ha2 = md5_hex(f"{method}:{uri}")

    fields = [
        'Digest username="%s"' % username,
        'realm="%s"' % realm,
        'nonce="%s"' % nonce,
        'uri="%s"' % uri,
    ]

    if qop:
        nc = "00000001"
        cnonce = md5_hex(str(random.random()))[:16]
        response = md5_hex(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
        fields.extend([
            'response="%s"' % response,
            'qop="%s"' % qop,
            'nc=%s' % nc,
            'cnonce="%s"' % cnonce,
        ])
    else:
        response = md5_hex(f"{ha1}:{nonce}:{ha2}")
        fields.append('response="%s"' % response)

    if opaque:
        fields.append('opaque="%s"' % opaque)

    return ", ".join(fields)


def probe_path(ip: str, port: int, path: str, username: str, password: str, timeout: float) -> dict:
    first = rtsp_request(ip, port, path, 1, None, timeout)
    status, reason = parse_status(first)
    result = {"path": path, "status": status, "reason": reason, "auth": None}

    if status != 401:
        return result

    www_auth = parse_header(first, "WWW-Authenticate")
    result["auth"] = www_auth
    if not www_auth or "Digest" not in www_auth:
        return result

    challenge = parse_digest_challenge(www_auth)
    uri = f"rtsp://{ip}:{port}{path}"
    auth_header = build_digest_auth(username, password, "DESCRIBE", uri, challenge)
    second = rtsp_request(ip, port, path, 2, auth_header, timeout)
    status2, reason2 = parse_status(second)

    body = ""
    if "\r\n\r\n" in second:
        body = second.split("\r\n\r\n", 1)[1].strip()

    result.update({
        "status_after_auth": status2,
        "reason_after_auth": reason2,
        "body_preview": body[:300],
    })
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Testa RTSP DESCRIBE com Digest em paths comuns.")
    parser.add_argument("ip")
    parser.add_argument("--port", type=int, default=554)
    parser.add_argument("--user", default="admin")
    parser.add_argument("--password", required=True)
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument("--delay", type=float, default=0.0, help="Espera em segundos entre os testes.")
    parser.add_argument("--paths", default=",".join(DEFAULT_PATHS))
    args = parser.parse_args()

    paths = [path.strip() for path in args.paths.split(",") if path.strip()]

    for index, path in enumerate(paths):
        result = probe_path(args.ip, args.port, path, args.user, args.password, args.timeout)
        print("=" * 80)
        print(f"Path: {path}")
        print(f"Sem auth: {result.get('status')} {result.get('reason')}")
        if result.get("auth"):
            print(f"WWW-Authenticate: {result['auth']}")
        if "status_after_auth" in result:
            print(f"Com Digest: {result['status_after_auth']} {result['reason_after_auth']}")
            if result.get("body_preview"):
                print("Body:")
                print(result["body_preview"])
        if args.delay > 0 and index < len(paths) - 1:
            time.sleep(args.delay)


if __name__ == "__main__":
    main()
