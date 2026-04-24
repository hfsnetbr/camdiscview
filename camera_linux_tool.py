#!/usr/bin/env python3
import argparse
import base64
import datetime
import hashlib
import os
import re
import socket
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urlunparse

import requests


PTZ_POSITION_SPACE = "http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace"
PTZ_ZOOM_SPACE = "http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace"
PTZ_TRANSLATION_SPACE = "http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace"
PTZ_ZOOM_TRANSLATION_SPACE = "http://www.onvif.org/ver10/tptz/ZoomSpaces/TranslationGenericSpace"

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

RTSP_PATHS = [
    "/",
    "/onvif1",
    "/onvif2",
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


def nmap_discover_hosts(target: str, timeout: float = 30.0) -> list[str]:
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-n", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    if result.returncode not in {0, 1}:
        return []

    hosts = []
    seen = set()
    for line in result.stdout.splitlines():
        match = re.search(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", line)
        if not match:
            continue
        ip = match.group(1)
        if ip not in seen:
            seen.add(ip)
            hosts.append(ip)
    return hosts


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


def wsse_password_digest(password: str) -> tuple[str, str, str]:
    nonce = os.urandom(16)
    created = datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    digest = hashlib.sha1(nonce + created.encode("utf-8") + password.encode("utf-8")).digest()
    return (
        base64.b64encode(nonce).decode("ascii"),
        created,
        base64.b64encode(digest).decode("ascii"),
    )


def build_wsse_envelope(username: str, password: str, body: str, namespaces: list[str]) -> str:
    nonce, created, password_value = wsse_password_digest(password)
    password_type = (
        "http://docs.oasis-open.org/wss/2004/01/"
        "oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
    )

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope
  xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  {' '.join(namespaces)}
  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
  xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <wsse:Security s:mustUnderstand="1">
      <wsse:UsernameToken>
        <wsse:Username>{username}</wsse:Username>
        <wsse:Password Type="{password_type}">{password_value}</wsse:Password>
        <wsse:Nonce>{nonce}</wsse:Nonce>
        <wsu:Created>{created}</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
  </s:Header>
  <s:Body>{body}</s:Body>
</s:Envelope>"""


def build_get_profiles(username: str, password: str) -> str:
    return build_wsse_envelope(
        username,
        password,
        "<trt:GetProfiles/>",
        ['xmlns:trt="http://www.onvif.org/ver10/media/wsdl"'],
    )


def build_get_stream_uri(username: str, password: str, profile_token: str) -> str:
    body = f"""<trt:GetStreamUri>
      <trt:StreamSetup>
        <tt:Stream>RTP-Unicast</tt:Stream>
        <tt:Transport>
          <tt:Protocol>RTSP</tt:Protocol>
        </tt:Transport>
      </trt:StreamSetup>
      <trt:ProfileToken>{profile_token}</trt:ProfileToken>
    </trt:GetStreamUri>"""
    return build_wsse_envelope(
        username,
        password,
        body,
        [
            'xmlns:trt="http://www.onvif.org/ver10/media/wsdl"',
            'xmlns:tt="http://www.onvif.org/ver10/schema"',
        ],
    )


def build_get_ptz_status(username: str, password: str, profile_token: str) -> str:
    body = f"""<tptz:GetStatus>
      <tptz:ProfileToken>{profile_token}</tptz:ProfileToken>
    </tptz:GetStatus>"""
    return build_wsse_envelope(
        username,
        password,
        body,
        ['xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"'],
    )


def build_relative_move(username: str, password: str, profile_token: str, pan: float, tilt: float, zoom: float) -> str:
    move_parts = []
    if pan or tilt:
        move_parts.append(
            f'<tt:PanTilt x="{pan}" y="{tilt}" space="{PTZ_TRANSLATION_SPACE}"/>'
        )
    if zoom:
        move_parts.append(
            f'<tt:Zoom x="{zoom}" space="{PTZ_ZOOM_TRANSLATION_SPACE}"/>'
        )

    body = f"""<tptz:RelativeMove>
      <tptz:ProfileToken>{profile_token}</tptz:ProfileToken>
      <tptz:Translation>{''.join(move_parts)}</tptz:Translation>
    </tptz:RelativeMove>"""
    return build_wsse_envelope(
        username,
        password,
        body,
        [
            'xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"',
            'xmlns:tt="http://www.onvif.org/ver10/schema"',
        ],
    )


def build_absolute_move(username: str, password: str, profile_token: str, pan: float, tilt: float, zoom: float) -> str:
    body = f"""<tptz:AbsoluteMove>
      <tptz:ProfileToken>{profile_token}</tptz:ProfileToken>
      <tptz:Position>
        <tt:PanTilt x="{pan}" y="{tilt}" space="{PTZ_POSITION_SPACE}"/>
        <tt:Zoom x="{zoom}" space="{PTZ_ZOOM_SPACE}"/>
      </tptz:Position>
    </tptz:AbsoluteMove>"""
    return build_wsse_envelope(
        username,
        password,
        body,
        [
            'xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"',
            'xmlns:tt="http://www.onvif.org/ver10/schema"',
        ],
    )


def build_get_presets(username: str, password: str, profile_token: str) -> str:
    body = f"""<tptz:GetPresets>
      <tptz:ProfileToken>{profile_token}</tptz:ProfileToken>
    </tptz:GetPresets>"""
    return build_wsse_envelope(
        username,
        password,
        body,
        ['xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"'],
    )


def build_set_preset(username: str, password: str, profile_token: str, preset_name: str) -> str:
    body = f"""<tptz:SetPreset>
      <tptz:ProfileToken>{profile_token}</tptz:ProfileToken>
      <tptz:PresetName>{preset_name}</tptz:PresetName>
    </tptz:SetPreset>"""
    return build_wsse_envelope(
        username,
        password,
        body,
        ['xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"'],
    )


def build_goto_preset(username: str, password: str, profile_token: str, preset_token: str) -> str:
    body = f"""<tptz:GotoPreset>
      <tptz:ProfileToken>{profile_token}</tptz:ProfileToken>
      <tptz:PresetToken>{preset_token}</tptz:PresetToken>
    </tptz:GotoPreset>"""
    return build_wsse_envelope(
        username,
        password,
        body,
        ['xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"'],
    )


def build_remove_preset(username: str, password: str, profile_token: str, preset_token: str) -> str:
    body = f"""<tptz:RemovePreset>
      <tptz:ProfileToken>{profile_token}</tptz:ProfileToken>
      <tptz:PresetToken>{preset_token}</tptz:PresetToken>
    </tptz:RemovePreset>"""
    return build_wsse_envelope(
        username,
        password,
        body,
        ['xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"'],
    )


def soap_post(url: str, body: str, timeout: float) -> requests.Response | None:
    try:
        return requests.post(
            url,
            data=body.encode("utf-8"),
            headers={
                "Content-Type": "application/soap+xml; charset=utf-8",
                "User-Agent": "Linux Camera Tool",
                "Connection": "close",
            },
            timeout=timeout,
        )
    except requests.RequestException:
        return None


def parse_profiles(xml_text: str) -> list[dict]:
    profiles = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return profiles

    for elem in root.iter():
        if elem.tag.split("}")[-1] != "Profiles":
            continue

        token = elem.attrib.get("token")
        name = None
        width = None
        height = None
        ptz_configuration_token = None
        ptz_node_token = None

        for child in elem.iter():
            local = child.tag.split("}")[-1]
            if local == "Name" and name is None:
                name = child.text
            elif local == "Width" and width is None:
                width = child.text
            elif local == "Height" and height is None:
                height = child.text
            elif local == "PTZConfiguration" and ptz_configuration_token is None:
                ptz_configuration_token = child.attrib.get("token")
            elif local == "NodeToken" and ptz_node_token is None:
                ptz_node_token = child.text

        if token:
            profiles.append({
                "token": token,
                "name": name or token,
                "width": width,
                "height": height,
                "ptz": bool(ptz_configuration_token),
                "ptz_configuration_token": ptz_configuration_token,
                "ptz_node_token": ptz_node_token,
            })

    return profiles


def extract_uri(xml_text: str) -> str | None:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    for elem in root.iter():
        if elem.tag.split("}")[-1] == "Uri":
            return elem.text

    return None


def media_service_candidates(xaddr: str) -> list[str]:
    parsed = urlparse(xaddr)
    base = f"{parsed.scheme}://{parsed.netloc}"
    candidates = [
        f"{base}/onvif/media_service",
        f"{base}/onvif/Media",
        f"{base}/onvif/media",
    ]
    unique = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
    return unique


def ptz_service_candidates(xaddr: str) -> list[str]:
    parsed = urlparse(xaddr)
    base = f"{parsed.scheme}://{parsed.netloc}"
    candidates = [
        f"{base}/onvif/ptz_service",
        f"{base}/onvif/PTZ",
        f"{base}/onvif/ptz",
    ]
    unique = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
    return unique


def add_credentials(url: str, username: str | None, password: str | None) -> str:
    if not username or password is None:
        return url
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    auth_host = f"{username}:{password}@{host}"
    return urlunparse((parsed.scheme, auth_host, parsed.path, parsed.params, parsed.query, parsed.fragment))


def discover_onvif_streams(ip: str, username: str | None, password: str | None, timeout: float) -> tuple[dict | None, list[dict]]:
    onvif = ws_discovery_probe(ip, timeout)
    streams = []

    if not onvif or not onvif.get("xaddrs") or not username or password is None:
        return onvif, streams

    onvif["ptz"] = {
        "available": False,
        "service_url": None,
        "profile_token": None,
        "profiles": [],
    }

    for media_url in media_service_candidates(onvif["xaddrs"]):
        response = soap_post(media_url, build_get_profiles(username, password), timeout)
        if not response or response.status_code != 200:
            continue

        profiles = parse_profiles(response.text)
        ptz_profiles = [profile["token"] for profile in profiles if profile.get("ptz")]
        if ptz_profiles:
            onvif["ptz"] = {
                "available": True,
                "service_url": ptz_service_candidates(onvif["xaddrs"])[0],
                "profile_token": ptz_profiles[0],
                "profiles": ptz_profiles,
            }

        for profile in profiles:
            uri_response = soap_post(
                media_url,
                build_get_stream_uri(username, password, profile["token"]),
                timeout,
            )
            if not uri_response or uri_response.status_code != 200:
                continue

            uri = extract_uri(uri_response.text)
            if uri:
                streams.append({
                    "source": "onvif",
                    "profile": profile,
                    "url": add_credentials(uri, username, password),
                    "plain_url": uri,
                    "service_url": media_url,
                })

        if streams:
            break

    return onvif, streams


def parse_ptz_status(xml_text: str) -> dict | None:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    status = {
        "pan": 0.0,
        "tilt": 0.0,
        "zoom": 0.0,
        "move_pan_tilt": None,
        "move_zoom": None,
        "utc_time": None,
    }

    for elem in root.iter():
        local = elem.tag.split("}")[-1]
        if local == "PanTilt":
            try:
                status["pan"] = float(elem.attrib.get("x", "0") or 0)
                status["tilt"] = float(elem.attrib.get("y", "0") or 0)
            except ValueError:
                pass
        elif local == "Zoom":
            try:
                status["zoom"] = float(elem.attrib.get("x", "0") or 0)
            except ValueError:
                pass
        elif local == "UtcTime":
            status["utc_time"] = elem.text

    move_status = None
    for elem in root.iter():
        if elem.tag.split("}")[-1] == "MoveStatus":
            move_status = elem
            break

    if move_status is not None:
        for child in move_status:
            local = child.tag.split("}")[-1]
            if local == "PanTilt":
                status["move_pan_tilt"] = child.text
            elif local == "Zoom":
                status["move_zoom"] = child.text

    return status


def parse_ptz_presets(xml_text: str) -> list[dict]:
    presets = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return presets

    for elem in root.iter():
        if elem.tag.split("}")[-1] != "Preset":
            continue

        token = elem.attrib.get("token")
        name = None
        for child in elem:
            if child.tag.split("}")[-1] == "Name":
                name = child.text
                break

        if token:
            presets.append({
                "token": token,
                "name": name or token,
            })

    presets.sort(key=lambda item: item["name"].lower())
    return presets


def extract_preset_token(xml_text: str) -> str | None:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    for elem in root.iter():
        if elem.tag.split("}")[-1] == "PresetToken":
            return elem.text

    return None


def ptz_get_status(service_url: str, username: str, password: str, profile_token: str, timeout: float) -> dict | None:
    response = soap_post(service_url, build_get_ptz_status(username, password, profile_token), timeout)
    if not response or response.status_code != 200:
        return None
    return parse_ptz_status(response.text)


def ptz_get_presets(service_url: str, username: str, password: str, profile_token: str, timeout: float) -> list[dict]:
    response = soap_post(service_url, build_get_presets(username, password, profile_token), timeout)
    if not response or response.status_code != 200:
        return []
    return parse_ptz_presets(response.text)


def ptz_set_preset(
    service_url: str,
    username: str,
    password: str,
    profile_token: str,
    preset_name: str,
    timeout: float,
) -> str | None:
    response = soap_post(service_url, build_set_preset(username, password, profile_token, preset_name), timeout)
    if not response or response.status_code != 200:
        return None
    return extract_preset_token(response.text)


def ptz_goto_preset(
    service_url: str,
    username: str,
    password: str,
    profile_token: str,
    preset_token: str,
    timeout: float,
) -> bool:
    response = soap_post(service_url, build_goto_preset(username, password, profile_token, preset_token), timeout)
    return bool(response and response.status_code == 200)


def ptz_remove_preset(
    service_url: str,
    username: str,
    password: str,
    profile_token: str,
    preset_token: str,
    timeout: float,
) -> bool:
    response = soap_post(service_url, build_remove_preset(username, password, profile_token, preset_token), timeout)
    return bool(response and response.status_code == 200)


def ptz_relative_move(
    service_url: str,
    username: str,
    password: str,
    profile_token: str,
    timeout: float,
    pan: float = 0.0,
    tilt: float = 0.0,
    zoom: float = 0.0,
) -> bool:
    response = soap_post(service_url, build_relative_move(username, password, profile_token, pan, tilt, zoom), timeout)
    return bool(response and response.status_code == 200)


def ptz_absolute_move(
    service_url: str,
    username: str,
    password: str,
    profile_token: str,
    timeout: float,
    pan: float,
    tilt: float,
    zoom: float,
) -> bool:
    response = soap_post(service_url, build_absolute_move(username, password, profile_token, pan, tilt, zoom), timeout)
    return bool(response and response.status_code == 200)


def rtsp_describe(ip: str, path: str, timeout: float) -> dict:
    target = f"rtsp://{ip}:554{path}"
    request = (
        f"DESCRIBE {target} RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "User-Agent: Linux Camera Tool\r\n"
        "Accept: application/sdp\r\n"
        "\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((ip, 554))
        sock.sendall(request.encode("utf-8"))
        response = sock.recv(4096).decode("utf-8", errors="ignore")
    except OSError as exc:
        return {"path": path, "status": None, "reason": str(exc), "www_authenticate": None}
    finally:
        sock.close()

    status_line = response.split("\r\n", 1)[0]
    match = re.match(r"RTSP/\d+\.\d+\s+(\d+)\s+(.*)", status_line)
    status = int(match.group(1)) if match else None
    reason = match.group(2).strip() if match else status_line
    www_authenticate = None

    for line in response.split("\r\n")[1:]:
        if line.lower().startswith("www-authenticate:"):
            www_authenticate = line.split(":", 1)[1].strip()
            break

    return {
        "path": path,
        "status": status,
        "reason": reason,
        "www_authenticate": www_authenticate,
    }


def stop_requested(stop_event=None) -> bool:
    return bool(stop_event and stop_event.is_set())


def discover_rtsp_candidates(
    ip: str,
    username: str | None,
    password: str | None,
    timeout: float,
    delay: float = 0.0,
    max_candidates: int | None = None,
    stop_event=None,
) -> list[dict]:
    candidates = []
    for index, path in enumerate(RTSP_PATHS):
        if stop_requested(stop_event):
            break

        result = rtsp_describe(ip, path, timeout)
        if result["status"] not in {200, 401, 403}:
            if delay > 0 and index < len(RTSP_PATHS) - 1:
                if stop_event and stop_event.wait(delay):
                    break
            continue

        plain_url = f"rtsp://{ip}:554{path}"
        candidates.append({
            "source": "rtsp-probe",
            "path": path,
            "status": result["status"],
            "reason": result["reason"],
            "auth": result["www_authenticate"],
            "plain_url": plain_url,
            "url": add_credentials(plain_url, username, password),
        })

        if max_candidates is not None and len(candidates) >= max_candidates:
            break

        if delay > 0 and index < len(RTSP_PATHS) - 1:
            if stop_event and stop_event.wait(delay):
                break
    return candidates


def ffprobe_ok(url: str, timeout: float) -> bool:
    try:
        result = subprocess.run(
            ["ffprobe", "-v", "error", "-rtsp_transport", "tcp", "-i", url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False

    return result.returncode == 0


def open_with_ffplay(
    url: str,
    transport: str = "auto",
    max_delay_us: int | None = None,
    disable_audio: bool = False,
    always_on_top: bool = False,
    window_title: str | None = None,
    borderless: bool = False,
) -> subprocess.Popen:
    cmd = ["ffplay"]

    if always_on_top:
        cmd.append("-alwaysontop")

    if borderless:
        cmd.append("-noborder")

    if window_title:
        cmd.extend(["-window_title", window_title])

    if transport in {"tcp", "udp"}:
        cmd.extend(["-rtsp_transport", transport])

    if max_delay_us is not None and max_delay_us > 0:
        cmd.extend(["-max_delay", str(max_delay_us)])

    if disable_audio:
        cmd.append("-an")

    cmd.append(url)
    return subprocess.Popen(cmd)


def print_camera_result(ip: str, onvif: dict | None, streams: list[dict], rtsp_candidates: list[dict]) -> None:
    print("=" * 80)
    print(f"Camera: {ip}")

    if onvif:
        print(f"ONVIF: sim ({onvif.get('xaddrs')})")
    else:
        print("ONVIF: sem resposta ao WS-Discovery")

    if streams:
        print("Streams ONVIF:")
        for stream in streams:
            profile = stream["profile"]
            size = ""
            if profile.get("width") and profile.get("height"):
                size = f" {profile['width']}x{profile['height']}"
            print(f"  {profile['token']} {profile['name']}{size} -> {stream['plain_url']}")

    if rtsp_candidates:
        print("RTSP candidatos:")
        for candidate in rtsp_candidates:
            auth = f" | auth: {candidate['auth']}" if candidate["auth"] else ""
            print(f"  {candidate['status']} {candidate['reason']} -> {candidate['plain_url']}{auth}")


def choose_open_url(streams: list[dict], rtsp_candidates: list[dict], timeout: float) -> str | None:
    for stream in streams:
        if ffprobe_ok(stream["url"], timeout):
            return stream["url"]

    for candidate in rtsp_candidates:
        if ffprobe_ok(candidate["url"], timeout):
            return candidate["url"]

    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Identifica cameras ONVIF/RTSP no Linux e opcionalmente abre o video."
    )
    parser.add_argument("ips", nargs="+", help="IPs das cameras.")
    parser.add_argument("--user", default="admin", help="Usuario da camera.")
    parser.add_argument("--password", help="Senha da camera.")
    parser.add_argument("--timeout", type=float, default=4.0, help="Timeout de rede em segundos.")
    parser.add_argument("--rtsp-delay", type=float, default=1.5, help="Espera entre tentativas RTSP.")
    parser.add_argument("--rtsp-max-candidates", type=int, default=2, help="Limita quantos candidatos RTSP guardar.")
    parser.add_argument("--skip-rtsp-when-onvif", action="store_true", help="Se ONVIF ja resolver a camera, nao testa RTSP direto.")
    parser.add_argument("--open", action="store_true", help="Abre o primeiro stream validado no ffplay.")
    args = parser.parse_args()

    for ip in args.ips:
        onvif, streams = discover_onvif_streams(ip, args.user, args.password, args.timeout)
        rtsp_candidates = []
        if not (args.skip_rtsp_when_onvif and streams):
            rtsp_candidates = discover_rtsp_candidates(
                ip,
                args.user,
                args.password,
                args.timeout,
                delay=args.rtsp_delay,
                max_candidates=args.rtsp_max_candidates,
            )
        print_camera_result(ip, onvif, streams, rtsp_candidates)

        if args.open:
            url = choose_open_url(streams, rtsp_candidates, args.timeout + 4)
            if url:
                print(f"Abrindo: {url}")
                open_with_ffplay(url, always_on_top=True, window_title=ip, borderless=True)
            else:
                print("Nao encontrei um stream validado automaticamente para abrir.")


if __name__ == "__main__":
    main()
