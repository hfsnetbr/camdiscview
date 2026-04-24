#!/usr/bin/env python3
import argparse
import base64
import hashlib
import os
import datetime
import requests
import xml.etree.ElementTree as ET


def wsse_password_digest(password: str):
    nonce = os.urandom(16)
    created = datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    digest = hashlib.sha1(
        nonce + created.encode("utf-8") + password.encode("utf-8")
    ).digest()

    return (
        base64.b64encode(nonce).decode("ascii"),
        created,
        base64.b64encode(digest).decode("ascii"),
    )


def build_get_stream_uri(username: str, password: str, profile_token: str):
    nonce, created, password_digest = wsse_password_digest(password)

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope
  xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
  xmlns:tt="http://www.onvif.org/ver10/schema"
  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
  xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <wsse:Security s:mustUnderstand="1">
      <wsse:UsernameToken>
        <wsse:Username>{username}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{password_digest}</wsse:Password>
        <wsse:Nonce>{nonce}</wsse:Nonce>
        <wsu:Created>{created}</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
  </s:Header>
  <s:Body>
    <trt:GetStreamUri>
      <trt:StreamSetup>
        <tt:Stream>RTP-Unicast</tt:Stream>
        <tt:Transport>
          <tt:Protocol>RTSP</tt:Protocol>
        </tt:Transport>
      </trt:StreamSetup>
      <trt:ProfileToken>{profile_token}</trt:ProfileToken>
    </trt:GetStreamUri>
  </s:Body>
</s:Envelope>"""


def extract_uri(xml_text: str):
    root = ET.fromstring(xml_text)

    for elem in root.iter():
        if elem.tag.split("}")[-1] == "Uri":
            return elem.text

    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://192.168.1.16:10000/onvif/media_service")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--password", required=True)
    parser.add_argument("--profile", default="PROFILE_000")
    args = parser.parse_args()

    xml = build_get_stream_uri(args.user, args.password, args.profile)

    r = requests.post(
        args.url,
        data=xml.encode("utf-8"),
        headers={
            "Content-Type": "application/soap+xml; charset=utf-8",
            "User-Agent": "ONVIF WSSE Client",
            "Connection": "close",
        },
        timeout=10,
    )

    print("HTTP:", r.status_code)

    if r.status_code != 200:
        print(r.text)
        return

    uri = extract_uri(r.text)

    if uri:
        print("RTSP:", uri)
    else:
        print("Não encontrei URI na resposta:")
        print(r.text)


if __name__ == "__main__":
    main()
