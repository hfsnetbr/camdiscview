#!/usr/bin/env python3
import argparse
import base64
import hashlib
import os
import datetime
import requests


def wsse_password_digest(password: str):
    nonce = os.urandom(16)
    created = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    digest = hashlib.sha1(
        nonce + created.encode("utf-8") + password.encode("utf-8")
    ).digest()

    return (
        base64.b64encode(nonce).decode("ascii"),
        created,
        base64.b64encode(digest).decode("ascii"),
    )


def build_get_profiles(username: str, password: str, mode: str):
    if mode == "digest":
        nonce, created, password_value = wsse_password_digest(password)
        password_type = (
            "http://docs.oasis-open.org/wss/2004/01/"
            "oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
        )

        extra = f"""
        <wsse:Nonce>{nonce}</wsse:Nonce>
        <wsu:Created>{created}</wsu:Created>
        """

    else:
        password_value = password
        password_type = (
            "http://docs.oasis-open.org/wss/2004/01/"
            "oasis-200401-wss-username-token-profile-1.0#PasswordText"
        )
        extra = ""

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope
  xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
  xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <wsse:Security s:mustUnderstand="1">
      <wsse:UsernameToken>
        <wsse:Username>{username}</wsse:Username>
        <wsse:Password Type="{password_type}">{password_value}</wsse:Password>
        {extra}
      </wsse:UsernameToken>
    </wsse:Security>
  </s:Header>
  <s:Body>
    <trt:GetProfiles/>
  </s:Body>
</s:Envelope>"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://192.168.1.16:10000/onvif/media_service")
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--mode", choices=["digest", "text"], default="digest")
    args = parser.parse_args()

    xml = build_get_profiles(args.user, args.password, args.mode)

    print(f"Testando WS-Security {args.mode} com usuário {args.user}")

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
    print(r.text)


if __name__ == "__main__":
    main()
