#!/usr/bin/env python3
import argparse
import subprocess
import requests
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin


DEFAULT_PORTS = [80, 8080, 8000, 8899, 8999, 5000, 554]

ONVIF_PATHS = [
    "/onvif/device_service",
    "/onvif/Device",
    "/onvif/device",
    "/onvif/services",
]

SOAP_PROBE = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <GetCapabilities xmlns="http://www.onvif.org/ver10/device/wsdl">
      <Category>All</Category>
    </GetCapabilities>
  </s:Body>
</s:Envelope>
"""


def run_nmap(network: str, ports: list[int]) -> dict[str, list[int]]:
    """
    Retorna:
    {
        "192.168.1.10": [80, 554],
        "192.168.1.11": [8080]
    }
    """

    port_str = ",".join(str(p) for p in ports)

    cmd = [
        "nmap",
        "-n",
        "-Pn",
        "-p",
        port_str,
        "--open",
        "-oX",
        "-",
        network,
    ]

    print(f"[INFO] Executando Nmap em {network} nas portas {port_str}")

    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Erro ao executar nmap:\n{result.stderr}")

    hosts = {}

    root = ET.fromstring(result.stdout)

    for host in root.findall("host"):
        address_node = host.find("address")
        if address_node is None:
            continue

        ip = address_node.attrib.get("addr")
        if not ip:
            continue

        open_ports = []

        ports_node = host.find("ports")
        if ports_node is None:
            continue

        for port_node in ports_node.findall("port"):
            port_id = int(port_node.attrib.get("portid"))

            state_node = port_node.find("state")
            if state_node is not None and state_node.attrib.get("state") == "open":
                open_ports.append(port_id)

        if open_ports:
            hosts[ip] = open_ports

    return hosts


def looks_like_onvif_response(text: str) -> bool:
    text_lower = text.lower()

    indicators = [
        "onvif",
        "getcapabilitiesresponse",
        "device_service",
        "soap",
        "envelope",
        "tds:",
        "trt:",
        "media",
        "ptz",
    ]

    return any(indicator in text_lower for indicator in indicators)


def test_onvif_endpoint(ip: str, port: int, timeout: float = 3.0) -> dict | None:
    scheme = "http"

    for path in ONVIF_PATHS:
        url = f"{scheme}://{ip}:{port}{path}"

        try:
            response = requests.post(
                url,
                data=SOAP_PROBE,
                headers={
                    "Content-Type": "application/soap+xml; charset=utf-8",
                    "User-Agent": "Python ONVIF Scanner",
                },
                timeout=timeout,
                verify=False,
            )

            body = response.text or ""

            if response.status_code in [200, 400, 401, 403, 500] and looks_like_onvif_response(body):
                return {
                    "ip": ip,
                    "port": port,
                    "url": url,
                    "status": response.status_code,
                    "auth_required": response.status_code in [401, 403],
                    "method": "POST SOAP",
                }

        except requests.RequestException:
            pass

        try:
            response = requests.get(
                url,
                headers={
                    "User-Agent": "Python ONVIF Scanner",
                },
                timeout=timeout,
                verify=False,
            )

            body = response.text or ""

            if response.status_code in [200, 400, 401, 403, 405, 500] and looks_like_onvif_response(body):
                return {
                    "ip": ip,
                    "port": port,
                    "url": url,
                    "status": response.status_code,
                    "auth_required": response.status_code in [401, 403],
                    "method": "GET",
                }

        except requests.RequestException:
            pass

    return None


def scan_host(ip: str, open_ports: list[int], timeout: float) -> dict:
    result = {
        "ip": ip,
        "open_ports": open_ports,
        "onvif": False,
        "onvif_url": None,
        "onvif_port": None,
        "http_status": None,
        "auth_required": False,
        "rtsp": 554 in open_ports,
    }

    candidate_ports = [p for p in open_ports if p != 554]

    for port in candidate_ports:
        onvif_result = test_onvif_endpoint(ip, port, timeout)

        if onvif_result:
            result["onvif"] = True
            result["onvif_url"] = onvif_result["url"]
            result["onvif_port"] = onvif_result["port"]
            result["http_status"] = onvif_result["status"]
            result["auth_required"] = onvif_result["auth_required"]
            break

    return result


def print_results(results: list[dict]):
    print()
    print("=" * 80)
    print("RESULTADO")
    print("=" * 80)

    found = False

    for item in results:
        if item["onvif"]:
            found = True
            print()
            print(f"[ONVIF] {item['ip']}")
            print(f"  Portas abertas: {item['open_ports']}")
            print(f"  Endpoint: {item['onvif_url']}")
            print(f"  Status HTTP: {item['http_status']}")
            print(f"  Requer autenticação: {'sim' if item['auth_required'] else 'não identificado'}")
            print(f"  RTSP 554 aberto: {'sim' if item['rtsp'] else 'não'}")

    if not found:
        print("Nenhuma câmera ONVIF confirmada.")

    print()
    print("Hosts com portas abertas encontrados:")
    for item in results:
        print(f"  {item['ip']} -> {item['open_ports']}")


def main():
    parser = argparse.ArgumentParser(
        description="Scanner ONVIF usando Nmap + teste de endpoints ONVIF"
    )

    parser.add_argument(
        "network",
        help="Rede ou IP para varrer. Ex: 192.168.1.0/24 ou 192.168.1.50",
    )

    parser.add_argument(
        "--ports",
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help="Portas para testar. Ex: 80,8080,8899,554",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Timeout HTTP por tentativa",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Quantidade de threads",
    )

    args = parser.parse_args()

    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]

    hosts = run_nmap(args.network, ports)

    if not hosts:
        print("Nenhum host com portas abertas encontrado.")
        return

    print(f"[INFO] Hosts encontrados: {len(hosts)}")

    results = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(scan_host, ip, open_ports, args.timeout)
            for ip, open_ports in hosts.items()
        ]

        for future in as_completed(futures):
            result = future.result()
            results.append(result)

            if result["onvif"]:
                print(f"[ONVIF] {result['ip']} -> {result['onvif_url']}")
            else:
                print(f"[NO] {result['ip']} -> portas {result['open_ports']}")

    results.sort(key=lambda x: x["ip"])
    print_results(results)


if __name__ == "__main__":
    main()
