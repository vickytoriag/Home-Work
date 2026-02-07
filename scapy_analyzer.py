import argparse
import socket
import random
import time
from urllib.parse import urlparse

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, send
from scapy.all import sniff, wrpcap, rdpcap


def resolve_hostname(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Ошибка разрешения имени {hostname}: {e}")
        return None


def parse_url(url_arg):
    if not url_arg.startswith("http://") and not url_arg.startswith("https://"):
        url_arg = "http://" + url_arg

    parsed = urlparse(url_arg)
    hostname = parsed.hostname
    path = parsed.path if parsed.path else "/"
    scheme = parsed.scheme or "http"
    return hostname, path, scheme


def send_http_request(hostname, path):
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return

    port = 80
    sport = random.randint(1025, 65500)

    http_request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        f"Connection: close\r\n\r\n"
    )

    syn = IP(dst=dest_ip) / TCP(sport=sport, dport=port, flags="S")
    syn_ack = sr1(syn, timeout=5, verbose=False)

    if not syn_ack:
        print("Не удалось установить соединение")
        return

    ack = IP(dst=dest_ip) / TCP(
        sport=sport,
        dport=port,
        seq=syn_ack.ack,
        ack=syn_ack.seq + 1,
        flags="A",
    )
    send(ack, verbose=False)

    pkt = IP(dst=dest_ip) / TCP(
        sport=sport,
        dport=port,
        seq=syn_ack.ack,
        ack=syn_ack.seq + 1,
        flags="PA",
    ) / http_request

    send(pkt, verbose=False)
    print("HTTP-запрос отправлен")


def capture_traffic(hostname, timeout=30, output_file=None):
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None

    print(f"Перехват трафика для {hostname} ({dest_ip})")
    packets = sniff(
        filter=f"tcp and host {dest_ip} and port 80",
        timeout=timeout
    )

    print(f"Перехвачено пакетов: {len(packets)}")

    if output_file:
        wrpcap(output_file, packets)
        print(f"Трафик сохранен в файл: {output_file}")

    return packets


def analyze_packets(packets):
    if not packets:
        print("Нет пакетов для анализа")
        return

    http_packets = []
    for pkt in packets:
        if pkt.haslayer("Raw"):
            data = pkt["Raw"].load.decode(errors="ignore")
            if data.startswith("GET") or data.startswith("POST") or data.startswith("HTTP"):
                http_packets.append(data)

    print(f"Найдено HTTP сообщений: {len(http_packets)}")

    for i, msg in enumerate(http_packets[:3], 1):
        print(f"\nHTTP сообщение {i}:\n{msg[:300]}")


def analyze_pcap(file_name):
    packets = rdpcap(file_name)
    analyze_packets(packets)


def main():
    parser = argparse.ArgumentParser(description="Scapy HTTP analyzer (учебное задание)")
    parser.add_argument("--send", help="Отправить HTTP запрос")
    parser.add_argument("--capture", help="Перехватить трафик")
    parser.add_argument("--analyze", help="Проанализировать pcap файл")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--output", help="Файл для сохранения трафика")

    args = parser.parse_args()

    if args.send:
        host, path, _ = parse_url(args.send)
        send_http_request(host, path)

    if args.capture:
        packets = capture_traffic(args.capture, args.timeout, args.output)
        analyze_packets(packets)

    if args.analyze:
        analyze_pcap(args.analyze)


if __name__ == "__main__":
    main()
