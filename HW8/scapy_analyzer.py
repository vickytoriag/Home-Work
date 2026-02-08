import argparse
import socket
import random
from urllib.parse import urlparse

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, send
from scapy.all import sniff, wrpcap, rdpcap
from scapy.packet import Raw


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


def capture_traffic(timeout=60, output_file=None):
    print("Перехват HTTP трафика (tcp port 80)...")
    packets = sniff(filter="tcp port 80", timeout=timeout)

    print(f"Перехвачено пакетов: {len(packets)}")

    if output_file and len(packets) > 0:
        wrpcap(output_file, packets)
        print(f"Трафик сохранен в файл: {output_file}")

    return packets


def analyze_packets(packets, host_filter="google-gruyere.appspot.com"):
    if not packets or len(packets) == 0:
        print("Нет пакетов для анализа")
        return

    http_messages = []
    for pkt in packets:
        if pkt.haslayer(Raw):
            raw_bytes = pkt[Raw].load
            text = raw_bytes.decode("utf-8", errors="ignore")

            if text.startswith("GET ") or text.startswith("POST ") or text.startswith("HTTP/"):
                if f"Host: {host_filter}" in text or text.startswith("HTTP/"):
                    http_messages.append(text)

    print(f"Найдено HTTP сообщений: {len(http_messages)}")

    for i, msg in enumerate(http_messages[:5], 1):
        print()
        print(f"HTTP-сообщение {i} (первые 300 символов)")
        print(msg[:300])


def analyze_pcap(file_name):
    packets = rdpcap(file_name)
    analyze_packets(packets)


def main():
    parser = argparse.ArgumentParser(description="Scapy HTTP analyzer (учебное задание)")

    parser.add_argument("--send", help="Отправить HTTP запрос (пример: http://example.com)")
    parser.add_argument("--capture", action="store_true", help="Перехватить HTTP трафик (port 80)")
    parser.add_argument("--analyze", help="Проанализировать pcap файл")
    parser.add_argument("--timeout", type=int, default=60, help="Таймаут перехвата в секундах")
    parser.add_argument("--output", default="traffic.pcap", help="Файл для сохранения трафика (pcap)")

    args = parser.parse_args()

    if not any([args.send, args.capture, args.analyze]):
        parser.print_help()
        return

    if args.send:
        host, path, scheme = parse_url(args.send)
        if scheme == "https":
            print("Примечание: скрипт отправляет запрос на port 80 (http).")
        send_http_request(host, path)

    if args.capture:
        packets = capture_traffic(args.timeout, args.output)
        analyze_packets(packets, host_filter="google-gruyere.appspot.com")

    if args.analyze:
        analyze_pcap(args.analyze)


if __name__ == "__main__":
    main()