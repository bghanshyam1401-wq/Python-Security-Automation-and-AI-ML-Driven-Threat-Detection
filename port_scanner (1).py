import socket
import threading
import argparse

open_ports = []
lock = threading.Lock()


def scan_port(target, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set timeout so the scanner does not hang on filtered ports
        sock.settimeout(timeout)

        result = sock.connect_ex((target, port))

        if result == 0:
            banner = ""

            try:
                sock.send(b"\r\n")

                # Decode banner safely to avoid errors from unusual bytes
                banner = sock.recv(1024).decode(
                    errors="ignore"
                ).strip()

            except Exception:
                banner = "No banner"

            # Lock prevents multiple threads writing to the list simultaneously
            with lock:
                open_ports.append((port, "Open", banner))

        sock.close()

    except (
        socket.timeout,
        ConnectionRefusedError,
        OSError
    ):
        pass


def main():
    parser = argparse.ArgumentParser(
        description="Multithreaded Port Scanner"
    )

    parser.add_argument("target")
    parser.add_argument("start_port", type=int)
    parser.add_argument("end_port", type=int)

    parser.add_argument(
        "--timeout",
        type=float,
        default=1
    )

    args = parser.parse_args()

    threads = []

    for port in range(
        args.start_port,
        args.end_port + 1
    ):
        t = threading.Thread(
            target=scan_port,
            args=(args.target, port, args.timeout)
        )

        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("\nPort | State | Banner")
    print("-" * 60)

    for port, state, banner in sorted(open_ports):
        print(f"{port:<5}| {state:<5}| {banner}")


if __name__ == "__main__":
    main()
