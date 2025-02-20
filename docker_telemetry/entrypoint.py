import subprocess
import signal
import sys
import time
import select
import os
import requests
import json
from datetime import datetime, timezone

IFACE = os.getenv("IFACE", "eth0")
RETH = os.getenv("RETH", "http://127.0.0.1:8545")
LIGHTHOUSE = os.getenv("LIGHTHOUSE", "http://127.0.0.1:5052")


subprocess.run(["sysctl", "-w", "net.ipv4.icmp_echo_ignore_broadcasts=1"])
subprocess.run(["sysctl", "-w", "net.ipv4.icmp_ignore_bogus_error_responses=1"])

# Enable packet forwarding
subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])

# Set up iptables rules for NAT
subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", "eth0", "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", "1.1.1.1:80"])
subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"])

DUMPS_STORAGE = "/dumps"
START_TIME = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H-%M-%S.%f')[:-3]

# List of commands to run as background processes

commands = [
    ["tcpdump", "-i", IFACE, "-n", "-vvv", "-s", "80", "-C", "10", "-w", f"{DUMPS_STORAGE}/{START_TIME}-tcpdump.pcap", "not", "port", "22"],
#    ["tcpdump", "-U", "-i", "lo", "-n", "-vvv", "-X", "-w", f"{DUMPS_STORAGE}/{START_TIME}-netflow.pcap", "udp", "port", "2055"],
#    ["softflowd", "-i", "eth0", "-n", "127.0.0.1:2055", "-v", "10", "-P", "udp", "-D"],
]

processes = []

def start_processes():
    print("Starting processes...")
    for command in commands:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,  # Ensures text output instead of bytes
            bufsize=1  # Enables line buffering
        )

        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        processes.append(process)
        print(f"Started: {' '.join(command)} (PID: {process.pid})")

def stop_processes():
    for process in processes:
        print(f"Stopping PID {process.pid}")
        process.terminate()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            print(f"Process {process.pid} did not terminate, killing it")
            process.kill()
            process.wait()
        print(f"Process {process.pid} terminated")

def signal_handler(sig, frame):
    print("Received stop signal, shutting down...")
    stop_processes()
    sys.exit(0)

def dump_lighthouse_api_peers():
    LIGHTHOUSE_PEERS_HTTP_URI = f"{LIGHTHOUSE}/lighthouse/peers/"
    try:
        response = requests.get(LIGHTHOUSE_PEERS_HTTP_URI)
        response.raise_for_status()
        iso_datitime = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H-%M-%S.%f')[:-3]
        file_path = f"{DUMPS_STORAGE}/{iso_datitime}-cons-peers.json"
        with open(file_path, 'w') as file:
            file.write(response.text)
        peers_total = len(json.loads(response.text))
        print(f"Consensus peers are fetched and dumped to {file_path}. Total:{peers_total}")
    except requests.RequestException as e:
        print(f"Failed to fetch peers from ETH2 {e}")

def dump_execution_api_peers():
    url = RETH
    headers = {"Content-Type": "application/json"}
    payload = {
        "jsonrpc": "2.0",
        "method": "admin_peers",
        "params": [],
        "id": 1
    }
    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        iso_datitime = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H-%M-%S.%f')[:-3]
        file_path = f"{DUMPS_STORAGE}/{iso_datitime}-exec-peers.json"
        peers = response.json().get("result", [])
        with open(file_path, 'w') as file:
            file.write(json.dumps(peers))
        peers_total = len(peers)
        print(f"Execution peers are fetched and dumped to {file_path}. Total:{peers_total}")
    except requests.RequestException as e:
        print(f"Failed to fetch peers from ETH1: {e}")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    start_processes()

    try:
        while True:
            for process in processes:
                # Check if the process has terminated
                if process.poll() is not None:
                    if process.returncode != 0:
                        print(f"Process {process.pid} failed with return code {process.returncode}", file=sys.stderr)
                    processes.remove(process)
                line = process.stdout.readline()
                if line:
                    print(line, flush=True)
                line = process.stderr.readline()
                if line:
                    print(line, flush=True)
            dump_lighthouse_api_peers()
            dump_execution_api_peers()
            time.sleep(10)  # Reduce CPU usage
    except KeyboardInterrupt:
        pass
    finally:
        stop_processes()
