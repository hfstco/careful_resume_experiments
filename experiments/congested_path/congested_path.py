import os
import subprocess
import sys
import time

import pexpect


NUM_BACKGROUND_FLOWS = 8
START_PORT = 50001

def main():
    current_time = time.strftime("%Y-%m-%d_%H-%M-%S")
    os.makedirs(current_time, exist_ok=True)

    # create dir on server
    print(f"Creating /tmp/{current_time} on server...", end='')
    pexpect.run(f"ssh faui7s25 -t mkdir -p /tmp/{current_time}")
    print("done", flush=True)
    print(f"Creating /tmp/{current_time} on client...", end='')
    pexpect.run(f"ssh skydsl -t mkdir -p /tmp/{current_time}")
    print("done", flush=True)

    # start tcpdump
    tcpdump_server = pexpect.spawn(f"ssh faui7s25 -t sudo tcpdump -i enp6s0 -s 96 -w /tmp/{current_time}/server.pcap portrange 50001-50009", encoding="utf-8", logfile=sys.stdout)
    tcpdump_client = pexpect.spawn(f"ssh skydsl -t sudo tcpdump -i enp6s0 -s 96 -w /tmp/{current_time}/client.pcap portrange 50001-50009", encoding="utf-8", logfile=sys.stdout)

    tcpdump_server.expect("listening on enp6s0")
    tcpdump_client.expect("listening on enp6s0")

    # create flow dirs on server
    background_servers = []
    for i in range(1, NUM_BACKGROUND_FLOWS + 1):
        pexpect.run(f"ssh faui7s25 -t mkdir -p /tmp/{current_time}/background_{i}")
    pexpect.run(f"ssh faui7s25 -t mkdir -p /tmp/{current_time}/foreground")

    # create flow dirs on client
    background_clients = []
    for i in range(1, NUM_BACKGROUND_FLOWS + 1):
        pexpect.run(f"ssh skydsl -t mkdir -p /tmp/{current_time}/background_{i}")
    pexpect.run(f"ssh skydsl -t mkdir -p /tmp/{current_time}/foreground")

    # start background servers
    for i in range(1, NUM_BACKGROUND_FLOWS + 1):
        print(f"Starting background server {i}...", end='')
        background_server = pexpect.spawn(f"ssh faui7s25 -t iperf3 -s -1 -p {START_PORT + i}", logfile=sys.stdout)
        #background_server = pexpect.spawn(
        #    f"ssh faui7s25 -t PREVIOUS_CWND_BYTES=0 PREVIOUS_RTT=0 SSLKEYLOGFILE=/tmp/{current_time}/background_{i}/server.tls /home/hfst/picoquic-cr/picoquicdemo "
        #    f"-8 -k /home/hfst/.acme.sh/quic.hfst.dev/quic.hfst.dev.key -c /home/hfst/.acme.sh/quic.hfst.dev/fullchain.cer -p {50001 + i} -1 -G cubic",
        #    logfile=sys.stdout)
        background_servers.append(background_server)
        print("done")

    # start foreground servers
    print("Starting foreground server...", end='')
    foreground_server = pexpect.spawn(f"ssh faui7s25 -t iperf3 -s -1 -p {START_PORT}", logfile=sys.stdout)
    print("done")

    time.sleep(3)

    # start background clients
    for i in range(1, NUM_BACKGROUND_FLOWS + 1):
        print(f"Starting background client {i}...", end='')
        background_client = pexpect.spawn(f"ssh skydsl -t iperf3 -c faui7s25.informatik.uni-erlangen.de -t 0 -R -p {START_PORT + i}", logfile=sys.stdout)
        #background_client = pexpect.spawn(
        #    f"ssh skydsl -t SSLKEYLOGFILE=/tmp/{current_time}/background_{i}/client.tls /home/hfst/picoquic-cr/picoquicdemo "
        #    f"-8 -G cubic faui7s25.informatik.uni-erlangen.de {50001 + i} /{1000 * 1000000}",
        #    logfile=sys.stdout)
        background_clients.append(background_client)
        print("done")

    time.sleep(15)

    # start foreground clients
    print("Starting foreground client...", end='')
    foreground_client = pexpect.spawn(f"ssh skydsl -t iperf3 -c faui7s25.informatik.uni-erlangen.de -t 0 -R -p {START_PORT}", logfile=sys.stdout)
    print("done")

    time.sleep(15)

    print("Stopping all servers and clients...", end='')
    for client in background_clients + [foreground_client]:
        client.terminate()
    for server in background_servers + [foreground_server]:
        server.terminate()
    print("done")

    time.sleep(5)

    tcpdump_server.terminate()
    tcpdump_client.terminate()

    time.sleep(5)

    subprocess.run([f"rsync -auvP faui7s25:/tmp/{current_time} ."], stdout=sys.stdout, stderr=sys.stderr, shell=True)
    subprocess.run([f"rsync -auvP skydsl:/tmp/{current_time} ."], stdout=sys.stdout, stderr=sys.stderr, shell=True)


if __name__ == "__main__":
    main()
