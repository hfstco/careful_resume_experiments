import os
import subprocess
import sys
import time

import pexpect


NUM_BACKGROUND_FLOWS = 8
START_PORT = 50001
SERVER="faui7s25"
CLIENT="skydsl"

def congested_path():
    current_time = time.strftime("%Y-%m-%d_%H-%M-%S")
    os.makedirs(current_time, exist_ok=True)

    # create dir on server
    subprocess.run(f"ssh {SERVER} -tt mkdir -p /tmp/{current_time}", stdout=sys.stdout, stderr=sys.stderr, shell=True)
    subprocess.run(f"ssh {CLIENT} -tt mkdir -p /tmp/{current_time}", stdout=sys.stdout, stderr=sys.stderr, shell=True)

    # start tcpdump
    tcpdump_server = subprocess.Popen(f"ssh {SERVER} -tt sudo tcpdump -i enp6s0 -s 96 -Z hfst -w /tmp/{current_time}/server.pcap portrange 50001-50009", encoding="utf-8", stdout=sys.stdout, stderr=sys.stderr, shell=True)
    tcpdump_client = subprocess.Popen(f"ssh {CLIENT} -tt sudo tcpdump -i enp6s0 -s 96 -Z hfst -w /tmp/{current_time}/client.pcap portrange 50001-50009", encoding="utf-8", stdout=sys.stdout, stderr=sys.stderr, shell=True)

    # create flow dirs on server
    background_servers = []
    for i in range(1, NUM_BACKGROUND_FLOWS + 1):
        subprocess.run(f"ssh {SERVER} -tt mkdir -p /tmp/{current_time}/background_{i}", stdout=sys.stdout, stderr=sys.stderr, shell=True)
    subprocess.run(f"ssh {SERVER} -tt mkdir -p /tmp/{current_time}/foreground", stdout=sys.stdout, stderr=sys.stderr, shell=True)

    # create flow dirs on client
    background_clients = []
    for i in range(1, NUM_BACKGROUND_FLOWS + 1):
        subprocess.run(f"ssh {CLIENT} -tt mkdir -p /tmp/{current_time}/background_{i}", stdout=sys.stdout, stderr=sys.stderr, shell=True)
    subprocess.run(f"ssh {CLIENT} -tt mkdir -p /tmp/{current_time}/foreground", stdout=sys.stdout, stderr=sys.stderr, shell=True)

    # start background servers
    for i in range(1, NUM_BACKGROUND_FLOWS + 1):
        #background_server = subprocess.Popen(f"ssh {SERVER} -tt iperf3 -s -1 -p {START_PORT + i}", stdout=sys.stdout, stderr=sys.stderr, shell=True)
        background_server = subprocess.Popen(
           f"ssh {SERVER} -tt PREVIOUS_CWND_BYTES=0 PREVIOUS_RTT=0 SSLKEYLOGFILE=/tmp/{current_time}/background_{i}/server.tls /home/hfst/picoquic-cr/picoquicdemo "
           f"-8 -k /home/hfst/.acme.sh/quic.hfst.dev/quic.hfst.dev.key -c /home/hfst/.acme.sh/quic.hfst.dev/fullchain.cer -p {50001 + i} -1 -G cubic",
           stdout=sys.stdout, stderr=sys.stderr, shell=True)
        background_servers.append(background_server)

    # start foreground servers
    #foreground_server = subprocess.Popen(f"ssh {SERVER} -tt iperf3 -s -1 -p {START_PORT}", stdout=sys.stdout, stderr=sys.stderr, shell=True)
    foreground_server = subprocess.Popen(
       f"ssh {SERVER} -tt PREVIOUS_CWND_BYTES=0 PREVIOUS_RTT=0 SSLKEYLOGFILE=/tmp/{current_time}/foreground/server.tls /home/hfst/picoquic-cr/picoquicdemo "
       f"-8 -k /home/hfst/.acme.sh/quic.hfst.dev/quic.hfst.dev.key -c /home/hfst/.acme.sh/quic.hfst.dev/fullchain.cer -p {50001} -1 -G cubic",
       stdout=sys.stdout, stderr=sys.stderr, shell=True)

    time.sleep(3)

    # start background clients
    for i in range(1, NUM_BACKGROUND_FLOWS + 1):
        #background_client = subprocess.Popen(f"ssh {CLIENT} -tt iperf3 -c faui7s25.informatik.uni-erlangen.de -t 0 -R -p {START_PORT + i}", stdout=sys.stdout, stderr=sys.stderr, shell=True)
        background_client = subprocess.Popen(
           f"ssh {CLIENT} -tt SSLKEYLOGFILE=/tmp/{current_time}/background_{i}/client.tls /home/hfst/picoquic-cr/picoquicdemo "
           f"-8 -G cubic faui7s25.informatik.uni-erlangen.de {50001 + i} /{1000 * 1000000}",
           stdout=sys.stdout, stderr=sys.stderr, shell=True)
        background_clients.append(background_client)

    time.sleep(15)

    # start foreground clients
    #foreground_client = subprocess.Popen(f"ssh {CLIENT} -t iperf3 -c faui7s25.informatik.uni-erlangen.de -t 0 -R -p {START_PORT}", stdout=sys.stdout, stderr=sys.stderr, shell=True)
    foreground_client = subprocess.Popen(
       f"ssh {CLIENT} -tt SSLKEYLOGFILE=/tmp/{current_time}/foreground/client.tls /home/hfst/picoquic-cr/picoquicdemo -8 -G cubic faui7s25.informatik.uni-erlangen.de {50001} /{1000 * 1000000}",
       stdout=sys.stdout, stderr=sys.stderr, shell=True)

    time.sleep(25)

    for client in background_clients + [foreground_client]:
        client.terminate()
    for server in background_servers + [foreground_server]:
        server.terminate()

    time.sleep(5)

    tcpdump_server.terminate()
    tcpdump_client.terminate()

    time.sleep(5)

    subprocess.run([f"rsync -auvP {SERVER}:/tmp/{current_time} ."], stdout=sys.stdout, stderr=sys.stderr, shell=True)
    subprocess.run([f"rsync -auvP {CLIENT}:/tmp/{current_time} ."], stdout=sys.stdout, stderr=sys.stderr, shell=True)

    #delete dirs
    subprocess.run(f"ssh {SERVER} -tt rm -R /tmp/{current_time}", stdout=sys.stdout, stderr=sys.stderr, shell=True)
    subprocess.run(f"ssh {CLIENT} -tt rm -R /tmp/{current_time}", stdout=sys.stdout, stderr=sys.stderr, shell=True)



if __name__ == "__main__":
    current_time = time.strftime("%Y-%m-%d_%H-%M-%S")
    os.makedirs(current_time, exist_ok=True)
    os.chdir(current_time)
    for i in range(10):
        congested_path()
