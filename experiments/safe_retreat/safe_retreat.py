import os
import shlex
import subprocess
import sys
import time
from logger import Logger


START_PORT = 51001
SERVER="faui7s25"
CLIENT="brdy"

def congested_path():
    current_time = time.strftime("%Y-%m-%d_%H-%M-%S")
    os.makedirs(current_time, exist_ok=True)

    # create dir on server
    subprocess.run(shlex.split(f"ssh {SERVER} -tt mkdir -p /tmp/{current_time}"), stdout=sys.stdout, stderr=sys.stderr, stdin=sys.stdin)
    subprocess.run(shlex.split(f"ssh {CLIENT} -tt mkdir -p /tmp/{current_time}"), stdout=sys.stdout, stderr=sys.stderr, stdin=sys.stdin)

    # start tcpdump
    tcpdump_server = subprocess.Popen(shlex.split(f"ssh {SERVER} -tt sudo tcpdump -i any -s 96 -w /tmp/{current_time}/server.pcap portrange 50001-50009"), stdout=sys.stdout, stderr=sys.stderr, stdin=sys.stdin)
    tcpdump_client = subprocess.Popen(shlex.split(f"ssh {CLIENT} -tt sudo tcpdump -i any -s 96 -w /tmp/{current_time}/client.pcap portrange 50001-50009"), stdout=sys.stdout, stderr=sys.stderr, stdin=sys.stdin)

    time.sleep(5)

    # start foreground servers
    server = subprocess.Popen(
       shlex.split(f"ssh {SERVER} -tt PREVIOUS_CWND_BYTES=37500000 PREVIOUS_RTT=600000 SSLKEYLOGFILE=/tmp/{current_time}/server.tls /home/hfst/picoquic-cr/picoquicdemo -8 -k /home/hfst/.acme.sh/quic.hfst.dev/quic.hfst.dev.key -c /home/hfst/.acme.sh/quic.hfst.dev/fullchain.cer -q /tmp/{current_time}/ -p {50001} -1 -G cubic"), stdout=sys.stdout, stderr=sys.stderr, stdin=sys.stdin)

    time.sleep(3)

    # start foreground clients
    client = subprocess.Popen(
       shlex.split(f"ssh {CLIENT} -tt SSLKEYLOGFILE=/tmp/{current_time}/client.tls /home/hfst/picoquic-cr/picoquicdemo -8 -G cubic -q /tmp/{current_time}/ faui7s25.informatik.uni-erlangen.de {50001} /{50 * 1000000}"), stdout=sys.stdout, stderr=sys.stderr, stdin=sys.stdin)

    client.wait()
    server.wait()

    tcpdump_server.terminate()
    tcpdump_client.terminate()

    time.sleep(5)

    subprocess.run([f"rsync -auvP {SERVER}:/tmp/{current_time} ."], stdout=sys.stdout, stderr=sys.stderr, shell=True)
    subprocess.run([f"rsync -auvP {CLIENT}:/tmp/{current_time} ."], stdout=sys.stdout, stderr=sys.stderr, shell=True)


if __name__ == "__main__":
    current_time = time.strftime("%Y-%m-%d_%H-%M-%S")
    os.makedirs(current_time, exist_ok=True)
    os.chdir(current_time)
    for i in range(10):
        congested_path()
