import paramiko
import sys

## EDIT SSH DETAILS ##

SSH_ADDRESS = "pub-compute-001"
#SSH_ADDRESS = raw_input('SSH_ADDRESS: ')
SSH_USERNAME = "root"
SSH_PASSWORD = "password"
SSH_KEY_FILE = "/root/.ssh/id_rsa"
#SSH_COMMAND = "hostname -f"
SSH_COMMAND = "ovs-vsctl list-br"

## CODE BELOW ##

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

ssh_stdin = ssh_stdout = ssh_stderr = None

try:
    #ssh.connect(SSH_ADDRESS, username=SSH_USERNAME, password=SSH_PASSWORD)
    ssh.connect(SSH_ADDRESS, 22, username=SSH_USERNAME, key_filename=SSH_KEY_FILE)
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(SSH_COMMAND)
except Exception as e:
    sys.stderr.write("SSH connection error: {0}".format(e))

#if ssh_stdout:
#    sys.stdout.write(ssh_stdout.read())
#if ssh_stderr:
#    sys.stderr.write(ssh_stderr.read())

#if ssh_stdout:
#	bridges = [line.rstrip('\n') for line in ssh_stdout.readlines()]
#	print(bridges)
#	if bridges:
#		for br in bridges:
