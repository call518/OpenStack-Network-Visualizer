#!/usr/bin/env python
# -*- mode:python; coding:utf-8 -*-

## ex) python find-interface-by-vm-uuid.py -u 090cc0be-4061-4974-b8a1-9f44d1467691

import paramiko
import time
import sys, getopt
import json
import socket
import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import random
import operator

def exec_ssh(ssh_hostname, ssh_cmd):
	SSH_USERNAME = "root"
	SSH_PASSWORD = "password"
	SSH_KEY_FILE = "/root/.ssh/id_rsa"

	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	ssh_stdin = ssh_stdout = ssh_stderr = None

	try:
	    #ssh.connect(SSH_ADDRESS, username=SSH_USERNAME, password=SSH_PASSWORD)
	    ssh.connect(hostname=ssh_hostname, port=22, username=SSH_USERNAME, key_filename=SSH_KEY_FILE)
	    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(ssh_cmd, timeout=None, bufsize=-1, get_pty=False, environment=None)
	except Exception as e:
	    sys.stderr.write("SSH connection error: {0}".format(e))

	output = ssh_stdout.read()

	return output

def getArgs(argv):
   vm_uuid = ''
   try:
      opts, args = getopt.getopt(argv,"hu:",["uuid="])
   except getopt.GetoptError:
      print sys.argv[0], '-u <vm_uuid>'
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print sys.argv[0], '-u <uuid>'
         sys.exit()
      elif opt in ("-u", "--uuid"):
         vm_uuid = arg
   return vm_uuid

#####################################################################################

if __name__ == '__main__':

	## 조사 대상 VM UUID 인자
	vm_uuid = getArgs(sys.argv[1:])

	###############################################
	### Raw 데이터 생성
	###############################################
	result = []

	## VM 인터페이스를 찾는 것이므로, Network 노드 정보는 불필요.
	hostnames = (
#		"pub-network-001",
#		"pub-network-002",
		"pub-compute-001",
		"pub-compute-002",
		"pub-compute-003",
		"pub-compute-004",
	)

	for hostname in hostnames:
		output_interface = exec_ssh(hostname, "ovs-vsctl -f json list interface")
	
		json_data_interface = json.loads(output_interface)
	
		for item_interface in json_data_interface['data']:
	
			if_hostname = hostname
			if_uuid = item_interface[0][1]
			if_admin_state = item_interface[1]
			if_name = item_interface[26]
			if_type = item_interface[33]
			if_external_ids = item_interface[13][1]
			if_link_state = item_interface[20]
			if type(item_interface[24]) is list:
				if_mtu = None
			else:
				if_mtu = item_interface[24]
			if_ofport = item_interface[27]
			if_options = item_interface[29][1]
			if_other_config = item_interface[30][1]
			if_statistics = item_interface[31][1]
			if_status = item_interface[32][1]
	
			## OpenStack 메타 정보 검색
			if_external_ids_attached_mac = if_external_ids_iface_id = if_external_ids_iface_status = if_external_ids_vm_uuid = None
			if len(if_external_ids) > 0:
				if_external_ids_attached_mac = if_external_ids[0][1]
				if_external_ids_iface_id = if_external_ids[1][1]
				if_external_ids_iface_status = if_external_ids[2][1]
				if len(if_external_ids) > 3:
					if_external_ids_vm_uuid = if_external_ids[3][1]

			## Options 속성 검색
			if_options_patch_peer = if_options_vxlan_df_default = if_options_vxlan_in_key = if_options_vxlan_local_ip = if_options_vxlan_out_key = if_options_vxlan_remote_ip = None
			if if_type == "patch":
				if_options_patch_peer = if_options[0][1]
			elif if_type == "vxlan":
				if_options_vxlan_df_default = if_options[0][1]
				if_options_vxlan_in_key = if_options[1][1]
				if_options_vxlan_local_ip = if_options[2][1]
				if_options_vxlan_out_key = if_options[3][1]
				if_options_vxlan_remote_ip = if_options[4][1]
	
			result.append({
				"if_hostname": if_hostname,
				"if_uuid": if_uuid,
				"if_name": if_name,
				"if_admin_state": if_admin_state,
				"if_name": if_name,
				"if_type": if_type,
				"if_external_ids_attached_mac": if_external_ids_attached_mac,
				"if_external_ids_iface_id": if_external_ids_iface_id,
				"if_external_ids_iface_status": if_external_ids_iface_status,
				"if_external_ids_vm_uuid": if_external_ids_vm_uuid,
				"if_link_state": if_link_state,
				"if_mtu": if_mtu,
				"if_ofport": if_ofport,
				"if_options_patch_peer": if_options_patch_peer,
				"if_options_vxlan_df_default": if_options_vxlan_df_default,
				"if_options_vxlan_in_key": if_options_vxlan_in_key,
				"if_options_vxlan_local_ip": if_options_vxlan_local_ip,
				"if_options_vxlan_out_key": if_options_vxlan_out_key,
				"if_options_vxlan_remote_ip": if_options_vxlan_remote_ip,
				"if_other_config": if_other_config,
				"if_statistics": if_statistics,
				"if_status": if_status
			})
	
	for interface in result:
		if_external_ids_vm_uuid = interface['if_external_ids_vm_uuid']
		if if_external_ids_vm_uuid == vm_uuid:
			for k, v in interface.iteritems():
				print "%s ---> %s" % (k, v)
			sys.exit(2)

	## 검색 결과 없을 시, 입력된 uuid에 해당되는 instance가 없음을 노티
	print "%s is not instance." % vm_uuid

