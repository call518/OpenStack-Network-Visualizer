#!/usr/bin/env python
# -*- mode:python; coding:utf-8 -*-

import paramiko
import time
import sys
import json
import socket
import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import random

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

def isStrBlank(myString):
    return not (myString and myString.strip())

def removeDup(src_list):
	return set([tuple(sorted(item)) for item in src_list])

def xstr(value):
    if value is None:
        return 'NONE'
    else:
        return str(value)

#####################################################################################

if __name__ == '__main__':

	node_szie = 10

	###############################################
	### Raw 데이터 생성
	###############################################
	result = []

	hostnames = (
#		"pub-network-001",
#		"pub-network-002",
		"pub-compute-001",
#		"pub-compute-002",
#		"pub-compute-003",
#		"pub-compute-004",
	)

	for hostname in hostnames:

		output_bridge = exec_ssh(hostname, "ovs-vsctl -f json list br")
		output_port = exec_ssh(hostname, "ovs-vsctl -f json list port")
		output_interface = exec_ssh(hostname, "ovs-vsctl -f json list interface")
	
		json_data_bridge = json.loads(output_bridge)
		json_data_interface = json.loads(output_interface)
		json_data_port = json.loads(output_port)
	
		for item_interface in json_data_interface['data']:
	
			if_hostname = hostname
			if_uuid = item_interface[0][1]
			if_admin_state = item_interface[1]
			if_name = "I:" + item_interface[26]
			if if_name.startswith("I:eth"):
				if_name = if_name + "(" + hostname + ")"
			if_type = item_interface[33]
			if if_type in ["vxlan", "patch", "internal"]:
				if_name = if_name + "(" + hostname + ")"
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
	
			## Interface가 속해 있는 Port 검색
			if_port_uuid = if_port_name = None
			for item_port in json_data_port['data']:
				if if_uuid == item_port[8][1]:
					if_port_uuid = item_port[0][1]
					if_port_name = "P:" + item_port[11] + "(" + hostname + ")"
					break
	
			## Port가 속해 있는 Bridge 검색
			if_br_uuid = if_br_name = None
			if if_port_uuid:
				for item_bridge in json_data_bridge['data']:
					tmp_br_uuid = item_bridge[0][1]
					tmp_br_name = item_bridge[13]
					for port in item_bridge[16][1]:
						if if_port_uuid == port[1]:
							if_br_uuid = tmp_br_uuid
							if_br_name = "B:" + tmp_br_name + "(" + hostname + ")"
							break
	
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
				"if_status": if_status,
				"if_port_uuid": if_port_uuid,
				"if_port_name": if_port_name,
				"if_br_uuid": if_br_uuid,
				"if_br_name": if_br_name
			})
	
		#print(result)


	###############################################
	### 이미지 생성 작업 시작
	###############################################
	G = nx.Graph() 

	for interface in result:
		#print("if_name: %s (%s)" % (interface['if_name'], interface['if_uuid']))
		#print("  if_port_name: %s (%s)" % (interface['if_port_name'], interface['if_port_uuid']))
		#print("  if_br_name: %s (%s)" % (interface['if_br_name'], interface['if_br_uuid']))

		if_name = interface['if_name']
		if_type = interface['if_type']

		G.add_node(if_name,
			if_hostname = xstr(interface['if_hostname']),
			if_uuid = xstr(interface['if_uuid']),
			if_admin_state = xstr(interface['if_admin_state']),
			if_type = xstr(if_type),
			if_external_ids_attached_mac = xstr(interface['if_external_ids_attached_mac']),
			if_external_ids_iface_id = xstr(interface['if_external_ids_iface_id']),
			if_external_ids_iface_status = xstr(interface['if_external_ids_iface_status']),
			if_external_ids_vm_uuid = xstr(interface['if_external_ids_vm_uuid']),
			if_link_state = xstr(interface['if_link_state']),
			if_mtu = xstr(interface['if_mtu']),
			if_ofport = xstr(interface['if_ofport']),
			if_options_patch_peer = xstr(interface['if_options_patch_peer']),
			if_options_vxlan_df_default = xstr(interface['if_options_vxlan_df_default']),
			if_options_vxlan_in_key = xstr(interface['if_options_vxlan_in_key']),
			if_options_vxlan_local_ip = xstr(interface['if_options_vxlan_local_ip']),
			if_options_vxlan_out_key = xstr(interface['if_options_vxlan_out_key']),
			if_options_vxlan_remote_ip = xstr(interface['if_options_vxlan_remote_ip']),
			if_other_config = xstr(interface['if_other_config']),
			if_statistics = xstr(interface['if_statistics']),
			if_status = xstr(interface['if_status']),
			if_port_uuid = xstr(interface['if_port_uuid']),
			if_port_name = xstr(interface['if_port_name']),
			if_br_uuid = xstr(interface['if_br_uuid']),
			if_br_name = xstr(interface['if_br_name'])
		)

		G.add_edge(interface['if_name'], interface['if_port_name'])
		G.add_edge(interface['if_port_name'], interface['if_br_name'])

	#nx.write_gexf(G, "test.gexf")
	nx.write_gexf(G, "file.gexf", version="1.2draft")
