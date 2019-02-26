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
		"pub-network-001",
#		"pub-network-002",
		"pub-compute-001",
		"pub-compute-002",
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
			#if_name = "I:" + item_interface[26] + "(" + if_hostname + ")"
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

		## VxLAN 터널 연결 구성
		#if if_type == "if_type" and not isStrBlank(data['if_type']):
		if if_type == "vxlan":
			vxlan_local_ip = interface['if_options_vxlan_local_ip']
			vxlan_remote_ip = interface['if_options_vxlan_remote_ip']
			vxlan_local_hostname = interface['if_options_vxlan_local_ip']
			vxlan_remote_hostname = interface['if_options_vxlan_remote_ip']
			#print(vxlan_local_ip, vxlan_remote_ip)
			#G.add_edge(interface['if_name'], interface['if_port_name'])
			#print(if_name, interface['if_options'])

	#print(G.nodes.data())
	#print(G.nodes())
	#print(G.edges())

	## Node 종류(Interface/Port/Bridge)별 목록 생성
	nodes_interface = [node for node in G.nodes() if node.startswith("I:")]
	nodes_port = [node for node in G.nodes() if node.startswith("P:")]
	nodes_bridge = [node for node in G.nodes() if node.startswith("B:")]

	## VxLAN 터널 링크 정보 Dictionay 생성
	vxlan_link_dict = {}
	for node_data in G.nodes(data=True):
		if_name = node_data[0]
		data_dict = node_data[1]
		if len(data_dict) > 0:
			if_type = data_dict['if_type']
			if if_type == "vxlan":
				vxlan_local_ip = data_dict['if_options_vxlan_local_ip']
				vxlan_local_hostname = socket.gethostbyaddr(vxlan_local_ip)[0]
				vxlan_remote_ip = data_dict['if_options_vxlan_remote_ip']
				vxlan_remote_hostname = socket.gethostbyaddr(vxlan_remote_ip)[0]
				vxlan_link_dict[vxlan_local_hostname + "---" + vxlan_remote_hostname] = if_name
	#print(vxlan_link_dict)

	## if_type 속성에 따른 Node 및 Edge 목록 생성
	## if_link_state 값이 Down인 Interface 노드 목록 생성
	nodes_if_type_patch = []
	nodes_if_type_vxlan = []
	nodes_if_type_internal = []
	nodes_if_type_normal = []
	edge_if_type_patch = []
	edge_if_type_vxlan = []
	nodes_if_link_state_down = []
	for node_data in G.nodes(data=True):
		if_name = node_data[0]
		data_dict = node_data[1]
		if len(data_dict) > 0:
			if_type = data_dict['if_type']
			if_link_state = data_dict['if_link_state']
			if if_type == "patch":
				nodes_if_type_patch.append(if_name)
				peer_if_hostname = data_dict['if_hostname']
				peer_if_name = "I:" + data_dict['if_options_patch_peer'] + "(" + peer_if_hostname + ")"
				edge_if_type_patch.append((if_name, peer_if_name))
				
			elif if_type == "vxlan":
				nodes_if_type_vxlan.append(if_name)
				vxlan_local_ip = data_dict['if_options_vxlan_local_ip']
				vxlan_local_hostname = socket.gethostbyaddr(vxlan_local_ip)[0]
				vxlan_remote_ip = data_dict['if_options_vxlan_remote_ip']
				vxlan_remote_hostname = socket.gethostbyaddr(vxlan_remote_ip)[0]
				if vxlan_remote_hostname in hostnames:
					find_key = vxlan_remote_hostname + "---" + vxlan_local_hostname
					remote_if_name = vxlan_link_dict[find_key]
					edge_if_type_vxlan.append((if_name, remote_if_name))
			elif if_type == "internal":
				nodes_if_type_internal.append(if_name)
			else:
				nodes_if_type_normal.append(if_name)
			if if_link_state == "down":
				nodes_if_link_state_down.append(if_name)

	## Patch Edge 목록을 G 객체에 통합
	G.add_edges_from(removeDup(edge_if_type_patch))

	## 레이아웃 정의
	##pos = nx.shell_layout(G)  # positions for all nodes
	pos = nx.spring_layout(G, k=0.05, iterations=40)  # positions for all nodes
	##pos = nx.spring_layout(G, iterations=50)
	##pos = nx.spectral_layout(G, scale=2)  # positions for all nodes
	##pos = nx.circular_layout(G)  # positions for all nodes
	##pos = nx.random_layout(G)  # positions for all nodes
	##pos = hierarchy_pos(G, "b:br-ex(pub-compute-001)")

	## 노드 겹침 회희 레이아웃::kamada kawai (주의: 노드가 많을 경우, 시간이 오래 걸림)
	#df = pd.dataframe(index=G.nodes(), columns=G.nodes())
	#for row, data in nx.shortest_path_length(G):
	#    for col, dist in data.items():
	#        df.loc[row,col] = dist
	#df = df.fillna(df.max().max())
	#pos = nx.kamada_kawai_layout(G, dist=df.to_dict())

	## Interface Node 그리기
	nx.draw_networkx_nodes(G, pos, nodelist=nodes_interface, with_labels=True, node_size=node_szie, node_shape='o', node_color='#F972FF', alpha=0.5, linewidths=1)

	## Port Node 그리기
	nx.draw_networkx_nodes(G, pos, nodelist=nodes_port, with_labels=True, node_size=node_szie, node_shape='o', node_color='#72B2FF', alpha=0.5, linewidths=1)

	## Bridge Node 그리기
	nx.draw_networkx_nodes(G, pos, nodelist=nodes_bridge, with_labels=True, node_size=node_szie, node_shape='o', node_color='#FF5634', alpha=0.5, linewidths=1)

	## Patch 타입 노드 업데이트 (색상 변경)
	nx.draw_networkx_nodes(G, pos, nodelist=nodes_if_type_patch, with_labels=True, node_size=node_szie, node_shape='o', node_color='#279700', alpha=0.5, linewidths=1)

	## VxLAN 타입 노드 업데이트 (색상 변경)
	nx.draw_networkx_nodes(G, pos, nodelist=nodes_if_type_vxlan, with_labels=True, node_size=node_szie, node_shape='o', node_color='#E9D000', alpha=0.5, linewidths=1)

	## Internal 타입 노드 업데이트 (색상 변경)
	nx.draw_networkx_nodes(G, pos, nodelist=nodes_if_type_internal, with_labels=True, node_size=node_szie, node_shape='o', node_color='#382000', alpha=0.5, linewidths=1)

	## Down 상태 노드 업데이트 (색상 변경)
	## 미사용 (OVS의 link_state값이 정확하지 않음. namespace에 속한 Interface의 상태 체크 못하는 것으로 추정)
	#nx.draw_networkx_nodes(G, pos, nodelist=nodes_if_link_state_down, with_labels=True, node_size=node_szie, node_shape='o', node_color='#FF0000', alpha=0.5, linewidths=1)

	## Interface/Port/Bridge Node Label 그리기
	nx.draw_networkx_labels(G, pos, font_size=1, font_family='sans-serif')

	## Interface/Port/Bridge Edge 목록 생성 (중복 존재 가능)
	edge_I2P = [(u, v) for (u, v) in G.edges() if (u.startswith("I:") and v.startswith("P:")) or (u.startswith("P:") and v.startswith("I:"))]
	edge_P2B = [(u, v) for (u, v) in G.edges() if (u.startswith("P:") and v.startswith("B:")) or (u.startswith("B:") and v.startswith("P:"))]

	## Edge 그리기
	nx.draw_networkx_edges(G, pos, edgelist=removeDup(edge_I2P), width=0.1, alpha=0.5, edge_color='#E67E22')
	nx.draw_networkx_edges(G, pos, edgelist=removeDup(edge_P2B), width=0.3, alpha=0.5, edge_color='#2ECC71')
	nx.draw_networkx_edges(G, pos, edgelist=removeDup(edge_if_type_patch), width=1, alpha=0.5, edge_color='#00FFE8')
	nx.draw_networkx_edges(G, pos, edgelist=removeDup(edge_if_type_vxlan), width=2, alpha=0.5, edge_color='#FFF818')

	plt.axis('off')

	#plt.figure(figsize = (10,9))

	plt.title("OpenStack Network Connectivity")

	print("Creating GEXF.........")
	nx.write_gexf(G, "/var/www/html/OpenStack-Network-Connectivity.gexf")
	#nx.write_gexf(G, "/var/www/html/OpenStack-Network-Connectivity.gexf", version="1.2draft")

	print("Creating Image........")
	plt.savefig("/var/www/html/OpenStack-Network-Connectivity.png", format = "png", dpi = 1200)
