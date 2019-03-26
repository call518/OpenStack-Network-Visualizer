#!/usr/bin/env python
# -*- mode:python; coding:utf-8 -*-

### Whole Topology
## ex) python visualizer.py

### Local-VM to Local-VM
## ex) python visualizer.py --src "T:tap94d54818-a5" --dst "T:tapeee4966d-68" [--onlypath]

### Local-VM to Remote-VM
## ex) python visualizer.py --src "T:tap94d54818-a5" --dst "T:tap708a8386-2f" [--onlypath]

### Local-VM to External
## ex) python visualizer.py --src "T:tap94d54818-a5" --dst "I:eth1(pub-compute-001)" [--onlypath]

import warnings
warnings.filterwarnings("ignore")
import paramiko
import time
import sys, getopt
import json
#import socket
import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import random
import operator
import re
import time

import plotly
#plotly.tools.set_credentials_file(username='your-account', api_key='your-api-key')
import plotly.plotly as py
import plotly.graph_objs as go

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


def removeDup(src_list):
	return set([tuple(sorted(item)) for item in src_list])

def xstr(value):
    if value is None:
        return 'NONE'
    else:
        return str(value)

def findDictValue(xstr, xdict):
    if xstr in xdict:
        return xdict[xstr]
    else:
        return "NONE"

def getArgs(argv):
	src_node = None
	dst_node = None
	only_path = False
	enable_fip = False
	enable_plotly = False
	usage_str = " [{-s|--src} <src node> {-d|--dst} <dst node> [-o|--onlypath] [-f|--fip] [-p|--plotly]"
	try:
		opts, args = getopt.getopt(argv, "hsdofp", ["help", "src=", "dst=", "onlypath", "fip", "plotly"])
	except getopt.GetoptError:
		print("# python " + sys.argv[0] + usage_str)
		sys.exit(2)
	for opt, arg in opts:
		if opt in ('-h', '--help'):
			print("# python " + sys.argv[0] + usage_str)
			sys.exit()
		elif opt in ("-s", "--src"):
			src_node = arg
		elif opt in ("-d", "--dst"):
			dst_node = arg
		elif opt in ("-o", "--onlypath"):
			only_path = True
		elif opt in ("-f", "--fip"):
			enable_fip = True
		elif opt in ("-p", "--plotly"):
			enable_plotly = True
	if (src_node == None and dst_node != None) or (src_node != None and dst_node == None):
		print("# python " + sys.argv[0] + usage_str)
		sys.exit(2)
	elif (src_node == None and dst_node == None) and only_path:
		print("# python " + sys.argv[0] + usage_str)
		sys.exit(2)
	return src_node, dst_node, only_path, enable_fip, enable_plotly

def getHostnameByOvsLocalIp(ip):
	for hostname, ovs_local_ip in hostnames.items():
		if ip == ovs_local_ip:
			return hostname
	return None

#####################################################################################

if __name__ == '__main__':

	## 최단 경로 조사 대상 인자
	src_node, dst_node, only_path, enable_fip, enable_plotly = getArgs(sys.argv[1:])

	print("\nProcessing.............")
	start_time = time.time()

	## 인자 체크.
	isSP = False
	if src_node != None and dst_node != None:
		isSP = True

	if isSP == False:
		only_path = False

	###############################################
	### Raw 데이터 생성
	###############################################

	result = []
	result_linux_bridge = []
	result_dvr_fip = []

	#hostnames = (
	#	#"dev-r2network-001",
	#	"dev-r2compute-001",
	#	#"dev-r2compute-002",
	#)

	## pair of hostanem and ovs-local-ip.
	#ovs_local_ip_by_hostname = {
	hostnames = {
		"dev-r2network-001": "10.0.42.18",
		"dev-r2compute-001": "10.0.42.36",
		"dev-r2compute-002": "10.0.42.37",
	}

	for hostname in hostnames:
		## Network 호스트인지 체크
		# snat-xxx 네임스페이스 존재 유무로 판단
		# 있으면, Network호스트, 없으면 Compute 호스트로 본다.
		isNetworkHost = False
		return_chk_network_node = exec_ssh(hostname, "if `ip netns | grep -q snat`; then echo network-node; fi")
		if return_chk_network_node.strip() == "network-node":
			isNetworkHost = True

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
	
			## Statistics 속성 검색
			if_statistics_collisions = if_statistics_rx_bytes = if_statistics_rx_crc_err = if_statistics_rx_dropped = if_statistics_rx_errors = if_statistics_rx_frame_err = if_statistics_rx_over_err = if_statistics_rx_packets = if_statistics_tx_bytes = if_statistics_tx_dropped = if_statistics_tx_errors = if_statistics_tx_packets = None
			statistics_dict = {}
			for k, v in if_statistics:
				statistics_dict[k] = v
			if_statistics_collisions = findDictValue("collisions", statistics_dict)
			if_statistics_rx_bytes = findDictValue("rx_bytes", statistics_dict)
			if_statistics_rx_crc_err = findDictValue("rx_crc_err", statistics_dict)
			if_statistics_rx_dropped = findDictValue("rx_dropped", statistics_dict)
			if_statistics_rx_errors = findDictValue("rx_dropped", statistics_dict)
			if_statistics_rx_frame_err = findDictValue("rx_frame_err", statistics_dict)
			if_statistics_rx_over_err = findDictValue("rx_over_err", statistics_dict)
			if_statistics_rx_packets = findDictValue("rx_packets", statistics_dict)
			if_statistics_tx_bytes = findDictValue("tx_bytes", statistics_dict)
			if_statistics_tx_dropped = findDictValue("tx_dropped", statistics_dict)
			if_statistics_tx_errors = findDictValue("tx_errors", statistics_dict)
			if_statistics_tx_packets = findDictValue("tx_packets", statistics_dict)
	
			## Interface가 속해 있는 Port 검색
			if_port_uuid = if_port_name = tmp_port_interface_uuid = tmp_port_name = None
			for item_port in json_data_port['data']:
				## OVS 버전에 따른 속성 순서 차이로 인해 구별함 (임시)
				try:
					tmp_port_interface_uuid = item_port[8][1]
				except TypeError:
					tmp_port_interface_uuid = item_port[9][1]
				if if_uuid == tmp_port_interface_uuid:
					if_port_uuid = item_port[0][1]
					try:
						if_port_name = "P:" + item_port[11] + "(" + hostname + ")"
					except TypeError:
						if_port_name = "P:" + item_port[12] + "(" + hostname + ")"
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
				"isNetworkHost": isNetworkHost,
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
				"if_statistics_collisions": if_statistics_collisions,
				"if_statistics_rx_bytes": if_statistics_rx_bytes,
				"if_statistics_rx_crc_err": if_statistics_rx_crc_err,
				"if_statistics_rx_dropped": if_statistics_rx_dropped,
				"if_statistics_rx_errors": if_statistics_rx_errors,
				"if_statistics_rx_frame_err": if_statistics_rx_frame_err,
				"if_statistics_rx_over_err": if_statistics_rx_over_err,
				"if_statistics_rx_packets": if_statistics_rx_packets,
				"if_statistics_tx_bytes": if_statistics_tx_bytes,
				"if_statistics_tx_dropped": if_statistics_tx_dropped,
				"if_statistics_tx_errors": if_statistics_tx_errors,
				"if_statistics_tx_packets": if_statistics_tx_packets,
				"if_status": if_status,
				"if_port_uuid": if_port_uuid,
				"if_port_name": if_port_name,
				"if_br_uuid": if_br_uuid,
				"if_br_name": if_br_name
			})

		## Linux Bridge 정보 수집
		cmd = "BR_ARRAY=(`ip link list type bridge | awk '/^[0-9]/ {print $2}' | sed -e 's/:$//g'`); num_br=1; for br in ${BR_ARRAY[@]}; do if [ $num_br -eq 1 ]; then echo '['; fi; echo '{\"'$br'\": ['; IF_ARRAY=(`ls -1 /sys/devices/virtual/net/$br/brif/`); num=1; for if in ${IF_ARRAY[@]}; do echo '\"'$if'\"'; if [ $num -lt ${#IF_ARRAY[@]} ]; then echo ','; fi; ((num++)); done; echo ']}'; if [ $num_br -lt ${#BR_ARRAY[@]} ]; then echo ','; else echo ']'; fi; ((num_br++)); done | tr '\n' ' '"
		output_linux_bridge = exec_ssh(hostname, cmd)
		if len(output_linux_bridge) > 0:
			output_linux_bridge = "{ \"hostname\": \"" + hostname + "\", \"data\": " + output_linux_bridge + "}"
			json_data_linux_bridge = json.loads(output_linux_bridge)
		else:
			json_data_linux_bridge = json.loads('{ "hostname": "%s", "data": [] }' % hostname)

		## Linux Bridge 목록 생성
		for data in json_data_linux_bridge['data']:
			for bridge, interfaces in data.items():
				#print(bridge, interfaces)
				result_linux_bridge.append({
					"isNetworkHost": isNetworkHost,
					"hostname": hostname,
					"bridge_name": bridge, 
					"interfaces": interfaces, 
				})

		## FIP활성화 및 Compute 호스트일 경우만(snat-xxx 네임스페이스 존재 유무로 판단),  FIP연결성 메타 정보 수집
		if enable_fip and not isNetworkHost:
			output_dvr_fip = exec_ssh(hostname, "(echo \"[\"; for NS in `ip netns | awk '{print $1}' | egrep \"qrouter|fip\"`; do IFs=`ip netns exec $NS ip -o link show | awk '{print $2\",\"$5\",\"$17 | \"sed -e 's/:,/,/g'\"}' | egrep \"^rfp|^fpr|^fg|^qr\"`; for IF in $IFs; do IF_ARRAY=(`echo $IF | awk -F',' '{print $1,$2,$3}'`); IF_NAME_ARRAY=(`echo ${IF_ARRAY[0]} | awk -F'@' '{print $1, $2}'`); IF_NAME=${IF_NAME_ARRAY[0]}; IF_ID=`ip netns exec $NS ip -o link show $IF_NAME | awk '{print $1 | \"sed -e 's/://g'\"}'`; IF_MTU=${IF_ARRAY[1]}; IF_MAC=${IF_ARRAY[2]}; IF_PAIR_ID=`echo ${IF_NAME_ARRAY[1]} | sed -e 's/^if//g'`; echo \"{\"; echo \"\\\"if_name\\\": \\\"$IF_NAME\\\",\"; echo \"\\\"if_namespace\\\": \\\"$NS\\\",\"; echo \"\\\"if_id\\\": \\\"$IF_ID\\\",\"; echo \"\\\"if_mtu\\\": \\\"$IF_MTU\\\",\"; echo \"\\\"if_mac\\\": \\\"$IF_MAC\\\",\"; echo \"\\\"if_pair_id\\\": \\\"$IF_PAIR_ID\\\"\"; echo \"},\"; done ;done | sed -e '$s/,//'; echo \"]\")")
			for item in json.loads(output_dvr_fip):
				item['if_hostname'] = hostname
				if_name = item['if_name']
				if if_name.startswith(("qr-","fg-")):
					item['if_name'] = "I:" + if_name + "(" + hostname + ")"
				else:
					item['if_name'] = "VP:" + if_name + "(" + hostname + ")"
				result_dvr_fip.append(item)

	###############################################
	### 이미지 생성 작업 시작
	###############################################
	plt.figure(figsize=(10,10)) ## 캔버스 크기 증가
	G = nx.Graph() 

	for interface in result:
		#print("if_name: %s (%s)" % (interface['if_name'], interface['if_uuid']))
		#print("  if_port_name: %s (%s)" % (interface['if_port_name'], interface['if_port_uuid']))
		#print("  if_br_name: %s (%s)" % (interface['if_br_name'], interface['if_br_uuid']))

		if_name = interface['if_name']
		if_type = interface['if_type']

		## 모든 Interface 타입 -> Node로 등록
		G.add_node(if_name,
			isNetworkHost = xstr(interface['isNetworkHost']),
			if_name = xstr(interface['if_name']),
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
			if_statistics_collisions = xstr(interface['if_statistics_collisions']),
			if_statistics_rx_bytes = xstr(interface['if_statistics_rx_bytes']),
			if_statistics_rx_crc_err = xstr(interface['if_statistics_rx_crc_err']),
			if_statistics_rx_dropped = xstr(interface['if_statistics_rx_dropped']),
			if_statistics_rx_errors = xstr(interface['if_statistics_rx_errors']),
			if_statistics_rx_frame_err = xstr(interface['if_statistics_rx_frame_err']),
			if_statistics_rx_over_err = xstr(interface['if_statistics_rx_over_err']),
			if_statistics_rx_packets = xstr(interface['if_statistics_rx_packets']),
			if_statistics_tx_bytes = xstr(interface['if_statistics_tx_bytes']),
			if_statistics_tx_dropped = xstr(interface['if_statistics_tx_dropped']),
			if_statistics_tx_errors = xstr(interface['if_statistics_tx_errors']),
			if_statistics_tx_packets = xstr(interface['if_statistics_tx_packets']),
			if_status = xstr(interface['if_status']),
			if_port_uuid = xstr(interface['if_port_uuid']),
			if_port_name = xstr(interface['if_port_name']),
			if_br_uuid = xstr(interface['if_br_uuid']),
			if_br_name = xstr(interface['if_br_name'])
		)

		## 인터페이스 <-> Bridge <-> Port 간 Edge 정보 추가
		# Edge등록을 통해, 없는 Port/Bridge 노드 자동 추가됨.
		G.add_edge(interface['if_name'], interface['if_port_name'])
		G.add_edge(interface['if_port_name'], interface['if_br_name'])
		#print G.nodes(data=True)
		#sys.exit(1)
		# 자동 추가된 Port/Bridge에 isNetworkHost 및 if_type 속성 추가
		G.node[interface['if_port_name']]['isNetworkHost'] = interface['isNetworkHost']
		G.node[interface['if_port_name']]['if_type'] = ''
		G.node[interface['if_port_name']]['if_hostname'] = interface['if_hostname']
		G.node[interface['if_br_name']]['isNetworkHost'] = interface['isNetworkHost']
		G.node[interface['if_br_name']]['if_type'] = ''
		G.node[interface['if_br_name']]['if_hostname'] = interface['if_hostname']
		#print G.node['P:qr-47ac2c1a-b0(pub-compute-001)']['isNetworkHost']
		#print G.nodes(data=True)
		#sys.exit(1)

		## VxLAN 터널 연결 구성
		if if_type == "vxlan":
			vxlan_local_ip = interface['if_options_vxlan_local_ip']
			vxlan_remote_ip = interface['if_options_vxlan_remote_ip']
			vxlan_local_hostname = interface['if_options_vxlan_local_ip']
			vxlan_remote_hostname = interface['if_options_vxlan_remote_ip']
			#print(vxlan_local_ip, vxlan_remote_ip)
			#G.add_edge(interface['if_name'], interface['if_port_name'])
			#print(if_name, interface['if_options'])

	## Linux Bridge 정보 'G'에 추가 (노드/엣지)
	edge_VP2LB = []
	edge_I2VP = []
	edge_T2LB = []
	for item in result_linux_bridge:
		isNetworkHost = item['isNetworkHost']
		hostname = item['hostname']
		br_name = "LB:" + item['bridge_name']
		interfaces = item['interfaces']
		G.add_node(br_name)
		G.node[br_name]['isNetworkHost'] = isNetworkHost
		G.node[br_name]['if_type'] = ''
		for interface in interfaces:
			if interface.startswith("qvb"):
				if_name = "VP:" + interface
				if_name_ovs_pair = re.sub(r'^VP:qvb', 'I:qvo', if_name)
				G.add_node(if_name)
				G.node[if_name]['isNetworkHost'] = isNetworkHost
				G.node[if_name]['if_type'] = ''
				G.node[if_name]['if_hostname'] = hostname
				G.add_edge(if_name_ovs_pair, if_name)
				G.add_edge(if_name, br_name)
				edge_VP2LB.append((if_name, br_name))
				edge_I2VP.append((if_name_ovs_pair, if_name))
			elif interface.startswith("tap"):
				if_name = "T:" + interface
				G.add_node(if_name)
				G.node[if_name]['isNetworkHost'] = isNetworkHost
				G.node[if_name]['if_type'] = ''
				G.node[if_name]['if_hostname'] = hostname
				G.add_edge(if_name, br_name)
				edge_T2LB.append((if_name, br_name))

	## VxLAN 터널 링크 정보 Dictionay 생성
	vxlan_link_dict = {}
	for node_data in G.nodes(data=True):
		if_name = node_data[0]
		data_dict = node_data[1]
		#print if_name, data_dict
		#sys.exit(1)
		if len(data_dict) > 0:
			if_type = data_dict['if_type']
			if if_type == "vxlan":
				vxlan_local_ip = data_dict['if_options_vxlan_local_ip']
				vxlan_remote_ip = data_dict['if_options_vxlan_remote_ip']
				#vxlan_local_hostname = socket.gethostbyaddr(vxlan_local_ip)[0]
				vxlan_local_hostname = getHostnameByOvsLocalIp(vxlan_local_ip)
				#vxlan_remote_hostname = socket.gethostbyaddr(vxlan_remote_ip)[0]
				vxlan_remote_hostname = getHostnameByOvsLocalIp(vxlan_remote_ip)
				vxlan_link_dict[vxlan_local_hostname + "---" + vxlan_remote_hostname] = if_name

	## if_type 속성에 따른 Node 및 Edge 목록 생성
	## if_link_state 값이 Down인 Interface 노드 목록 생성
	nodes_if_type_patch = []
	nodes_if_type_vxlan = []
	nodes_if_type_internal = []
	nodes_if_type_internal_fg = []
	nodes_if_type_normal = []
	edge_if_type_patch = []
	edge_if_type_vxlan = []
	#nodes_if_link_state_down = []
	for node_data in G.nodes(data=True):
		if_name = node_data[0]
		data_dict = node_data[1]
		if len(data_dict) > 0:
			if_type = data_dict['if_type']
			#if_link_state = data_dict['if_link_state']
			if if_type == "patch":
				nodes_if_type_patch.append(if_name)
				peer_if_hostname = data_dict['if_hostname']
				peer_if_name = "I:" + data_dict['if_options_patch_peer'] + "(" + peer_if_hostname + ")"
				edge_if_type_patch.append((if_name, peer_if_name))
				
			elif if_type == "vxlan":
				nodes_if_type_vxlan.append(if_name)
				vxlan_local_ip = data_dict['if_options_vxlan_local_ip']
				#vxlan_local_hostname = socket.gethostbyaddr(vxlan_local_ip)[0]
				vxlan_local_hostname = getHostnameByOvsLocalIp(vxlan_local_ip)
				vxlan_remote_ip = data_dict['if_options_vxlan_remote_ip']
				#vxlan_remote_hostname = socket.gethostbyaddr(vxlan_remote_ip)[0]
				vxlan_remote_hostname = getHostnameByOvsLocalIp(vxlan_remote_ip)
				if vxlan_remote_hostname in hostnames:
					find_key = vxlan_remote_hostname + "---" + vxlan_local_hostname
					remote_if_name = vxlan_link_dict[find_key]
					edge_if_type_vxlan.append((if_name, remote_if_name))
			elif if_type == "internal":
				if if_name.startswith("I:fg-"):
					nodes_if_type_internal_fg.append(if_name)
				else:
					nodes_if_type_internal.append(if_name)
			else:
				nodes_if_type_normal.append(if_name)
			#if if_link_state == "down":
			#	nodes_if_link_state_down.append(if_name)

	## Interface/Port/Bridge Edge 목록 생성 (중복 존재 가능)
	edge_I2P = [(u, v) for (u, v) in G.edges() if (u.startswith("I:") and v.startswith("P:")) or (u.startswith("P:") and v.startswith("I:"))]
	edge_P2B = [(u, v) for (u, v) in G.edges() if (u.startswith("P:") and v.startswith("B:")) or (u.startswith("B:") and v.startswith("P:"))]

	if enable_fip:
		## FIP 정보 추가를 위해, (B:br-int, P:int-br-ex) 타입의 Edge 제거
		list_isNetworkHost = G.nodes(data='isNetworkHost')
		for (u, v) in edge_P2B:
			#print u
			#sys.exit(1)
			if not G.node[u]['isNetworkHost']:
				if (u.startswith("B:br-int") and v.startswith("P:int-br-ex")) or (u.startswith("P:int-br-ex") and v.startswith("B:br-int")):
					#print(u, v) 
					G.remove_edge(u, v)
	
		## "namespace + hostname"를 key로 해서, VP:rfp-* 인터페이스 이름 조회 가능한 dict 생성
		dvr_fip_ns_hostname_rfp_pair = {}
		for item in result_dvr_fip:
			if_name = item['if_name']
			if_hostname = item['if_hostname']
			if if_name.startswith("VP:rfp-"):
				if_namespace = item['if_namespace']
				key = if_namespace + "(" + if_hostname + ")"
				dvr_fip_ns_hostname_rfp_pair[key] = if_name
	
		## I:qr-* <-> VP:rfp-* 에 대한 Node/Edge 정보 생성/추가
		edge_SNAT = []
		for item in result_dvr_fip:
			if_name = item['if_name']
			if if_name.startswith("I:qr-"):
				if_namespace = item['if_namespace']
				if_hostname = item['if_hostname']
				key = item['if_namespace'] + "(" + if_hostname + ")"
				if_rfp = dvr_fip_ns_hostname_rfp_pair[key]
				#print if_namespace, if_name, if_rfp
				G.add_node(if_rfp)
				G.add_edge(if_name, if_rfp)
				#print if_name, if_rfp
				#edge_I2P.append((if_name, if_rfp))
				edge_SNAT.append((if_name, if_rfp))
	
		## VP:fpr-* 인터페이스의 Index-ID를 key로 해서, VP:fpr-* 이름을 조희 가능한 dict 생성
		dvr_fip_id_hostname_fpr_pair = {}
		for item in result_dvr_fip:
			if_name = item['if_name']
			if if_name.startswith("VP:fpr-"):
				if_id = item['if_id']
				if_hostname = item['if_hostname']
				key = if_id + "(" + if_hostname + ")"
				#print if_id, if_name
				dvr_fip_id_hostname_fpr_pair[key] = if_name
		## VP:rfp-* <-> VP:fpr-* 에 대한 Node/Edge 정보 생성/추가
		for item in result_dvr_fip:
			if_name = item['if_name']
			if if_name.startswith("VP:rfp-"):
				if_pair_id = item['if_pair_id']
				if_hostname = item['if_hostname']
				key = if_pair_id + "(" + if_hostname + ")"
				#print if_pair_id
				if_pair_name = dvr_fip_id_hostname_fpr_pair[key]
				#print if_name, if_pair_name
				G.add_node(if_pair_name)
				G.add_edge(if_name, if_pair_name)
				edge_I2VP.append((if_name, if_pair_name))
	
		## hostname을 key로 해서, I:fg-* 인터페이스 이름 조회 가능한 dict 생성
		dvr_fip_hostname_fg_pair = {}
		for item in result_dvr_fip:
			if_name = item['if_name']
			if_hostname = item['if_hostname']
			if if_name.startswith("I:fg-"):
				dvr_fip_hostname_fg_pair[if_hostname] = if_name
	
		## VP:fpr-* <-> I:fg-* 에 대한 Edge 정보 생성/추가
		edge_ROUTING = []
		for item in result_dvr_fip:
			if_name = item['if_name']
			if if_name.startswith("VP:fpr-"):
				if_hostname = item['if_hostname']
				if_fg_name = dvr_fip_hostname_fg_pair[if_hostname]
				#print if_name, if_hostname, if_fg_name
				G.add_edge(if_name, if_fg_name)
				edge_ROUTING.append((if_name, if_fg_name))

	## 순서와 무관하게 중복 제거 처리
	edge_I2P = removeDup(edge_I2P)
	edge_P2B = removeDup(edge_P2B)
	edge_VP2LB = removeDup(edge_VP2LB)
	edge_I2VP = removeDup(edge_I2VP)
	edge_T2LB = removeDup(edge_T2LB)
	if enable_fip:
		edge_SNAT = removeDup(edge_SNAT)
		edge_ROUTING = removeDup(edge_ROUTING)
	edge_if_type_patch = removeDup(edge_if_type_patch)
	edge_if_type_vxlan = removeDup(edge_if_type_vxlan)

	## 모든 Egde 목록을 G 객체에 통합
	G.add_edges_from(edge_I2P)
	G.add_edges_from(edge_P2B)
	G.add_edges_from(edge_VP2LB)
	G.add_edges_from(edge_I2VP)
	G.add_edges_from(edge_T2LB)
	if enable_fip:
		G.add_edges_from(edge_SNAT)
		G.add_edges_from(edge_ROUTING)
	G.add_edges_from(edge_if_type_patch)
	G.add_edges_from(edge_if_type_vxlan)

	## 요청된 시작과 끝 노드에 대한 '최단 경로' 노드 리스트 작성
	if isSP:
		shortest_path_list = nx.astar_path(G, source=src_node, target=dst_node)
		#shortest_path_list = nx.shortest_path(G, source=src_node, target=dst_node)
		#shortest_path_list = nx.all_shortest_paths(G, source=src_node, target=dst_node)
		#shortest_path_list = nx.shortest_path_length(G, source=src_node, target=dst_node)
		#shortest_path_list = nx.average_shortest_path_length(G, source=src_node, target=dst_node)
		#shortest_path_list = nx.has_path(G, source=src_node, target=dst_node)
		#for p in shortest_path_list:
		#	print(p)
		#sys.exit(1)

	## Node 종류(Interface/Port/Bridge)별 목록 생성
	nodes_interface = [node for node in G.nodes() if node.startswith("I:")]
	nodes_port = [node for node in G.nodes() if node.startswith("P:")]
	nodes_bridge = [node for node in G.nodes() if node.startswith("B:")]
	nodes_linux_bridge = [node for node in G.nodes() if node.startswith("LB:")]
	nodes_linux_interface_pair = [node for node in G.nodes() if node.startswith("VP:")]
	nodes_linux_interface_tap = [node for node in G.nodes() if node.startswith("T:")]

	if isSP:
		nodes_sp_interface = [node for node in shortest_path_list if node.startswith("I:")]
		nodes_sp_port = [node for node in shortest_path_list if node.startswith("P:")]
		nodes_sp_bridge = [node for node in shortest_path_list if node.startswith("B:")]
		nodes_sp_linux_bridge = [node for node in shortest_path_list if node.startswith("LB:")]
		nodes_sp_linux_interface_pair = [node for node in shortest_path_list if node.startswith("VP:")]
		nodes_sp_linux_interface_tap = [node for node in shortest_path_list if node.startswith("T:")]
		nodes_sp_if_type_patch = [node for node in nodes_if_type_patch if node in shortest_path_list]
		nodes_sp_if_type_vxlan = [node for node in nodes_if_type_vxlan if node in shortest_path_list]
		nodes_sp_if_type_internal = [node for node in nodes_if_type_internal if node in shortest_path_list]
		nodes_sp_if_type_internal_fg = [node for node in nodes_if_type_internal_fg if node in shortest_path_list]
		#nodes_sp_if_link_state_down = [node for node in nodes_if_link_state_down if node in shortest_path_list]

	## SP Node 종류(Interface/Port/Bridge)별 목록 생성
	if isSP:
		## SP Edge 목록 생성
		edge_I2P_sp = []
		for edge in edge_I2P:
			src = edge[0]
			dst = edge[1]
			if src in shortest_path_list and dst in shortest_path_list:
				edge_I2P_sp.append(edge)
	
		edge_P2B_sp = []
		for edge in edge_P2B:
			src = edge[0]
			dst = edge[1]
			if src in shortest_path_list and dst in shortest_path_list:
				edge_P2B_sp.append(edge)
	
		edge_VP2LB_sp = []
		for edge in edge_VP2LB:
			src = edge[0]
			dst = edge[1]
			if src in shortest_path_list and dst in shortest_path_list:
				edge_VP2LB_sp.append(edge)
	
		edge_I2VP_sp = []
		for edge in edge_I2VP:
			src = edge[0]
			dst = edge[1]
			if src in shortest_path_list and dst in shortest_path_list:
				edge_I2VP_sp.append(edge)
	
		edge_T2LB_sp = []
		for edge in edge_T2LB:
			src = edge[0]
			dst = edge[1]
			if src in shortest_path_list and dst in shortest_path_list:
				edge_T2LB_sp.append(edge)
	
		edge_if_type_patch_sp = []
		for edge in edge_if_type_patch:
			src = edge[0]
			dst = edge[1]
			if src in shortest_path_list and dst in shortest_path_list:
				edge_if_type_patch_sp.append(edge)
	
		edge_if_type_vxlan_sp = []
		for edge in edge_if_type_vxlan:
			src = edge[0]
			dst = edge[1]
			if src in shortest_path_list and dst in shortest_path_list:
				edge_if_type_vxlan_sp.append(edge)

	if only_path:
		## 필요한 Node 정보만 남기고 정리
		nodes_sp_if_type_patch_tmp = []
		for node in nodes_sp_if_type_patch:
			if node in shortest_path_list:
				nodes_sp_if_type_patch_tmp.append(node)
		nodes_sp_if_type_patch = nodes_sp_if_type_patch_tmp
	
		nodes_sp_if_type_vxlan_tmp = []
		for node in nodes_sp_if_type_vxlan:
			if node in shortest_path_list:
				nodes_sp_if_type_vxlan_tmp.append(node)
		nodes_sp_if_type_vxlan = nodes_sp_if_type_vxlan_tmp
	
		nodes_sp_if_type_internal_tmp = []
		for node in nodes_sp_if_type_internal:
			if node in shortest_path_list:
				nodes_sp_if_type_internal_tmp.append(node)
		nodes_sp_if_type_internal = nodes_sp_if_type_internal_tmp
	
		if enable_fip:
			nodes_sp_if_type_internal_fg_tmp = []
			for node in nodes_sp_if_type_internal_fg:
				if node in shortest_path_list:
					nodes_sp_if_type_internal_fg_tmp.append(node)
			nodes_sp_if_type_internal_fg = nodes_sp_if_type_internal_fg_tmp
	
		## 필요한 Edge 정보만 남기고 정리
		edge_I2P_sp_tmp = []
		for edge in edge_I2P:
			src = edge[0]
			dst = edge[1]
			if src in shortest_path_list and dst in shortest_path_list:
				edge_I2P_sp_tmp.append(edge)
		edge_I2P_sp = edge_I2P_sp_tmp
	
		edge_P2B_sp_tmp = []
		for edge in edge_P2B:
			src = edge[0]
			dst = edge[1]
			if src in shortest_path_list and dst in shortest_path_list:
				edge_P2B_sp_tmp.append(edge)
		edge_P2B_sp = edge_P2B_sp_tmp
	
		edge_VP2LB_sp_tmp = []
		for edge in edge_VP2LB:
			src = edge[0]
			dst = edge[1]
			if src in shortest_path_list and dst in shortest_path_list:
				edge_VP2LB_sp_tmp.append(edge)
		edge_VP2LB_sp = edge_VP2LB_sp_tmp
	
		edge_I2VP_sp_tmp = []
		for edge in edge_I2VP:
			src = edge[0]
			dst = edge[1]
			if src in shortest_path_list and dst in shortest_path_list:
				edge_I2VP_sp_tmp.append(edge)
		edge_I2VP_sp = edge_I2VP_sp_tmp
	
		edge_T2LB_sp_tmp = []
		for edge in edge_T2LB:
			src = edge[0]
			dst = edge[1]
			if src in shortest_path_list and dst in shortest_path_list:
				edge_T2LB_sp_tmp.append(edge)
		edge_T2LB_sp = edge_T2LB_sp_tmp
	
		edge_if_type_patch_sp_tmp = []
		for edge in edge_if_type_patch:
			src = edge[0]
			dst = edge[1]
			if src in shortest_path_list and dst in shortest_path_list:
				edge_if_type_patch_sp_tmp.append(edge)
		edge_if_type_patch_sp = edge_if_type_patch_sp_tmp
	
		edge_if_type_vxlan_sp_tmp = []
		for edge in edge_if_type_vxlan:
			src = edge[0]
			dst = edge[1]
			if src in shortest_path_list and dst in shortest_path_list:
				edge_if_type_vxlan_sp_tmp.append(edge)
		edge_if_type_vxlan_sp = edge_if_type_vxlan_sp_tmp
	
		## 'G'의 노드 목록에서 무관한 노드 제거
		for node in list(G.nodes()):
			if node not in shortest_path_list:
				G.remove_node(node)

	## 레이아웃 정의
	if only_path == True:
		pos = nx.spring_layout(G, k=0.05, iterations=70)
	else:
		pos = nx.kamada_kawai_layout(G, scale=1)

	#pos = nx.shell_layout(G)  # positions for all nodes
	#pos = nx.spring_layout(G, k=0.05, iterations=50)  # positions for all nodes
	#pos = nx.spring_layout(G, iterations=50)
	#pos = nx.spectral_layout(G, scale=2)  # positions for all nodes
	#pos = nx.circular_layout(G)  # positions for all nodes
	#pos = nx.random_layout(G)  # positions for all nodes

	## 노드 겹침 회피 레이아웃::kamada kawai (주의: 노드가 많을 경우, 시간이 오래 걸림)
	#df = pd.DataFrame(index=G.nodes(), columns=G.nodes())
	#for row, data in nx.shortest_path_length(G):
	#    for col, dist in data.items():
	#        df.loc[row,col] = dist
	#df = df.fillna(df.max().max())
	#pos = nx.kamada_kawai_layout(G, dist=df.to_dict())

	## Default Node 사이즈
	node_szie = 3

	if isSP:
		alpha_normal = 0.1
	else:
		alpha_normal = 0.5

	alpha_sp = 0.9


	### 기본 Node 스타일 정의/생성
	if not only_path:
		## Interface Node 그리기
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_interface, with_labels=True, node_size=node_szie, node_shape='o', node_color='#F972FF', alpha=alpha_normal, linewidths=1)
	
		## Port Node 그리기
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_port, with_labels=True, node_size=node_szie, node_shape='o', node_color='#72B2FF', alpha=alpha_normal, linewidths=1)
	
		## Bridge Node 그리기
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_bridge, with_labels=True, node_size=node_szie, node_shape='o', node_color='#FF5634', alpha=alpha_normal, linewidths=1)
	
		## Linux Interface Node 그리기 (veth pair)
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_linux_interface_pair, with_labels=True, node_size=node_szie, node_shape='o', node_color='#F972FF', alpha=alpha_normal, linewidths=1)
	
		## Linux Interface Node 그리기 (tap)
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_linux_interface_tap, with_labels=True, node_size=node_szie, node_shape='o', node_color='#7E7E7E', alpha=alpha_normal, linewidths=1)
	
		## Linux Bridge Node 그리기
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_linux_bridge, with_labels=True, node_size=node_szie, node_shape='o', node_color='#0C00A0', alpha=alpha_normal, linewidths=1)
	
		## Patch 타입 노드 업데이트 (색상 변경)
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_if_type_patch, with_labels=True, node_size=node_szie, node_shape='o', node_color='#279700', alpha=alpha_normal, linewidths=1)
	
		## VxLAN 타입 노드 업데이트 (색상 변경)
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_if_type_vxlan, with_labels=True, node_size=node_szie, node_shape='o', node_color='#E9D000', alpha=alpha_normal, linewidths=1)
	
		## Internal 타입 노드 업데이트 (색상 변경)
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_if_type_internal, with_labels=True, node_size=node_szie, node_shape='o', node_color='#382000', alpha=alpha_normal, linewidths=1)
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_if_type_internal_fg, with_labels=True, node_size=node_szie, node_shape='o', node_color='#FF0000', alpha=alpha_normal, linewidths=1)
	
		## Down 상태 노드 업데이트 (색상 변경)
		## 미사용 (OVS의 link_state값이 정확하지 않음. namespace에 속한 Interface의 상태 체크 못하는 것으로 추정)
		#nx.draw_networkx_nodes(G, pos, nodelist=nodes_if_link_state_down, with_labels=True, node_size=node_szie, node_shape='o', node_color='#FF0000', alpha=alpha_normal, linewidths=1)
		#nx.draw_networkx_nodes(G, pos, nodelist=nodes_sp_if_link_state_down, with_labels=True, node_size=node_szie_ap, node_shape='o', node_color='#FF0000', alpha=alpha_sp, linewidths=1)


	### SP 모드일 경우 Node 스타일 정의/덮어쓰기
	if isSP:
		if only_path:
			node_szie_sp = 300
		else:
			node_szie_sp = 20
		## Interface Node 그리기
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_sp_interface, with_labels=True, node_size=node_szie_sp, node_shape='o', node_color='#F972FF', alpha=alpha_sp, linewidths=1, label='OVS Interface')
	
		## Port Node 그리기
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_sp_port, with_labels=True, node_size=node_szie_sp, node_shape='o', node_color='#72B2FF', alpha=alpha_sp, linewidths=1, label='OVS POrt')
	
		## Bridge Node 그리기
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_sp_bridge, with_labels=True, node_size=node_szie_sp, node_shape='o', node_color='#FF5634', alpha=alpha_sp, linewidths=1, label='OVS Bridge')
	
		## Linux Interface Node 그리기 (veth pair)
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_sp_linux_interface_pair, with_labels=True, node_size=node_szie_sp, node_shape='o', node_color='#F972FF', alpha=alpha_sp, linewidths=1, label='Linux VETH-Pair')
	
		## Linux Interface Node 그리기 (tap)
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_sp_linux_interface_tap, with_labels=True, node_size=node_szie_sp, node_shape='o', node_color='#7E7E7E', alpha=alpha_sp, linewidths=1, label='Linux TAP')
	
		## Linux Bridge Node 그리기
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_sp_linux_bridge, with_labels=True, node_size=node_szie_sp, node_shape='o', node_color='#0C00A0', alpha=alpha_sp, linewidths=1, label='Linux Bridge')
	
		## Patch 타입 노드 업데이트 (색상 변경)
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_sp_if_type_patch, with_labels=True, node_size=node_szie_sp, node_shape='o', node_color='#279700', alpha=alpha_sp, linewidths=1, label='OVS Patch')
	
		## VxLAN 타입 노드 업데이트 (색상 변경)
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_sp_if_type_vxlan, with_labels=True, node_size=node_szie_sp, node_shape='o', node_color='#E9D000', alpha=alpha_sp, linewidths=1, label='OVS VxLAN')
	
		## Internal 타입 노드 업데이트 (색상 변경)
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_sp_if_type_internal, with_labels=True, node_size=node_szie_sp, node_shape='o', node_color='#382000', alpha=alpha_sp, linewidths=1, label='OVS Internal')
		nx.draw_networkx_nodes(G, pos, nodelist=nodes_sp_if_type_internal_fg, with_labels=True, node_size=node_szie_sp, node_shape='o', node_color='#FF0000', alpha=alpha_sp, linewidths=1, label='OVS Internal(fg)')
	
		## Down 상태 노드 업데이트 (색상 변경)
		## 미사용 (OVS의 link_state값이 정확하지 않음. namespace에 속한 Interface의 상태 체크 못하는 것으로 추정)
		#nx.draw_networkx_nodes(G, pos, nodelist=nodes_sp_if_link_state_down, with_labels=True, node_size=node_szie_ap, node_shape='o', node_color='#FF0000', alpha=alpha_sp, linewidths=1, label='OVS Link-Down')


	## Node Label 그리기 (Interface/Port/Bridge)
	label_font_size = 1
	label_font_size_sp = 2
	label_font_size_sp_only = 5

	labels = {}
	labels_sp = {}

	for node in G.nodes():
		if isSP:
			if node not in shortest_path_list:
				labels[node] = node
			else:
				labels_sp[node] = node
		else:
			labels[node] = node

	if not isSP:
		nx.draw_networkx_labels(G, pos, labels, font_size=label_font_size, font_family='sans-serif', alpha=alpha_normal)
	elif isSP and not only_path:
		nx.draw_networkx_labels(G, pos, labels, font_size=label_font_size, font_family='sans-serif', alpha=alpha_normal)
		nx.draw_networkx_labels(G, pos, labels_sp, font_size=label_font_size_sp, font_family='sans-serif', alpha=alpha_sp)
	else:
		nx.draw_networkx_labels(G, pos, labels_sp, font_size=label_font_size_sp_only, font_family='sans-serif', alpha=alpha_sp)

	## Edge 그리기
	# Only Path의 경우 Edge 스타일 정의/생성
	if only_path:
		nx.draw_networkx_edges(G, pos, edgelist=edge_I2P_sp, width=1, alpha=0.5, edge_color='#E67E22', label='OVS-Interface <--> OVS-Port')
		nx.draw_networkx_edges(G, pos, edgelist=edge_P2B_sp, width=2, alpha=0.5, edge_color='#2ECC71', label='OVS-Port <--> OVS-Bridge')
		nx.draw_networkx_edges(G, pos, edgelist=edge_if_type_patch_sp, width=5, alpha=0.5, edge_color='#00FFE8', label='OVS-Patch')
		nx.draw_networkx_edges(G, pos, edgelist=edge_if_type_vxlan_sp, width=5, alpha=0.5, edge_color='#FFF818', label='VxLAN Tunnel')
		nx.draw_networkx_edges(G, pos, edgelist=edge_I2VP_sp, width=0.8, alpha=0.5, edge_color='#68FF66', label='OVS-Interface <--> Linux-VETH')
		nx.draw_networkx_edges(G, pos, edgelist=edge_VP2LB_sp, width=0.2, alpha=0.5, edge_color='#E67E22', label='Linux-VETH <--> Linux-Bridge')
		nx.draw_networkx_edges(G, pos, edgelist=edge_T2LB_sp, width=0.2, alpha=0.5, edge_color='#6A6A6A', label='Linux-TAP <--> Linux-Bridge')
	# 그외, 모든 노드 정보 표시 모드에서 Edge 스타일 정의/생성
	else:
		nx.draw_networkx_edges(G, pos, edgelist=edge_I2P, width=0.1, alpha=alpha_normal, edge_color='#E67E22', label='OVS-Interface <--> OVS-Port')
		nx.draw_networkx_edges(G, pos, edgelist=edge_P2B, width=0.2, alpha=alpha_normal, edge_color='#2ECC71', label='OVS-Port <--> OVS-Bridge')
		nx.draw_networkx_edges(G, pos, edgelist=edge_if_type_patch, width=0.8, alpha=alpha_normal, edge_color='#00FFE8', label='OVS-Patch')
		nx.draw_networkx_edges(G, pos, edgelist=edge_if_type_vxlan, width=1, alpha=alpha_normal, edge_color='#FFF818', label='VxLAN Tunnel')
		nx.draw_networkx_edges(G, pos, edgelist=edge_I2VP, width=0.8, alpha=alpha_normal, edge_color='#68FF66', label='OVS-Interface <--> Linux-VETH')
		nx.draw_networkx_edges(G, pos, edgelist=edge_VP2LB, width=0.2, alpha=alpha_normal, edge_color='#E67E22', label='Linux-VETH <--> Linux-Bridge')
		nx.draw_networkx_edges(G, pos, edgelist=edge_T2LB, width=0.2, alpha=alpha_normal, edge_color='#6A6A6A', label='Linux-TAP <--> Linux-Bridge')
		if enable_fip:
			nx.draw_networkx_edges(G, pos, edgelist=edge_SNAT, width=0.2, alpha=alpha_normal, edge_color='#FF0000', style='dashed', label='fg <--> fpr (in F-IP Namespace)')
			nx.draw_networkx_edges(G, pos, edgelist=edge_ROUTING, width=0.2, alpha=alpha_normal, edge_color='#0000C7', style='dashed', label='rfp <--> qr (in Dist-Router Namespace)')

	## 모든 노드 표시 모드에서, SP 경로만 강조 Edge 스타일 정의/생성
	if isSP and not only_path:
		nx.draw_networkx_edges(G, pos, edgelist=edge_I2P_sp, width=0.1, alpha=alpha_sp, edge_color='#E67E22', label='OVS-Interface <--> OVS-Port')
		nx.draw_networkx_edges(G, pos, edgelist=edge_P2B_sp, width=0.2, alpha=alpha_sp, edge_color='#2ECC71', label='OVS-Port <--> OVS-Bridge')
		nx.draw_networkx_edges(G, pos, edgelist=edge_if_type_patch_sp, width=0.8, alpha=alpha_sp, edge_color='#00FFE8', label='OVS-Patch')
		nx.draw_networkx_edges(G, pos, edgelist=edge_if_type_vxlan_sp, width=1, alpha=alpha_sp, edge_color='#FFF818', label='VxLAN Tunnel')
		nx.draw_networkx_edges(G, pos, edgelist=edge_I2VP_sp, width=0.8, alpha=alpha_sp, edge_color='#68FF66', label='OVS-Interface <--> Linux-VETH')
		nx.draw_networkx_edges(G, pos, edgelist=edge_VP2LB_sp, width=0.2, alpha=alpha_sp, edge_color='#E67E22', label='Linux-VETH <--> Linux-Bridge')
		nx.draw_networkx_edges(G, pos, edgelist=edge_T2LB_sp, width=0.2, alpha=alpha_sp, edge_color='#6A6A6A', label='Linux-TAP <--> Linux-Bridge')
		if enable_fip:
			nx.draw_networkx_edges(G, pos, edgelist=edge_SNAT, width=0.2, alpha=alpha_normal, edge_color='#FF0000', style='dashed', label='fg <--> fpr (in F-IP Namespace)')
			nx.draw_networkx_edges(G, pos, edgelist=edge_ROUTING, width=0.2, alpha=alpha_normal, edge_color='#0000C7', style='dashed', label='rfp <--> qr (in Dist-Router Namespace)')

	plt.axis('off')

	#plt.figure(figsize = (10,9))

	plt.title("OpenStack Network Connectivity")
	print("Processed [elapsed time: %f sec]\n" % (time.time() - start_time))

	print("Creating GEXF.........")
	start_time = time.time()
	nx.write_gexf(G, "/var/www/html/OpenStack-Network-Connectivity.gexf")
	#nx.write_gexf(G, "/var/www/html/OpenStack-Network-Connectivity.gexf", version="1.1draft")
	print("Created GEXF [elapsed time: %f sec]\n" % (time.time() - start_time))

	print("Creating Image........")
	start_time = time.time()
	#plt.legend(numpoints = 1)
	plt.legend(loc=1, prop={'size': 3})
	plt.savefig("/var/www/html/OpenStack-Network-Connectivity.png", format = "png", dpi = 800)
	print("Created Image [elapsed time: %f sec]\n" % (time.time() - start_time))

##### plot.ly 그래프 작성/전송 ########################################################
	if enable_plotly:
		print("Creating Plotly........")
		start_time = time.time()
		#G=nx.random_geometric_graph(200,0.125)
		#pos=nx.get_node_attributes(G,'pos')
		
		## 'G'에 노드별 포지션 정보 추가
		nx.set_node_attributes(G, name='pos', values=pos)
	
		## 기준 노드 선정 (중심에서 0.5, 0.5 거리에 있는 노드 선택)
		dmin = 1
		ncenter = 0
		for n in pos:
			x,y = pos[n]
			d = (x - 0.5) ** 2 + (y - 0.5) ** 2
			if d < dmin:
				ncenter = n
				dmin = d
		
		p = nx.single_source_shortest_path_length(G,ncenter)
		
		## Edge 추적
		edge_trace = go.Scatter(
			x = [],
			y = [],
			line = dict(width=0.5, color='#888'),
			hoverinfo = 'none',
			mode = 'lines')
	
		## Edge 포지션 생성
		for edge in G.edges():
			x0, y0 = G.node[edge[0]]['pos']
			x1, y1 = G.node[edge[1]]['pos']
			edge_trace['x'] += tuple([x0, x1, None])
			edge_trace['y'] += tuple([y0, y1, None])
	
		## Node 추적
		node_trace = go.Scatter(
			x = [],
			y = [],
			text = [],
			mode = 'markers',
			hoverinfo = 'text',
			marker = dict(
				showscale = True,
		 		# colorscale options
				#'Greys' | 'YlGnBu' | 'Greens' | 'YlOrRd' | 'Bluered' | 'RdBu' |
				#'Reds' | 'Blues' | 'Picnic' | 'Rainbow' | 'Portland' | 'Jet' |
				#'Hot' | 'Blackbody' | 'Earth' | 'Electric' | 'Viridis' |
				colorscale = 'YlGnBu',
				reversescale = True,
				color = [],
				size = 10,
				colorbar = dict(
					thickness = 15,
					title = 'Node Connections',
					xanchor = 'left',
					titleside = 'right'
				),
				line = dict(width=2)))
	
		## Node 포지션 생성	
		for node in G.nodes():
			x, y = G.node[node]['pos']
			node_trace['x'] += tuple([x])
			node_trace['y'] += tuple([y])
		
		## Node 표현 정보 생성
		for node, adjacencies in enumerate(G.adjacency()):
			node_trace['marker']['color'] += tuple([len(adjacencies[1])])
			#node_info = '# of connections: ' + str(len(adjacencies[1]))
			node_info = adjacencies[0] + " (#" + str(len(adjacencies[1])) + ") "
			node_trace['text'] += tuple([node_info])
		
		## 그래프 생성
		fig = go.Figure(
			data = [edge_trace, node_trace],
			layout = go.Layout(
				title = '<br>Network graph made with Python',
				titlefont = dict(size = 16),
				showlegend = False,
		 		hovermode = 'closest',
				margin = dict(b=20, l=5, r=5, t=40),
				annotations = [
					dict(
						text = "Python code: <a href='https://plot.ly/ipython-notebooks/network-graphs/'> https://plot.ly/ipython-notebooks/network-graphs/</a>",
						showarrow = False,
						xref = "paper",
						yref="paper",
						x=0.005,
						y=-0.002
					)
				],
				xaxis = dict(showgrid=False, zeroline=False, showticklabels=False),
				yaxis = dict(showgrid=False, zeroline=False, showticklabels=False)
			)
		)
		
		## plot.ly로 데이터 전송
		py.plot(fig, filename='networkx')
		print("Created Plotly [elapsed time: %f sec]\n" % (time.time() - start_time))

#### (참고용) ########################################################
	print("======= Summary of Graph =======")
	## 그래프 정보 출력
	print(nx.info(G))

	## 그래프 밀도 출력 (0~1 사이 값으로, 1은 최대 밀도)
	#print("Network density:", nx.density(G))

	## 최단 경로 찾기 예제
	#fell_whitehead_path = nx.shortest_path(G, source="I:qvoeee4966d-68", target="I:vxlan-0a00e8ae(pub-compute-001)")
	#print("Shortest path between Fell and Whitehead:", fell_whitehead_path)

	## 노드별 중요도(중심성) 측정
	#degree_dict = dict(G.degree(G.nodes()))
	#sorted_degree = sorted(degree_dict.items(), key=operator.itemgetter(1), reverse=True)
	#print("Top 20 nodes by degree:")
	#for d in sorted_degree[:20]:
	#	print(d)
