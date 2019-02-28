# Virtaul Network Visualizer

"Virtaul Network Visualizer"

(Note) Current phase is prototype.

# Screen Shots
<div>
    <a href="https://plot.ly/~call518/0/?share_key=8311TGGGOaQIdsOFp8LG1L" target="_blank" title="networkx" style="display: block; text-align: center;"><img src="https://plot.ly/~call518/0.png?share_key=8311TGGGOaQIdsOFp8LG1L" alt="networkx" style="max-width: 100%;width: 600px;"  width="600" onerror="this.onerror=null;this.src='https://plot.ly/404.png';" /></a>
    <script data-plotly="call518:0" sharekey-plotly="8311TGGGOaQIdsOFp8LG1L" src="https://plot.ly/embed.js" async></script>
</div>
![ScreenShot](README/Ex1-OpenStack-Network-Connectivity.png?raw=true)
![ScreenShot](README/Ex2-OpenStack-Network-Connectivity.png?raw=true)

# Tutorial

### Requirements

* 모든 호스트들은 Key 기반 SSH 연결 허용.
* VXLAN 연결 IP를 Hostname으로 질의 가능. (e.g /etc/hosts 등록)
* 기본 그래프 파일 출력 경로 -> "/var/www/html/"
* Headers
 * B: Bridge
 * P: Port
 * I: Interface

### Full

* 생략 정보 없이 전체 구조 조망.
* 대상 규모 조정. (hostnames 리스트 조정)

```bash
# python viewer-full.py
```

### Full - Shortest-Path

* 특정 출발지와 도착지를 지정하여 최단 경로만을 표시.

```bash
# python viewer-full-shortest-path.py --src I:qvo1623b069-e5 --dst I:qvob6a8f706-db
```

### Simple

* 그래프 가독성/간소화를 위해 Interface 정보를 생략.
* (Note) 현재 OpenStack OVS에서 Port당 다수의 Interface를 사용하는 케이스는 없다를 전제로 함.

```bash
# python viewer-simple.py
```

### Simple - Tree

* Tree 형태로 보여줌.
* (Note) 현재는 단일 Host만 지원.
* (Note) 기본 "root_node"는 "br-ex 브릿지"로 지정됨. (변경 가능)

```bash
# python viewer-simple-tree.py
```

# TODO

* 코드 통합/정리.
* Dash나 Plotly 연계하여 Dynamic한 시각화 지원.
* 현재는 OVS만 지원하나, Linux-Bridge 상태까지 포함 필요.
* Namespace 그룹 정보 반영 필요.
