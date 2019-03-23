# OpenStack Network Visualizer

"OpenStack Network Visualizer"


# Screen Shots

![ScreenShot](README/Ex1-OpenStack-Network-Connectivity.png?raw=true)
![ScreenShot](README/Ex2-OpenStack-Network-Connectivity.png?raw=true)
![ScreenShot](README/Ex3-OpenStack-Network-Connectivity.png?raw=true)
![ScreenShot](README/Ex4-OpenStack-Network-Connectivity.png?raw=true)

<div>
    <a href="https://plot.ly/~call518/0/?share_key=8311TGGGOaQIdsOFp8LG1L" target="_blank" title="networkx" style="display: block; text-align: center;"><img src="https://plot.ly/~call518/0.png?share_key=8311TGGGOaQIdsOFp8LG1L" alt="networkx" style="max-width: 100%;width: 100%;"  width="100%" onerror="this.onerror=null;this.src='https://plot.ly/404.png';" /></a>
</div>

# Tutorial

### Usage

```bash
# python [{-s|--src} <src node> {-d|--dst} <dst node> [-o|--onlypath] [-f|--fip] [-p|--plotly]
```

* -s|--src : 경로 탐색시, 출발 노드 지정
* -d|--dst : 경로 탐색시, 도착 노드 지정
* -o|--onlypath : 경로 노드만 표시
* -f|--fip : DVR모드에서 FIP 관련 정보 표시
* -p|--plotly : plotly 활성화

### Requirements

* 모든 호스트들은 Key 기반 SSH 연결 허용.
* VXLAN 연결 IP를 Hostname으로 질의 가능. (e.g /etc/hosts 등록)
* 기본 그래프 파일 출력 경로 -> "/var/www/html/"
* Headers (Types)
 * B: Bridge
 * P: Port
 * I: Interface
 * VP: VETH Pair
 * LB : Linux Bridge
 * T: TAP Device
* (Note) FIP 정보는 DVR 모드만 지원.

### Examples

* 조사 대상 조정. (hostnames 리스트 조정)

```bash
### 전체 구성도 작성

# python visualizer.py


### 전체 구성도에서 특정 구간(src <-> dst)의 경로 탐색

# python visualizer.py --src "T:tap94d54818-a5" --dst "T:tap708a8386-2f"


### 전체 구성도에서 특정 구간(src <-> dst)의 경로 탐색 (해당 경로만 표시)

# python visualizer.py --src T:tap94d54818-a5 --dst "I:eth1(pub-compute-001)" --onlypath
```


# TODO

* 코드 통합/정리.
* Dash나 Plotly 연계하여 Dynamic한 시각화 지원.
* Namespace 정보 반영.
