---
category: blog
layout: post
date: "2017-03-24T17:13:10+09:00"
tags: [ "linux", "getrusage" ]
---

# getrusageによるメモリ使用量の計測をbypassしてみた

## 概要

`time`等で用いられる`getrusage`は`RUSAGE_CHILDREN`指定のとき範囲がprocess tree中の部分木なので、orphan processを作れば抜け出すことができる。

## 目的

以下のようなプログラムがあるとする。
$1$GBの空間を消費して何らかの計算を行うプログラムである。

``` c++
#include <bits/stdc++.h>
using namespace std;
int main() {
    vector<char> a(1024*1024*1024, 'A');
    cout << "Hello, world!" << endl;
    return 0;
}
```

これを普通に`time`下で実行すると以下のように$1$GB使用したと報告されてしまう。
これを回避し、ほとんどメモリを消費していないかのように偽装したい。

```
$ command time -f "%es %MKB" ./a.out
Hello, world!
0.69s 1000156KB
```

## getrusage, process tree

linuxにおけるリソース計測には主に`getrusage` syscallが用いられる。
`wait3`/`wait4`経由の場合も多い(例えばGNU timeではそのようだった)が挙動としては同じである。

`getrusage`の第$1$引数`who`は主に`RUSAGE_SELF`か`RUSAGE_CHILDREN`をとる。
`RUSAGE_SELF`が指定された場合は子processの使用リソースは計上されないため、単に`fork`すれば隠蔽できる。
一方で`RUSAGE_CHILDREN`が指定されている場合は単なる`fork`では不十分。
対象processを根とするprocess tree上の部分木内の全てのprocess (`pstree`を見よ)が計測範囲となるため。
つまり対象processのparent processを適当に付け替えればよい。
`getppid` syscallは存在するがsetppidは存在しないが、親processを殺して里親を得ることで実現できる。

手元の環境で実際に行ってprocess treeを見ると以下のようになる。
`gnome-terminal`下の`zsh`から起動した`sleep`が、その部分木の外の`upstart`の直下に移動していることが分かる。

```
$ bash -c 'sleep 10 & kill $$' &

$ pstree | less
systemd-+-ModemManager-+-{gdbus}
        |              `-{gmain}
        |-NetworkManager-+-dhclient
        |                |-dnsmasq
        |                |-{gdbus}
        |                `-{gmain}
        .
        .
        .
        |-lightdm-+-Xorg---{Xorg}
        |         |-lightdm-+-upstart-+-at-spi-bus-laun-+-dbus-daemon
        |         |         |         |                 |-{dconf worker}
        |         |         |         |                 |-{gdbus}
        |         |         |         |-gnome-terminal--+-zsh-+-less
        |         |         |         |                 |     |-pstree
        |         |         |         |                 |     `-vim---vim
        .         .         .         .                 .
        .         .         .         .                 .
        .         .         .         .
        |         |         |         |-sleep
        .         .         .         .
        .         .         .         .
        .         .         .         .
```

## 結論

以下に相当する手順を踏んで呼び出せばよい。
return codeや邪魔な出力は別で適当にすること。

``` sh
#!/bin/sh
bash -c '
    bash -c "
        sleep 0.1
        ./a.out
        kill -CONT '$$'
    " &
    kill $$
'
kill -STOP $$
```

```
$ command time -f "%es %MKB" ./a.sh
Hello, world!
0.24s 3304KB
```

上手く偽装できている。

ただし実際の使用量は変化しないことに注意。別な機構(例えば`ulimit`など)には補足されうる。
