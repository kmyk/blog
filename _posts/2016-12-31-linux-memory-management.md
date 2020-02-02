---
category: blog
layout: post
date: "2016-12-31T23:33:38+09:00"
title: "Linuxにおけるメモリ管理機構の利用に関する覚え書き"
tags: [ "linux", "oom-killer", "ulimit" ]
---

## OOM killer

>   OOM Killer（Out of Memory Killer）は，システムが実メモリーと仮想メモリー空間（スワップ領域）を使い切り，必要なメモリー領域を新たに確保できない場合に，プロセスを強制終了させて空きメモリーを確保する，Linuxカーネルの仕組みです。

引用元: [Linuxキーワード - OOM Killer：ITpro](http://itpro.nikkeibp.co.jp/article/COLUMN/20061117/254053/)

つまりメモリ食いすぎなプロセスを殺してくれるLinux kernelの機能。

### 優先順位

RAMとswap領域が使い切られたとき、OOM killerはプロセスを殺す(`SIGKILL`)。
殺すプロセスはOOM scoreと呼ばれる値が最も高いもの。
この値は `/proc/$PID/oom_score` で確認でき、最もこの値が高いプロセスは`dstat --top-oom`で確認できる。

OOM scoreの計算式は基本的にメモリ使用率$\frac{x}{\mathrm{RAM} + \mathrm{swap}}$の$1000$倍(つまりパーミル、‰)。
全部使ったらOOM scoreは$1000$。
ただしさらに`root`補正($-30$)と`oom_score_adj`補正(そのまま加算される)がかかる。

上は現在(`4.4.0-57-generic`で確認)のもの。古くは違ったらしいので今後変化しないとは限らない。


### 召喚

root権限がない共用の鯖上で、計算資源を占有する行儀の悪いプロセスを殺したいとする。
OOM scoreの決め方から、以下の$2$点を満たすプロセスを生成すれば目標が達成される。

1.  殺害目標プロセスと合わせて$100\%$のメモリを消費する。
2.  殺害目標プロセスよりメモリ消費量が少ない。

ただし注意点として、

-   大きなmallocはメモリの連続性を要求してしまうので、ある程度小分けにして確保する。
-   over-commitの発生を防ぐため、実際に書き込む。

特にover-commitについて。
これはlinux kernelの機能で、確保されたメモリ空間に対し、それが実際に使われるまで実メモリの消費を遅延する機能。
これにより、単に`malloc`を何度も呼ぶだけではOOM killerを呼ぶという目的は達成できないことに注意。

具体的には以下のC++のコードのようにするとよいだろう。
コマンドライン引数として与えた$n$に対し$n$MB確保するだけのプログラム。

``` c++
#include <bits/stdc++.h>
using namespace std;
int main(int argc, char **argv) {
    assert (argc == 2);
    int n = atoi(argv[1]); // MB
    vector<string> a;
    while (n --) a.push_back(string(1024 * 1024, '\0'));
    return 0;
}
```

## ulimit

コマンドに割り当てる資源を制限するためのshell組込み関数。
メモリに限らず諸々を制限可能。
shellの機能であるので設定の影響範囲はそのshellから呼んだものだけ。

``` sh
$ ulimit -a
core file size          (blocks, -c) 0
data seg size           (kbytes, -d) unlimited
scheduling priority             (-e) 0
file size               (blocks, -f) unlimited
pending signals                 (-i) 63236
max locked memory       (kbytes, -l) 64
max memory size         (kbytes, -m) unlimited
open files                      (-n) 1024
pipe size            (512 bytes, -p) 8
POSIX message queues     (bytes, -q) 819200
real-time priority              (-r) 0
stack size              (kbytes, -s) 8192
cpu time               (seconds, -t) unlimited
max user processes              (-u) 63236
virtual memory          (kbytes, -v) 8156448
file locks                      (-x) unlimited
```

内部実装としては `sys_setrlimit` / `sys_getrlimit` system call。
呼び出したプロセスに対して設定された値が `execve` や `fork` で伝播することで設定される。

### /etc/security/limits.conf

同様の制限を全体に対してかけるための設定ファイル。
ユーザが設定可能な上限(`hard`)と、デフォルトでの制限(`soft`)を設定可能。

### おすすめ設定

`virtual memory`を全体の半分ぐらいに制限しておくとよい。
うっかりメモリを吹き飛ばすようなプログラムを書いてしまったときに、速やかに止まってくれる。
`.bashrc`とかに書く。

``` sh
$ ulimit -Sv `cat /proc/meminfo | grep MemTotal | awk '{ print $2 / 2 }'`
```

## 参考

OOM killer:

-   [Linuxキーワード - OOM Killer：ITpro](http://itpro.nikkeibp.co.jp/article/COLUMN/20061117/254053/)
-   [How is kernel oom score calculated? - Server Fault](http://serverfault.com/questions/571319/how-is-kernel-oom-score-calculated/571326)
-   [OOM Killer に殺されないようにする - いますぐ実践! Linuxシステム管理 / Vol.238](http://www.usupi.org/sysad/238.html)
-   [passingloop   &bull; Linux のオーバーコミットについて調べてみた](http://passingloop.tumblr.com/post/11957331420/overcommit-and-oom-killer)

ulimit:

-   [Linuxコマンド集 - 【 ulimit 】 コマンドに割り当てる資源を制限する：ITpro](http://itpro.nikkeibp.co.jp/article/COLUMN/20060227/230911/)
-   [Man page of ULIMIT](https://linuxjm.osdn.jp/html/LDP_man-pages/man3/ulimit.3.html)
-   [Man page of GETRLIMIT](https://linuxjm.osdn.jp/html/LDP_man-pages/man2/getrlimit.2.html)
-   [/etc/security/limits.confに関するメモ | OpenGroov](https://open-groove.net/linux/memo-etcsecuritylimits-conf/)
