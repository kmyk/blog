---
layout: post
alias: "/blog/2015/11/18/code-festival-2015-relay/"
date: 2015-11-18T12:47:58+09:00
tags: [ "competitive", "writeup", "codefestival", "atcoder" ]
---

# CODE FESTIVAL 2015 チーム対抗早解きリレー

去年もあったリレーのコンテンツ。けっこう楽しめた。チームメンバーと交流できる時間が増えていてよかった。
どうせならメンバーとペアプロとかできたらもっと良いかもとか思った、けどアンケートに書き忘れたのでここに書いておきます。

本番は我々のチーム`RGB Color Model`は6位か7位ぐらいだったはず。

<!-- more -->

## [A - チーム分け](https://beta.atcoder.jp/contests/code-festival-2015-relay/tasks/cf_2015_relay_a) {#a}

リレーの各チームに関して、メンバーの本戦での順位を計算する問題。
全完チームへのインタビューの際に、「実際のチーム分けと同じなので公平性のためどのチームも等しくなるだろう、というメタ解法があります。」みたいなことが言われていて、なるほどなと思った。

``` c++
#include <iostream>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    array<int,20> a = {};
    repeat (i,200) {
        a[((i / 20) % 2)
            ? (i % 20)
            : (19 - (i % 20))] += i+1;
    }
    // repeat (i,20) cerr << i << ' ' << a[i] << endl;
    int t; cin >> t; -- t;
    cout << a[t] << endl;
    return 0;
}
```

``` plain
1005
```

## [B - 全完](https://beta.atcoder.jp/contests/code-festival-2015-relay/tasks/cf_2015_relay_b) {#b}

適当に回して`/x{10}/`で、みたいな解法をしたかったけど、shellscriptで90度回転は難しいっぽいのでonelinerをした。

``` python
#!/usr/bin/env python3
print('No' if 'x' * 10 in map(lambda x: ''.join(x), zip(*[list(input()) for i in range(10)])) else 'Yes')
```

## [C - 円周率](https://beta.atcoder.jp/contests/code-festival-2015-relay/tasks/cf_2015_relay_c) {#c}

良心的なサンプル。私は偶然ちょうど`0`のところまで覚えてます。

``` python
#!/usr/bin/env python3
print(list('314159265358979323846264338327950').index(input()))
```

## [D - ピザ](https://beta.atcoder.jp/contests/code-festival-2015-relay/tasks/cf_2015_relay_d) {#d}

2倍するだけ。一番簡単だと思う。

``` perl
#!/usr/bin/perl
print~-($_=<>)?2*$_:1,$/
```

## [E - 反転時計](https://beta.atcoder.jp/contests/code-festival-2015-relay/tasks/cf_2015_relay_e) {#e}

時計の問題。時針は6時、分針は30分のところで反転させるのがベスト。それ以前なら待つ。以降なら即時反転。

``` python
#!/usr/bin/env python3
ht, mt = map(int,input().split())
hn, mn = map(int,input().split())
if hn < 6:
    hn = 6
    mn = 30
elif mn < 30:
    mn = 30
hn, mn = (hn + 6) % 12, (mn + 30) % 60
print(['No', 'Yes'][(ht, mt) >= (hn, mn)])
```

## [F - グラフの個数](https://beta.atcoder.jp/contests/code-festival-2015-relay/tasks/cf_2015_relay_f) {#f}

手で数える。
木を作ってから閉路を作っていたら、閉路を作ってから辺を生やして数える方が楽だよ、とメンバーに教えてもらった。
本番、我々のチームは`Text (cat)`で提出して謎WAに苦しんだ。原因は末尾の改行がないことによる。

``` plain
1
2
5
13
```

## [G - 主菜と副菜](https://beta.atcoder.jp/contests/code-festival-2015-relay/tasks/cf_2015_relay_g) {#g}

まず副菜のみに関してdpする。主菜のそれぞれに関して、その主菜を使った残りの金額で副菜を$O(1)$で取る。$O(ML+N)$。

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
int main() {
    int n, m, l; cin >> n >> m >> l;
    vector<int> a(n), b(n); repeat (i,n) cin >> a[i] >> b[i];
    vector<int> c(m), d(m); repeat (i,m) cin >> c[i] >> d[i];
    vector<int> dp(l+1);
    repeat (i,m) {
        repeat_reverse (j,l+1) {
            if (c[i] + j < l) {
                dp[j + c[i]] = max(dp[j + c[i]], dp[j] + d[i]);
            }
        }
    }
    int result = 0;
    repeat (i,n) {
        if (0 <= l - a[i]) {
            result = max(result, dp[l - a[i]] + b[i]);
        }
    }
    cout << result << endl;
    return 0;
}
```

## [H - 塗りつぶし](https://beta.atcoder.jp/contests/code-festival-2015-relay/tasks/cf_2015_relay_h) {#h}

左上から右下への、マスの色の変わる遷移の数が最小となる道を探せばよい。dijkstraで$O(HW \log HW)$。

本番における私の担当問題。一番実装が重い問題。私は特に困難もなくACできたが、はまってしまって苦しんだチームは多かったようだ。
今回はdijkstraでいいけど計算量的にもっと良いアルゴリズムがあるよ、とメンバーに教えてもらったのに、記憶にある単語でぐぐっても見つからなくて悲しい。

``` c++
#include <iostream>
#include <vector>
#include <queue>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
struct state_t {
    int y, x;
    int cost;
};
bool operator < (state_t const & a, state_t const & b) {
    return a.cost > b.cost; // reversed, for priority_queue
}
const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };
int main() {
    int h, w; cin >> h >> w;
    vector<vector<char> > c(h, vector<char>(w));
    repeat (y,h) repeat (x,w) cin >> c[y][x];
    vector<vector<bool> > used(h, vector<bool>(w));
    priority_queue<state_t> q;
    q.push((state_t){ 0, 0, 0 });
    while (not q.empty()) {
        state_t s = q.top(); q.pop();
        if (used[s.y][s.x]) continue;
        used[s.y][s.x] = true;
        if (s.y == h-1 and s.x == w-1) {
            cout << s.cost << endl;
            break;
        }
        repeat (i,4) {
            state_t t = s;
            t.y += dy[i];
            t.x += dx[i];
            if (t.y < 0 or h <= t.y or t.x < 0 or w <= t.x) continue;
            if (used[t.y][t.x]) continue;
            if (c[s.y][s.x] != c[t.y][t.x]) t.cost += 1;
            q.push(t);
        }
    }
    return 0;
}
```

## [I - Platoon Match](https://beta.atcoder.jp/contests/code-festival-2015-relay/tasks/cf_2015_relay_i) {#i}

各プレイヤーのkill数とdeath数の和のいくつかを用いて、全プレイヤーのkill数の総和を作れるならば`valid`。
ただしkill数とdeath数の総和が異なる場合は事前に落とす。

考察が一番重い問題に感じる。本番中にメンバーから説明貰ったけどその場では分からなかった。でも落ち着いて考えれば分かる。

まずkill数の総和 $\Sigma k_i$ とdeath数の総和 $\Sigma d_i$ は等しいとする。
すると2チームのkill数death数をそれぞれ $k_A, d_A, k_B, d_B$ とすると、 $k_A = d_B, d_A = k_B$ を満たすかどうかを見ればよい。
kill数とdeath数の総和が等しいので、 $k_A = d_B$ であれば $d_A = k_B$ は自動的に満たされる。
つまりプレイヤーの集合$A$で、 $\Sigma\_{i \in A} k_i = \Sigma\_{i \not\in A} d_i$ なる$A$を探せばよい。
この条件は、 $\Sigma k_i - \Sigma\_{i \not\in A} k_i = \Sigma\_{i \not\in A} d_i$ であり、$A$の補集合$B$を用いて $\Sigma k_i = \Sigma\_{i \in B} (k_i + d_i)$ と変形できる。
こうなれば左辺は事前に計算し右辺はdpで列挙でき、解ける。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
bool solve(int n, vector<int> const & k, vector<int> const & d) {
    int sk = accumulate(k.begin(), k.end(), 0);
    int sd = accumulate(d.begin(), d.end(), 0);
    if (sk != sd) return false;
    vector<bool> dp(sk+1);
    dp[0] = true;
    repeat (i,n) {
        repeat_reverse (j,sk+1) {
            if (dp[j] and k[i]+d[i]+j < sk+1) {
                dp[k[i]+d[i]+j] = true;
            }
        }
    }
    return dp[sk];
}
int main() {
    int n; cin >> n;
    vector<int> k(n), d(n); repeat (i,n) cin >> k[i] >> d[i];
    cout << (solve(n,k,d) ? "valid" : "invalid") << endl;
    return 0;
}
```

## [J - 石山ゲーム](https://beta.atcoder.jp/contests/code-festival-2015-relay/tasks/cf_2015_relay_j) {#j}

実験すれば解ける。2次元の表を埋めるだけなので楽。
ジャッジの進みかたとかから察するに実行時に探索して解いてたぽいチームがあってすごいなあと思った。

``` python
#!/usr/bin/env python3
x, y = map(int,input().split())
x, y = min(x, y), max(x, y)
if x == 1:
    z = y % 2 != 1
elif x == 2:
    z = y % 4 != 2
elif x == 3:
    if y == 1:
        z = False
    elif y == 4:
        z = True
    else:
        z = y % 4 != 0
elif x == 4:
    z = y != 4
else:
    z = True
print(['rng', 'snuke'][z])
```
