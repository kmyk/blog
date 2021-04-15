---
layout: post
redirect_from:
  - /writeup/algo/codeforces/codeforces-321/
  - /blog/2015/09/04/codeforces-321/
date: 2015-09-04T00:31:27+09:00
tags: [ "codeforces", "competitive", "writeup" ]
"target_url": [ "http://codeforces.com/contest/321" ]
---

# Codeforces Round #190 (Div. 1)

茶会。2完で2位。提出時間見ると先輩氏は各問題を私の2倍速で解いててさすがだなあと思った。

<!-- more -->

## [A. Ciel and Robot](http://codeforces.com/contest/321/problem/A) {#a}

まあ分かる。なんだか好きな感じの問題。

### 問題

目標となる座標と、ロボットへの命令列が与えられる。命令列を無限回繰り返し実行させたとき、ロボットは目標の座標を踏むかどうかを判定する。

### 解法

命令列の1回の実行で結果的にどれだけ動くことになるか求める。
1回目の実行の各点から、その1回分ずつまとめて動いていった上に目標座標があるかは、引き算と剰余で$O(1)$で求められる。
よって全体では命令列を$s$とし$O(|s|)$。
逆向きの実行は許されてないので、割り算するときは正負に注意。

## 解答

``` python
#!/usr/bin/env python3
import operator
table = {
        'U' : ( 0,  1),
        'D' : ( 0, -1),
        'L' : (-1,  0),
        'R' : ( 1,  0) }

a, b = map(int,input().split())
s = list(input())

zs = set()
x, y = 0, 0
zs.add((x, y))
for c in s:
    x, y = map(operator.add, (x, y), table[c])
    zs.add((x, y))

result = False
for (zx, zy) in zs:
    p, q = a - zx, b - zy
    if (x == 0 and p != 0) or (x != 0 and p % x != 0) or (x != 0 and p // x < 0): continue
    if (y == 0 and q != 0) or (y != 0 and q % y != 0) or (y != 0 and q // y < 0): continue
    if x != 0 and y != 0 and p // x != q // y: continue
    result = True

print('Yes' if result else 'No')
```

if文のあたりが怖い。`and`や`not`だけじゃなくて`implies`論理演算子が欲しいです。でも`<=`は嫌です。

## [B. Ciel and Duel](http://codeforces.com/contest/321/problem/B) {#b}

結構苦戦した。守備表示なモンスターを倒す条件をケアし忘れて1WA。

### 問題

遊戯王ぽいルールの下で、敵味方の場のモンスターカードが与えられて、相手プレイヤーへのダメージの最大値を求める。攻撃表示の敵には超過ダメージがあって、敵モンスターを全滅させれば直接攻撃ができる。

### 解法

守備表示の敵を無視して超過ダメージのみを狙う戦略と、全滅させて直接攻撃をする戦略、これらを両方試して良い方を選べばよい。
超過ダメージ戦略は、何体のモンスターに攻撃させるか総当たり。
直接攻撃戦略は、守備表示のモンスターはできるだけギリギリで倒して、残りは適当にする。

守備表示のモンスターには相手のそれを超過する戦闘力のモンスターをぶつけないといけないことに注意。
$n,m \le 100$に対しおおよそ2乗ぐらいの計算量。

### 解答

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
ll strategy_exceeding(vector<int> xs, vector<int> zs) {
    {
        int n = xs.size();
        int m = zs.size();
        if (n < m) {
            zs.erase(zs.begin(), zs.end() - n);
        } else if (n > m) {
            xs.erase(xs.begin() + m, xs.end());
        }
    }
    assert (xs.size() == zs.size());
    int n = xs.size();
    ll result = 0;
    repeat (i,n) {
        ll acc = 0;
        repeat_from (j,i,n) {
            if (zs[j] < xs[j-i]) break;
            acc += zs[j] - xs[j-i];
        }
        result = max(result, acc);
    }
    return result;
}
ll strategy_direct(vector<int> const & xs, vector<int> const & ys, vector<int> zs) {
    if (xs.size() + ys.size() >= zs.size()) return 0;
    repeat (i,int(ys.size())) {
        auto it = lower_bound(zs.begin(), zs.end(), ys[i]+1);
        if (it == zs.end()) return 0;
        zs.erase(it);
    }
    ll result = 0;
    repeat (i,int(xs.size())) {
        auto it = lower_bound(zs.begin(), zs.end(), xs[i]);
        if (it == zs.end()) return 0;
        result += *it - xs[i];
        zs.erase(it);
    }
    result += accumulate(zs.begin(), zs.end(), 0);
    return result;
}
int main() {
    int n, m; cin >> n >> m;
    vector<int> xs; // atk
    vector<int> ys; // def
    repeat (i,n) {
        string a; int b; cin >> a >> b;
        (a == "ATK" ? xs : ys).push_back(b);
    }
    vector<int> zs(m);
    repeat (i,m) cin >> zs[i];
    sort(xs.begin(), xs.end());
    sort(ys.begin(), ys.end());
    sort(zs.begin(), zs.end());
    cout << max(strategy_exceeding(xs, zs), strategy_direct(xs, ys, zs)) << endl;
    return 0;
}
```

渡された配列を破壊しながら処理したりしなかったりするのが微妙な感じ。

## [C. Ciel the Commander](http://codeforces.com/contest/321/problem/C) {#c}

解法は自然に思いついた。Bが遅かったので、時間中には書けなかった。dfsするときに`depth`に`1`足すの忘れてて1WAした。

<del> これの解法を木の重心分解とか呼ぶらしいというのは通してから知った。 </del>  
違った。通ったから油断してた。<http://mathworld.wolfram.com/CentroidPoint.html>

### 問題

木が与えられる。各頂点に`'A' > 'B' > 'C' > 'D' > ... > 'Z'`の記号を振る。任意の2頂点間について、記号が同じであれば、2つを繋ぐ道の上にその記号より強い記号を持つ頂点が存在する、を成り立たせたい。そのような記号の振り方を出力する。

### 解法

まずそのような記号の振り方の存在に関して、必ず存在する。明らかに一番厳しい場合である直線状の木を考えても、

``` plain
A
BAB
CBCACBC
DCDBDCDADCDBDCD
EDECEDEBEDECEDEAEDECEDEBEDECEDE
FEFDFEFCFEFDFEFBFEFDFEFCFEFDFEFAFEFDFEFCFEFDFEFBFEFDFEFCFEFDFEF
...
```

とすれば$10^5 \ll 2^{26}-1$なので十分記号は足りる。

このような記号の振り方を求める。まず最も遠い頂点との距離が最小であるような頂点Pを求め、そこに記号`'A'`を振る。その頂点を除いて木を分割し、小さくなった木々を対し再帰的に処理する。木の直径(頂点間の距離で最大のもの)が、適当な点から最も遠い点Aとその点Aから最も遠い点Bの距離で与えられる、という事実を使ってそのような点Pを求めた。

<del> O(n \log n)。 </del> グラフの頂点数が必ず半分以下になるとは限らないので、$n \log n$よりちょっと大きくなるかも。

### 解答

``` c++
#include <iostream>
#include <vector>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
std::pair<int,int> deepest_node(int i, int p, vector<vector<int> > const & g, vector<char> const & used) {
    int result = i; int depth = 0;
    for (int j : g[i]) if (j != p and not used[j]) {
        auto q = deepest_node(j, i, g, used);
        if (depth < q.second + 1) {
            result = q.first;
            depth = q.second + 1;
        }
    }
    return make_pair(result, depth);
}
int find_by_depth(int target, int current, int i, int p, vector<vector<int> > const & g, vector<char> const & used) {
    if (target == current) return i;
    for (int j : g[i]) if (j != p and not used[j]) {
        int k = find_by_depth(target, current + 1, j, i, g, used);
        if (k != -1) return k;
    }
    return -1;
}
void f(int i, char c, vector<vector<int> > const & g, vector<char> & result) {
    assert ('A' <= c and c <= 'Z');
    assert (not result[i]);
    int j = deepest_node(i, -1, g, result).first;
    int diameter = deepest_node(j, -1, g, result).second;
    int k = find_by_depth(diameter / 2, 0, j, -1, g, result);
    assert (k != -1);
    result[k] = c;
    for (int l : g[k]) if (not result[l]) {
        f(l, c+1, g, result);
    }
}
vector<char> solve(vector<vector<int> > const & g) {
    vector<char> result(g.size(), '\0');
    f(0, 'A', g, result);
    return result;
}
int main() {
    int n; cin >> n;
    assert (n < (1<<26)-1);
    vector<vector<int> > g(n);
    repeat (i,n-1) {
        int a, b; cin >> a >> b; -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    vector<char> s = solve(g);
    cout << s[0]; repeat_from (i,1,n) cout << ' ' << s[i]; cout << endl;
    return 0;
}
```

引数の順を決めるのにけっこう困った。`find_by_depth`は`target`と`current`まとめた方が良かったですね。

---

# Codeforces Round #190 (Div. 1)

-   Fri Sep  4 21:31:03 JST 2015
    -   重心じゃなかったので訂正
