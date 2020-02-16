---
layout: post
alias: "/blog/2015/10/02/arc-015-c/"
date: 2015-10-02T23:59:59+09:00
tags: [ "atcoder", "arc", "competitive", "writeup" ]
---

# AtCoder Regular Contest 015 C - 変わった単位

使っているノートパソコンのバックライトの調子が悪い。そのせいで色々あって`#ArchLinuxInstallBattle`したりしたのでACが遅れた。まあ事故だったので気にしないこととする。

しかし競技の調子も悪い。

<!-- more -->

## [C - 変わった単位](https://beta.atcoder.jp/contests/arc015/tasks/arc015_3) {#c}

有理数を書いて投げたらWAして困ってしまい、諦めて解答を見た。

### 解法

適当に基準を決めて基準からの最大と最小をそれぞれ求めればよい。
ただし誤差に注意。


危険なのは以下のような入力で、$a = 3 b = \frac{3}{2} c = \frac{3^2}{2} d = \frac{3^2}{2^2} e = \frac{3^3}{2^2} f = \dots$と指数で分母分子が大きくなる。このようにすれば容易に$2^{64}$を越える。

``` c++
200
a 3 b
c 2 b
c 3 d
e 2 d
e 3 f
...
```

`double`を使い、結果が整数なので$\epsilon$として`+ 0.1`する、というのを試したら通った。


### 実装

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <cmath>
#include <algorithm>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
int main() {
    int n; cin >> n;
    map<string,int> ix;
    vector<vector<pair<int,double> > > g;
    repeat (i,n) {
        string a, b; ll m;
        cin >> a >> m >> b;
        if (not ix.count(a)) { int j = ix.size(); ix[a] = j; }
        if (not ix.count(b)) { int j = ix.size(); ix[b] = j; }
        g.resize(ix.size());
        g[ix[b]].push_back(make_pair(ix[a], m));
        g[ix[a]].push_back(make_pair(ix[b], 1 /(double) m));
    }
    vector<double> used(ix.size(), NAN);
    used[0] = 1;
    int j = 0;
    vector<int> v;
    v.push_back(0);
    while (j < v.size()) {
        for (auto p : g[v[j]]) if (std::isnan(used[p.first])) {
            used[p.first] = used[v[j]] * p.second;
            v.push_back(p.first);
        }
        ++ j;
    }
    sort(v.begin(), v.end(), [&](int x, int y) -> bool {
        return used[x] < used[y];
    });
    int a = v.back();
    int b = v.front();
    ll m = used[a] / used[b] + 0.1;
    vector<string> units(ix.size());
    for (auto p : ix) units[p.second] = p.first;
    cout << 1 << units[a] << '=' << m << units[b] << endl;
    return 0;
}
```

### 参考

-   [AtCoder ARC #015 : C - 変わった単位 - kmjp&#39;s blog](http://kmjp.hatenablog.jp/entry/2013/10/06/0930)
