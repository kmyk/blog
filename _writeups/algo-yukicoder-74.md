---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/74/
  - /blog/2016/06/22/yuki-74/
date: 2016-06-22T04:05:40+09:00
tags: [ "competitive", "writeup", "yukicoder", "graph" ]
"target_url": [ "http://yukicoder.me/problems/no/74" ]
---

# Yukicoder No.74 貯金箱の退屈

これすき

## solution

依存関係で切って、グラフに落として各連結成分ごとに見る。$O(N^2)$。

それ単体でひっくり返せるコインと、何か別のコインと一緒にしかひっくり返せないコインがある。
ここで、コインを頂点、一緒にひっくり返すことができるという関係を辺として、単純グラフを書く。
それ単体でひっくり返せるコインに対し、その対応する頂点に印を付ける。

単体でひっくり返せないコインでも、その一緒にひっくり返さないといけないコインが単体でひっくり返せるなら、単体でひっくり返せると考えてよい。
単体でひっくり返せるなら、表向きにできるのは明らかである。
つまり、印の付いた頂点を含む連結成分は全て無視できる。

印の付いた頂点を含まない連結成分について考えよう。
このとき、連結成分内の適当な$2$頂点について、それらを一緒にひっくり返すことができる。
ひっくり返す関係で道を作ることを考えればよい。
これにより、その連結成分内で裏を向いているコインが偶数枚であるかを確認すればよい。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <set>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    // input
    int n; cin >> n;
    vector<int> d(n); repeat (i,n) cin >> d[i];
    vector<bool> w(n); repeat (i,n) { int it; cin >> it; w[i] = it; }
    // make graph
    vector<set<int> > g(n);
    repeat (i,n) {
        int x =  (i + d[i]) % n;
        int y = ((i - d[i]) % n + n) % n;
        g[x].insert(y);
        g[y].insert(x);
    }
    vector<bool> loop(n);
    repeat (i,n) loop[i] = g[i].count(i);
    while (true) {
        bool modified = false;
        repeat (i,n) if (not loop[i]) {
            for (int j : g[i]) if (loop[j]) {
                loop[i] = true;
                modified = true;
            }
        }
        if (not modified) break;
    }
    // check the answer
    function<void (int, set<int> &)> select = [&](int i, set<int> & component) {
        component.insert(i);
        for (int j : g[i]) if (not component.count(j)) {
            select(j, component);
        }
    };
    bool ans = true;
    vector<bool> used(n);
    repeat (i,n) if (not used[i]) {
        if (loop[i]) {
            used[i] = true;
            continue;
        }
        set<int> component;
        select(i, component);
        int cnt = 0;
        for (int j : component) {
            used[j] = true;
            cnt += not w[j];
        }
        if (cnt % 2 != 0) {
            ans = false;
            break;
        }
    }
    // output
    cout << (ans ? "Yes" : "No") << endl;
    return 0;
}
```
