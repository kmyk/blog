---
layout: post
redirect_from:
  - /writeup/algo/atcoder/kupc-2017-g/
  - /blog/2017/10/22/kupc-2017-g/
date: "2017-10-22T13:33:30+09:00"
tags: [ "competitive", "writeup", "kupc", "atcoder", "lie", "tree", "special-judge" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2017/tasks/kupc2017_g" ]
---

# Kyoto University Programming Contest 2017: G - encode/decode 2017

問題文みたら誰もが自明に思い付く(と思っていた)のを試してみたらWAで、やはり駄目かと思って普通に解いてACした後からrejudgeでWAだったのがACになり、しばらくして社長判断で提出取消になりました。
何も怪しいことはしてないので不正かどうかの疑いすらせず提出したが、手法そのものより「意図的な問題破壊」がNGということです。
次に同じのが出ても同じ手法は控えるので許してという気持ちがあります。
ところでこれはKUPCのG問題であったため私ともうひとりしか不正しなかったのでしょうが、同様のがABCのB問題あたりに置かれて多くの人が見たら不正扱いできない量の提出があったと思います。

ところで(それが取り消された上でも)京都オンサイト$1$位でした。
純粋な競プロでの$1$位は初のはず。
賞品などは無だし全体では$16$位ですが、それでもなんだか嬉しいですね。

## solution

-   encode: 次数が極端に大きいなどで他から区別できる1点を作り、そこから長さ$64$以上のpathを生やし、その各点を$X$のbitに対応させ適当に辺を生やして$0, 1$を埋め込む。
-   decode: 区別された1点から辺を辿る。次数などを見てうまくbit列を抜き出し$X$を復元する。

具体的な構成は乱択とかで無理矢理やるとよい。
[星型の木](https://en.wikipedia.org/wiki/Star%5f%28graph%5ftheory%29)が与えられた場合が面倒なので、次数の大きい順にいくつかの頂点をなかったことにしてしまうとよい。

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <random>
#include <set>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using ll = long long;
using namespace std;

ll decode(int n, int a, vector<vector<int> > const & g) {
    vector<int> sorted_with_degree(n);
    iota(whole(sorted_with_degree), 0);
    sort(whole(sorted_with_degree), [&](int i, int j) { return g[i].size() > g[j].size(); });
    int d1 = sorted_with_degree[0];
    int d2 = sorted_with_degree[1];
    int root = -1;
    repeat (i, n) if (i != d1) {
        if (not count(whole(g[i]), d1) and not g[i].empty()) {
            root = i;
        }
    }

    function<ll (int, int, int)> go = [&](int i, int parent, int depth) {
        vector<int> g_i = g[i];
        g_i.erase(remove(whole(g_i), d1), g_i.end());
        g_i.erase(remove(whole(g_i), parent), g_i.end());
        ll y = 0;
        if (count(whole(g_i), d2)) {
            y |= 1ll << depth;
        }
        g_i.erase(remove(whole(g_i), d2), g_i.end());
        if (g_i.empty()) return 0ll;
        assert (g_i.size() == 1);
        y |= go(g_i[0], i, depth + 1);
        return y;
    };
    return go(root, -1, 0);
}

void decode() {
    // input
    int n, a; cin >> n >> a;
    vector<vector<int> > g(n);
    repeat (i, a) {
        int c, d; cin >> c >> d; -- c; -- d;
        g[c].push_back(d);
        g[d].push_back(c);
    }

    // solve
    ll y = decode(n, a, g);

    // output
    cout << y << endl;
}

void encode() {
    // input
    int n, m; cin >> n >> m;
    vector<set<int> > t(n);
    repeat (i, m) {
        int a, b; cin >> a >> b; -- a; -- b;
        t[a].insert(b);
        t[b].insert(a);
    }
    ll x; cin >> x;

    // solve
    vector<int> leaves;
    repeat (i, n) {
        if (t[i].size() == 1) {
            leaves.push_back(i);
        }
    }
    vector<vector<int> > g;
    default_random_engine gen;
    auto generate = [&]() {
        g.assign(n, vector<int>());
        vector<int> vs;
        // d1
        int d1;
        do {
            d1 = uniform_int_distribution<int>(0, n - 1)(gen);
            if (bernoulli_distribution(0.01)(gen)) return false;
        } while (t[d1].size() > 10);
        vs.push_back(d1);
        vector<int> rootable;
        vector<int> chainable;
        repeat (i, n) if (i != d1) {
            if (t[d1].count(i) or bernoulli_distribution(0.1)(gen)) {
                rootable.push_back(i);
            } else {
                chainable.push_back(i);
                g[d1].push_back(i);
                g[i].push_back(d1);
            }
        }
        // root
        assert (not rootable.empty());
        int root = rootable[uniform_int_distribution<int>(0, rootable.size() - 1)(gen)];
        vs.push_back(root);
        repeat (i, 64) {
            int v = vs.back();
            int w;
            do {
                w = uniform_int_distribution<int>(0, n - 1)(gen);
                if (bernoulli_distribution(0.01)(gen)) return false;
            } while (t[v].count(w) or count(whole(vs), w) or not count(whole(chainable), w));
            vs.push_back(w);
            g[v].push_back(w);
            g[w].push_back(v);
        }
        // d2
        int d2 = 0;
        for (; d2 < n; ++ d2) {
            if (count(whole(vs), d2) or not count(whole(chainable), d2)) continue;
            bool found = true;
            repeat (i, 64) {
                if (x & (1ll << i)) {
                    int v = vs[1 + i];
                    if (t[d2].count(v)) {
                        found = false;
                        break;
                    }
                }
            }
            if (found) break;
        }
        if (d2 == n) return false;
        repeat (i, 64) {
            if (x & (1ll << i)) {
                int v = vs[1 + i];
                g[v].push_back(d2);
                g[d2].push_back(v);
            }
        }
        return true;
    };
    while (not generate());
    assert (decode(n, -1, g) == x);

    // output
    int a = 0;
    repeat (c, n) {
        for (int d : g[c]) if (c < d) {
            ++ a;
        }
    }
    cout << a << endl;
    repeat (c, n) {
        for (int d : g[c]) if (c < d) {
            cout << c + 1 << ' ' << d + 1 << endl;
        }
    }
}

int main() {
    string s; cin >> s;
    if (s == "encode") {
        encode();
    } else if (s == "decode") {
        decode();
    }
    return 0;
}
```
