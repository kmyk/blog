---
redirect_from:
layout: post
date: 2018-08-25T17:16:45+09:00
tags: [ "competitive", "writeup", "atcoder", "graph", "tree", "counting" ]
"target_url": [ "https://beta.atcoder.jp/contests/summerfes2018-div1/tasks/summerfes2018_g" ]
---

# Summer Festival Contest 2018 (Division 1): G - 屋台衝突 (Food Stall Collision)

## 解法

直径を作るpathを取り出す。$O(N)$。

単純な無向木という条件から閉路はなく、ある点に$3$つ以上の区間が重なることはない。
これにより区間の絵を書くと以下のようなものになる。

```
A-BABA--BABABABA--------BA--BA--BABAB
 A----BA--------BABABABA--BA--BA-----B
```

逆にここからどういうグラフができるかを考えれば「ほとんど直線状」なもの。
次みたいな感じ。

```
                 * * *     * *                *   *                   *   *
                  \|/      |/                  \ /                     \ /
*--------*---------*-------*------*------*------*-----*----------*------*----*
```

与えられたグラフがこの形になっているかを確認し、後は葉たちの順序の組合せなどを数えればよい。
直径の端点の選択は自由であるので別のものを選んだ場合を漏らさないこと、並べる順序を左右反転した場合を忘れないことに注意。

## メモ

$11$WA

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

template <int32_t MOD>
struct mint {
    int64_t data;  // faster than int32_t a little
    mint() = default;  // data is not initialized
    mint(int64_t value) : data(value) {}  // assume value is in proper range
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->data + other.data; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator - (mint<MOD> other) const { int64_t c = this->data - other.data; return mint<MOD>(c <    0 ? c + MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int64_t c = this->data * int64_t(other.data) % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->data += other.data; if (this->data >= MOD) this->data -= MOD; return *this; }
    inline mint<MOD> & operator -= (mint<MOD> other) { this->data -= other.data; if (this->data <    0) this->data += MOD; return *this; }
    inline mint<MOD> & operator *= (mint<MOD> other) { this->data = this->data * int64_t(other.data) % MOD; if (this->data < 0) this->data += MOD; return *this; }
};

template <int32_t MOD>
mint<MOD> fact(int n) {
    static vector<mint<MOD> > memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() * mint<MOD>(memo.size()));
    }
    return memo[n];
}

pair<int, int> get_eccentricity(int k, vector<vector<int> > const & tree) {
    pair<int, int> result = { -1, -1 };  // (depth, vertex)
    function<void (int, int, int)> dfs = [&](int i, int parent, int depth) {
        chmax(result, make_pair(depth, i));
        for (int j : tree[i]) if (j != parent) {
            dfs(j, i, depth + 1);
        }
    };
    dfs(k, -1, 0);
    return result;
}
int get_diameter(vector<vector<int> > const & tree) {
    return get_eccentricity(get_eccentricity(0, tree).second, tree).first;
}

constexpr int MOD = 1e9 + 7;

mint<MOD> solve(int n, vector<vector<int> > const & g) {
    // check the constructivity
    int t1 = get_eccentricity(0,  g).second;
    int t2 = get_eccentricity(t1, g).second;
    assert (g[t1].size() == 1);
    assert (g[t2].size() == 1);
    vector<int> leaves;
    for (int i = g[t1][0], parent = -1; i != t2; ) {
        assert (g[i].size() >= 2);
        leaves.push_back(g[i].size() - 2);  // push the number of leaves

        int next = -1;
        for (int j : g[i]) if (j != parent) {
            if (g[j].size() >= 2 or j == t2) {  // if a non-leaf exists
                if (next != -1) return 0;
                next = j;  // goto the unique non-leaf
            }
        }
        assert (next != -1);
        parent = i;
        i = next;
    }

    // count
    if (leaves.empty()) {  // the graph with two nodes
        return 4;
    } else {
        leaves.front() += 1;  // for t1
        leaves.back()  += 1;  // for t2

        mint<MOD> cnt = 1;
        for (int l : leaves) {
            cnt *= fact<MOD>(l);
        }
        if (leaves.size() >= 2) {
            cnt *= 2;  // flip
        }
        cnt *= 4;  // t1, t2
        return cnt;
    }
}

int main() {
    // input
    int n; cin >> n;
    vector<vector<int> > g(n);
    REP (i, n - 1) {
        int u, v; cin >> u >> v;
        -- u;
        -- v;
        g[u].push_back(v);
        g[v].push_back(u);
    }

    // solve
    auto cnt = solve(n, g);

    // output
    cout << cnt.data << endl;
    return 0;
}
```
