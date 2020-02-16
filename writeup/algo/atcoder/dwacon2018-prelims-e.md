---
layout: post
alias: "/blog/2018/01/14/dwacon2018-prelims-e/"
date: "2018-01-14T03:41:58+09:00"
tags: [ "competitive", "writeup", "atcoder", "dwacon", "reactive", "tree", "centroid" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwacon2018-prelims/tasks/dwacon2018_prelims_e" ]
---

# 第4回 ドワンゴからの挑戦状 予選: E - ニワンゴくんの家探し

C以降では最も簡単だと思います。でも最後の出力の前に`!`を付け忘れて$1$WAしました。

重心がひとつのとき部分木を大きさでsortしないとだめなのを後から指摘された(記事の修正した)(なしでも通ってしまったが)。
さらに$2000 \cdot (\frac{3}{5})^{14} \approx 1.57$だけで言えてることも気付いてなかった(再度修正した)。

## solution

重心分解。

-   重心が$2$点あるなら、それらを$u, v$として質問する。
    家の候補の頂点数はちょうど$\frac{N}{2}$になる。
-   重心が$1$点のみなら、それに隣接する頂点から部分木が大きい順に$2$点選んで$u, v$として質問する。
    隣接する頂点が$k \le 5$点あるとする ($k \ge 2$としてよいため$u, v$は必ず選べることに注意)。
    -   返答が$u, v$いずれかであれば、家はその部分木の中。家の候補の頂点数は$\frac{N - 1}{k}$になる。
    -   返答が$0$であれば、家はそれらの部分木の中にはない。家の候補の頂点数は$\frac{(N - 1)(k - 2)}{k}$。

最悪の場合でも毎回$N$は$\frac{3}{5}$未満になるので$14$回やれば$2000 \cdot (\frac{3}{5})^{14} \approx 1.57$となり、候補の頂点数$$k \lt 1.57$となり$k = 1 \in \mathbb{N}$個に絞られる。
よってクエリ数は$Q = 14$あれば十分。
`assert (query_count <= 13);`みたいなのを付けて提出したら落ちたから$13$だとだめな(あるいは私の実装が間違ってる)気がするが証明はできず。

<del>重心が$1$点の$k = 5$の場合で失敗すると次は$k = 3$に落ちることから$2000 \cdot (\frac{3}{5} \cdot \frac{1}{3})^7 \approx 0.026$。</del>
これは嘘で、部分木の大きさにばらつきがあるときは重心がずれることがある。
ただし部分木の大きさにばらつきがあるということは$\frac{3}{5}$よりもっと小さくなりうるのでこれだけでは$13$回ではだめな証明にはならない。


## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

vector<int> get_centroids(vector<vector<int> > const & g, int root, set<int> const & forbidden) {
    map<int, int> available; {
        function<void (int, int)> go = [&](int i, int parent) {
            available.emplace(i, available.size());
            for (auto j : g[i]) if (j != parent and not forbidden.count(j)) {
                go(j, i);
            }
        };
        go(root, -1);
    }
    int n = available.size();
    vector<int> result;
    vector<int> size(n, -1);
    function<void (int, int)> go = [&](int x, int parent) {
        bool is_centroid = true;
        int i = available[x];
        size[i] = 1;
        for (auto y : g[x]) if (y != parent and available.count(y)) {
            int j = available[y];
            go(y, x);
            size[i] += size[j];
            if (size[j] > n / 2) is_centroid = false;
        }
        if (n - size[i] > n / 2) is_centroid = false;
        if (is_centroid) result.push_back(x);
    };
    go(root, -1);
    return result;
}

int ask(int u, int v) {
    cout << "? " << (u + 1) << " " << (v + 1) << endl;
    cout.flush();
    int ans; cin >> ans;
    return ans - 1;
}

int main() {
    // input
    int n, q; cin >> n >> q;
    vector<vector<int> > g(n);
    REP (i, n - 1) {
        int a, b; cin >> a >> b;
        -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    // ask
    int root = 0;
    set<int> forbidden;
    while (q --) {
        vector<int> centroid = get_centroids(g, root, forbidden);
        if (centroid.size() == 2) {
            int ans = ask(centroid[0], centroid[1]);
            if (ans == centroid[1]) swap(centroid[0], centroid[1]);
            assert (ans == centroid[0]);
            root = centroid[0];
            forbidden.insert(centroid[1]);
        } else {
            vector<int> child;
            for (int j : g[centroid[0]]) if (not count(ALL(forbidden), j)) {
                child.push_back(j);
            }
            if (child.empty()) {
                assert (root == centroid[0]);
                break;  // already found
            }
            assert (child.size() >= 2);
            int ans = ask(child[0], child[1]);
            if (ans == child[1]) swap(child[0], child[1]);
            if (ans == child[0]) {
                root = child[0];
                forbidden.insert(centroid[0]);
            } else {
                assert (ans == -1);
                root = centroid[0];
                forbidden.insert(child[0]);
                forbidden.insert(child[1]);
            }
        }
    }
    // answer
    cout << "! " << (root + 1) << endl;
    return 0;
}
```

---

# 第4回 ドワンゴからの挑戦状 予選: E - ニワンゴくんの家探し

-   2018年  1月 14日 日曜日 23:50:58 JST
    -   修正
-   2018年  1月 15日 月曜日 15:08:55 JST
    -   追記 これで最後のはず
