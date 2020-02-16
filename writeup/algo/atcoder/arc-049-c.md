---
layout: post
alias: "/blog/2016/03/20/arc-049-c/"
date: 2016-03-20T00:52:17+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "graph" ]
---

# AtCoder Regular Contest 049 C - ぬりまーす

## [C - ぬりまーす](https://beta.atcoder.jp/contests/arc049/tasks/arc049_c)

### 解法

$B \le 10$であるので、タイプ$2$の制約に関連する頂点の使用に関して総当たり。<del>O(B^2 N) ぐらい。</del> たぶん$O(2^B N^2)$あれば抑えられる。

特に、タイプ$2$の制約をタイプ$1$の制約に還元すると楽。
タイプ$2$の制約は、両方塗るとすれば塗る順の制約になり、片方を絶対に塗らないとすれば無視できる。前者はタイプ$1$の制約である。
$u$側に指定されている頂点を集めてきて重複除去し、それの部分集合の全てに関して、その要素を使わないとした場合を全て試す。

ここで、$v$側から禁止集合を作るとWAる。両方使う場合は$u \to v$の順に塗る制約となり、この制約が存在する状況は、両方を塗らない、$u$のみ塗るにも対応する。
残る状況は$v$のみを塗るであるので、禁止するべきは$u$側である。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <queue>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
using namespace std;
int solve_a(vector<vector<int> > const & a, vector<bool> const & forbidden) {
    int n = a.size();
    vector<vector<int> > a_inv(n); repeat (i,n) for (int j : a[i]) a_inv[j].push_back(i);
    vector<int> indeg(n);
    queue<int> q; repeat (i,n) if (not forbidden[i] and a[i].empty()) q.push(i);
    int cnt = 0;
    while (not q.empty()) {
        int i = q.front(); q.pop();
        ++ cnt;
        for (int j : a_inv[i]) if (not forbidden[j]) {
            ++ indeg[j];
            if (indeg[j] == a[j].size()) {
                q.push(j);
            }
        }
    }
    return cnt;
}
int main() {
    int n, al; cin >> n >> al;
    vector<vector<int> > a(n); // x to y
    repeat (i,al) {
        int x, y; cin >> x >> y; -- x; -- y;
        a[x].push_back(y);
    }
    int bl; cin >> bl;
    vector<vector<int> > b(n); // u to v
    vector<int> u(bl);
    repeat (i,bl) {
        int v; cin >> u[i] >> v; -- u[i]; -- v;
        b[u[i]].push_back(v);
    }
    sort(u.begin(), u.end());
    u.erase(unique(u.begin(), u.end()), u.end());
    int ul = u.size();
    int ans = 0;
    repeat (s,1<<ul) {
        // remove restriction b
        vector<vector<int> > c = a;
        vector<bool> forbidden(n);
        repeat (i,ul) {
            if (s&(1<<i)) {
                for (int v : b[u[i]]) {
                    c[v].push_back(u[i]);
                }
            } else {
                forbidden[u[i]] = true;
            }
        }
        setmax(ans, solve_a(c, forbidden));
    }
    cout << ans << endl;
    return 0;
}
```

---

# AtCoder Regular Contest 049 C - ぬりまーす

-   2017年  5月 10日 水曜日 22:02:12 JST
    -   計算量を間違えてると教えてもらったので修正: <https://twitter.com/kosakkun/status/862289354168741888>
