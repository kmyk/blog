---
redirect_from:
  - /writeup/algo/yukicoder/709/
layout: post
date: 2018-06-30T02:12+09:00
tags: [ "competitive", "writeup", "yukicoder" ]
"target-url": [ "https://yukicoder.me/problems/no/709" ]
---

# Yukicoder No.709 優勝可能性

## 解法

それぞれの能力に対し現時点での最高値と、その最高値を達成するような人の(重複のない)集合を管理する。
$O(NM)$。

優勝できる可能性がある人の人数は、$M$個の能力について最高値を持つ人数の総和。
$O(1)$で出してもよいが$O(M)$で毎回求めるとバグがない。
ただし複数の能力で最高値を持つ人がいると壊れるため、最高値の能力の中で番号が最小のものの集合にのみ追加するようにする。
最高値がずれて集合から削除されたとき、他の能力のそれに追加できるかどうかを試す。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

int main() {
    // input
    int n, m; cin >> n >> m;
    auto r = vectors(n, m, int());
    REP (y, n) REP (x, m) cin >> r[y][x];

    // solve
    vector<int> max_r(m, INT_MIN);
    vector<vector<int> > argmax_r(m);
    REP (y, n) {
        bool used = false;
        REP (x, m) {
            if (max_r[x] < r[y][x]) {
                max_r[x] = r[y][x];
                for (int y1 : argmax_r[x]) {
                    REP3 (x1, x + 1, m) {
                        if (max_r[x1] == r[y1][x1]) {
                            argmax_r[x1].push_back(y1);
                            break;
                        }
                    }
                }
                argmax_r[x].clear();
            }
            if (max_r[x] == r[y][x]) {
                if (not used) {
                    used = true;
                    argmax_r[x].push_back(y);
                }
            }
        }

        // output
        int answer = 0;
        REP (x, m) {
            answer += argmax_r[x].size();
        }
        cout << answer << endl;
    }
    return 0;
}
```
