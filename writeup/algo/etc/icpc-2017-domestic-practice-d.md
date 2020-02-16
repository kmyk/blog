---
layout: post
redirect_from:
  - /blog/2017/07/02/icpc-2017-domestic-practice-d/
date: "2017-07-02T22:11:25+09:00"
tags: [ "competitive", "writeup", "aoj", "icpc-domestic", "binary-search", "greedy" ]
---

# ACM-ICPC 2017 模擬国内予選: D. ゲームバランス

落としたのは反省しています。しかしテストケースが悪意に満ちているのだけは許せない。

## solution

答え$X$で二分探索。経験値は貪欲に得てよい。$O((N + M) \log \max S\_i)$。

注意点として

-   $1 + X \le s\_1$で初手で詰んだなら$\infty$を返すと綺麗
    -   $-1$とかを返すなら前処理と二分探索の左端の修正が必要
-   強い敵を倒せば経験値が多いとは限らない
    -   自分のレベルに近いものを倒すのが正しくて、そのような敵の番号をしゃくとり法っぽく管理する
-   テストケースに対する出力はほとんど$-1$で正しい
    -   提出前に確認してこれ間違ってますねとか言うのは罠にかかっている

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;

template <typename UnaryPredicate>
ll binsearch(ll l, ll r, UnaryPredicate p) { // [l, r), p is monotone
    assert (l < r);
    -- l;
    while (r - l > 1) {
        ll m = (l + r) / 2;
        (p(m) ? r : l) = m;
    }
    return r; // = min { x | p(x) }
}


const int inf = 1e9+7;
int count_battle(vector<int> const & s, int m, int x) {
    int n = s.size();
    int l = 1;
    auto getexp = [&](int s_i) {
        return s_i < l + x ? max(1, x - abs(l - s_i)) : 0;
    };
    if (getexp(s[0]) == 0) return inf; // impossible
    int cnt = 0;
    int i = 0;
    for (; cnt < m + 3; ++ cnt) {
        if (getexp(s[n - 1]) != 0) {
            ++ cnt;
            break;
        }
        while (i + 1 < n and s[i + 1] <= l) ++ i;
        int j = max(0, i - 3);
        while (j + 1 < n and getexp(s[j]) <= getexp(s[j + 1])) ++ j;
        l += getexp(s[j]);
    }
    return cnt;
}

int solve(vector<int> const & s, int m) {
    int n = s.size();
    int y = binsearch(2, s[n - 1] + 100, [&](int x) {
        return count_battle(s, m, x) < m;
    }) - 1;
    int cnt = count_battle(s, m, y);
    if (cnt == inf or cnt < m) return -1;
    return y;
}

int main() {
    while (true) {
        int n, m; scanf("%d%d", &n, &m);
        if (n == 0 and m == 0) break;
        vector<int> s(n); repeat (i, n) scanf("%d", &s[i]);
        int result = solve(s, m);
        printf("%d\n", result);
    }
    return 0;
}
```
