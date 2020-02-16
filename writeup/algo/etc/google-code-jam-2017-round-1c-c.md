---
layout: post
redirect_from:
  - /blog/2018/04/05/google-code-jam-2017-round-1c-c/
date: "2018-04-05T00:17:38+09:00"
tags: [ "competitive", "writeup", "gcj", "probability" ]
"target_url": [ "https://codejam.withgoogle.com/codejam/contest/dashboard?c=3274486#s=p2" ]
---

# Google Code Jam 2017 Round 1C: C. Core Training

## solution

$N = K$の場合は、最も$p\_i$の小さいコア$i$を強化するのがよい。
$N \ne K$の場合は、$A, B$を全て試して次のようにする: 元々の$p\_i$の大きい順に、上から$A$個を$p\_i = 1.0$に、残りの中で上から$B$個を抜き出してきてそれらに対して$N = K$の場合と同様にする。

kmjpさんの解説も見て: <http://kmjp.hatenablog.jp/entry/2017/05/03/1100>

## note

「$+ 0.0001$した場合をそれぞれに試してみて最も改善されるものを採用」という貪欲ではWAだった。editorialで次のように言及されているので通ると思うのだがなぜだろう。

>   It is also possible to arrive at the correct answers via other methods such as gradient descent.

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

double run_dp(int k, vector<int> const & p) {
    vector<double> cur, prv;
    cur.assign(k + 1, 0);
    cur[0] = 1;
    for (int p_i : p) {
        cur.swap(prv);
        cur.assign(k + 1, 0);
        REP (j, k) {
            cur[j + 1] += prv[j] * (p_i / 10000.0);
            cur[j]     += prv[j] * ((10000 - p_i) / 10000.0);
        }
        cur[k] += prv[k];
    }
    return cur[k];
}
double solve(int n, int k, const int u, vector<int> const & p) {
    double answer = - INFINITY;
    REP (a, n + 1) {
        REP3 (b, a, n + 1) {
            int v = u;
            vector<int> q = p;
            sort(q.rbegin(), q.rend());
            REP (i, a) {
                while (v and q[i] < 10000) {
                    -- v;
                    ++ q[i];
                }
            }
            if (a < b) {
                while (v and q[b - 1] < 10000) {
                    int i = min_element(q.begin() + a, q.begin() + b) - q.begin();
                    -- v;
                    ++ q[i];
                }
            }
            chmax(answer, run_dp(k, q));
        }
    }
    return answer;
}

int read_fixed() {
    int a, b; scanf("%d.%d", &a, &b);
    return a * 10000 + b;
}
int main() {
    int t; scanf("%d", &t);
    REP (i, t) {
        int n, k; scanf("%d%d", &n, &k);
        int u = read_fixed();
        vector<int> p(n);
        REP (i, n) p[i] = read_fixed();
        double answer = solve(n, k, u, p);
        printf("Case #%d: %.6lf\n", i + 1, answer);
fprintf(stderr, "Case #%d: %.6lf\n", i + 1, answer);
    }
    return 0;
}
```
