---
layout: post
redirect_from:
  - /writeup/algo/etc/gcj-2017-round2-b/
  - /blog/2017/05/16/gcj-2017-round2-b/
date: "2017-05-16T23:07:40+09:00"
tags: [ "competitive", "writeup", "gcj" ]
"target_url": [ "https://code.google.com/codejam/contest/5314486/dashboard#s=p1" ]
---

# Google Code Jam 2017 Round 2: B. Roller Coaster Scheduling

本番はflowを流してSmallだけ。
Largeは後から解いたが、Contest Analysis読んでも分からなかったのでなんとなくで書いたら通った。
正確には、読んでも分からないのでなくて英語が長くてつらいので丁寧に読むのが面倒。
未証明。

## solution

それらしい下限を求めたらそれが答え。$O(N + C + M)$。

各客について、客の持つチケットの枚数は下限。
各位置について、その位置を$p$ ($1 \le p \le N$)として$p$より前のチケットの総数$S$に対し$\frac{S}{p} \in \mathbb{Q}$は下限。
この下限が答え。

promotionの回数について。
上で求めた運行の回数を$R$とする。
各位置についてのその位置のをチケットの総数$S$に対し$\max(0, S - R)$を考え、その総和が回数。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }

pair<int, int> solve(int n, int c, int m, vector<int> const & p, vector<int> const & b) {
    vector<int> p_cnt(n);
    vector<int> b_cnt(c);
    repeat (i,m) {
        p_cnt[p[i]] += 1;
        b_cnt[b[i]] += 1;
    }
    int rides = 0;
    repeat (i,c) {
        setmax(rides, b_cnt[i]);
    }
    int p_acc = 0;
    repeat (i,n) {
        p_acc += p_cnt[i];
        setmax(rides, (p_acc + (i+1)-1) / (i+1));
    }
    int tickets = 0;
    repeat (i,n) {
        tickets += max(0, p_cnt[i] - rides);
    }
    return { rides, tickets };
}

int main() {
    int t; scanf("%d", &t);
    repeat (x,t) {
        int n, c, m; scanf("%d%d%d", &n, &c, &m);
        vector<int> p(m), b(m); repeat (i,m) { scanf("%d%d", &p[i], &b[i]); -- p[i]; -- b[i]; }
        int y, z; tie(y, z) = solve(n, c, m, p, b);
        printf("Case #%d: %d %d\n", x+1, y, z);
    }
    return 0;
}
```

### smallだけ

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <array>
#include <numeric>
#include <set>
#include <map>
#include <queue>
#include <tuple>
#include <unordered_set>
#include <unordered_map>
#include <functional>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
#define repeat_from_reverse(i,m,n) for (int i = (n)-1; (i) >= int(m); --(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
#define debug(x) #x << " = " << (x) << " "
using ll = long long;
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }


// http://www.prefield.com/algorithm/basic/template.html
#define REP(i,n) for(int i=0;i<(int)n;++i)
#define FOR(i,c) for(__typeof((c).begin())i=(c).begin();i!=(c).end();++i)
#define ALL(c) (c).begin(), (c).end()

// http://www.prefield.com/algorithm/graph/graph.html
struct Edge {
  int src, dst;
  Edge(int src, int dst) :
    src(src), dst(dst) { }
};
typedef vector<Edge> Edges;
typedef vector<Edges> Graph;

// http://www.prefield.com/algorithm/graph/maximum_matching.html + a
#define EVEN(x) (mu[x] == x || (mu[x] != x && phi[mu[x]] != mu[x]))
#define ODD(x)  (mu[x] != x && phi[mu[x]] == mu[x] && phi[x] != x)
#define OUTER(x) (mu[x] != x && phi[mu[x]] == mu[x] && phi[x] == x)
int maximumMatching(const Graph &g) {
  int n = g.size();
  vector<int> mu(n), phi(n), rho(n), scanned(n);
  REP(v,n) mu[v] = phi[v] = rho[v] = v; // (1) initialize
  for (int x = -1; ; ) {
    if (x < 0) {                        // (2) select even
      for (x = 0; x < n && (scanned[x] || !EVEN(x)); ++x);
      if (x == n) break;
    }
    int y = -1;                         // (3) select incident
    FOR(e, g[x]) if (OUTER(e->dst) || (EVEN(e->dst) && rho[e->dst] != rho[x])) y = e->dst;
    if (y == -1) scanned[x] = true, x = -1;
    else if (OUTER(y)) phi[y] = x;      // (4) growth
    else {
      vector<int> dx(n, -2), dy(n, -2); // (5,6), !TRICK! x % 2 --> x >= 0
      for (int k = 0, w = x; dx[w] < 0; w = k % 2 ? mu[w] : phi[w]) dx[w] = k++;
      for (int k = 0, w = y; dy[w] < 0; w = k % 2 ? mu[w] : phi[w]) dy[w] = k++;
      bool vertex_disjoint = true;
      REP(v,n) if (dx[v] >= 0 && dy[v] > 0) vertex_disjoint = false;
      if (vertex_disjoint) {            // (5) augment
        REP(v,n) if (dx[v] % 2) mu[phi[v]] = v, mu[v] = phi[v];
        REP(v,n) if (dy[v] % 2) mu[phi[v]] = v, mu[v] = phi[v];
        mu[x] = y; mu[y] = x; x = -1;
        REP(v,n) phi[v] = rho[v] = v, scanned[v] = false;
      } else {                          // (6) shrink
        int r = x, d = n;
        REP(v,n) if (dx[v] >= 0 && dy[v] >= 0 && rho[v] == v && d > dx[v]) d = dx[v], r = v;
        REP(v,n) if (dx[v] <= d && dx[v] % 2 && rho[phi[v]] != r) phi[phi[v]] = v;
        REP(v,n) if (dy[v] <= d && dy[v] % 2 && rho[phi[v]] != r) phi[phi[v]] = v;
        if (rho[x] != r) phi[x] = y;
        if (rho[y] != r) phi[y] = x;
        REP(v,n) if (dx[rho[v]] >= 0 || dy[rho[v]] >= 0) rho[v] = r;
      }
    }
  }
  Edges matching;
  REP(u,n) if (u < mu[u]) matching.push_back( Edge(u, mu[u]) );
  return matching.size(); // make explicit matching
}


pair<int, int> solve(int n, int c, int m, vector<int> const & p, vector<int> const & b) {
    if (c != 2) return make_pair(-1, -1);
    Graph g(m);
    repeat (i,m) {
        repeat (j,m) {
            if (b[i] != b[j] and not (p[i] == 0 and p[j] == 0)) {
                g[i].push_back(Edge(i, j));
            }
        }
    }
    int y = maximumMatching(g);
    y = y + (m-2*y);
    g = Graph(m);
    repeat (i,m) {
        repeat (j,m) {
            if (b[i] != b[j] and p[i] != p[j]) {
                g[i].push_back(Edge(i, j));
            }
        }
    }
    int z = maximumMatching(g);
    z = z + (m-2*z);
    return make_pair(y, z-y);
}

int main() {
    int t; scanf("%d", &t);
    repeat (x,t) {
        int n, c, m; scanf("%d%d%d", &n, &c, &m);
        vector<int> p(m), b(m); repeat (i,m) { scanf("%d%d", &p[i], &b[i]); -- p[i]; -- b[i]; }
        int y, z; tie(y, z) = solve(n, c, m, p, b);
        printf("Case #%d: %d %d\n", x+1, y, z);
    }
    return 0;
}
```
