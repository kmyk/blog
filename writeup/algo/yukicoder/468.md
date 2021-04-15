---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/468/
  - /blog/2016/12/20/yuki-468/
date: "2016-12-20T02:17:06+09:00"
tags: [ "competitive", "writeup", "yukicoder", "graph", "dijkstra", "dag" ]
"target_url": [ "http://yukicoder.me/problems/no/468" ]
---

# Yukicoder No.468 役に立つ競技プログラミング実践編

問題文が長くてつらかった。

## solution

dijkstraを$2$回。ただしある頂点をqueueに追加するのはその頂点がその入次数と同じ回数だけ見られた後。DAGが保証されてるのでメモ化再帰とかでもよい。$O(M \log N)$。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <queue>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
int main() {
    int n, m; cin >> n >> m;
    vector<vector<pair<int, int> > > g(n);
    vector<vector<pair<int, int> > > h(n);
    repeat (i,m) {
        int a, b, c; cin >> a >> b >> c;
        g[a].emplace_back(b, c);
        h[b].emplace_back(a, c);
    }
    vector<int> fast(n); {
        reversed_priority_queue<pair<int, int> > que;
        vector<int> done(n);
        que.emplace(0, 0);
        while (not que.empty()) {
            int a = que.top().second; que.pop();
            for (auto it : g[a]) {
                int b, c; tie(b, c) = it;
                setmax(fast[b], fast[a] + c);
                done[b] += 1;
                if (done[b] == h[b].size()) que.emplace(fast[b], b);
            }
        }
    }
    vector<int> slow(n, fast[n-1]); {
        priority_queue<pair<int, int> > que;
        vector<int> done(n);
        que.emplace(fast[n-1], n-1);
        while (not que.empty()) {
            int b = que.top().second; que.pop();
            for (auto it : h[b]) {
                int a, c; tie(a, c) = it;
                setmin(slow[a], slow[b] - c);
                done[a] += 1;
                if (done[a] == g[a].size()) que.emplace(slow[a], a);
            }
        }
    }
    int t = fast[n-1];
    int p = 0; repeat (a,n) p += fast[a] < slow[a];
    cout << t << ' ' << p << '/' << n << endl;
    return 0;
}
```
