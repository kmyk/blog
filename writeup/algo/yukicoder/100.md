---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/100/
  - /blog/2017/01/05/yuki-100/
date: "2017-01-05T18:23:06+09:00"
tags: [ "competitive", "writeup", "yukicoder", "lie", "alarm" ]
"target_url": [ "http://yukicoder.me/problems/no/100" ]
---

# Yukicoder No.100 直列あみだくじ

これはそこそこ落ちにくいのでは。

## solution

嘘解法。heuristicな探索 + `SIGALRM`。

与えられた置換$\sigma$に対し置換$\tau$で$\tau \circ \tau = \sigma$となるような$\tau$を構成せよという問題。
$\tau(x) = y$と仮定すると$\tau(y) = \sigma(x)$という制約が得られ、再帰的に$\tau(\sigma(x)) = \sigma(\tau(y)), \tau(\sigma(\tau(y))) = \sigma(\tau(\sigma(x))), \dots$と続く。
この性質により自由度は比較的小さく、存在するならば高速に構成できる。
一方存在しない場合はとても時間がかかるので、適当な時間で打ち切るとよい。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <functional>
#include <sys/signal.h>
#include <sys/time.h>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
void handler(int) {
    cout << "No" << endl;
    exit(EXIT_SUCCESS);
}
int main() {
    // timer
    signal(SIGALRM, handler);
    itimerval tv;
    tv.it_value.tv_sec = 4;
    tv.it_value.tv_usec = 800 * 1000;
    tv.it_interval = {};
    setitimer(ITIMER_REAL, &tv, NULL);
    // solve
    int n; cin >> n;
    vector<int> f(n); repeat (i,n) { cin >> f[i]; -- f[i]; }
    vector<int> g(n, -1), g_inv(n, -1);
    function<bool (int, int)> def = [&](int i, int j) {
        if (g    [i] != -1 and g    [i] != j) return false;
        if (g_inv[j] != -1 and g_inv[j] != i) return false;
        if (g[i] == j and g_inv[j] == i) return true;
        g[i] = j;
        g_inv[j] = i;
        return def(j, f[i]);
    };
    function<bool (int)> go = [&](int i) {
        while (i < n and g[i] != -1) ++ i;
        if (i == n) return true;
        repeat (j,n) if (g_inv[j] == -1) {
            vector<int> h = g;
            vector<int> h_inv = g_inv;
            if (def(i, j)) {
                if (go(i+1)) return true;
            }
            g = h;
            g_inv = h_inv;
        }
        return false;
    };
    cout << (go(0) ? "Yes" : "No") << endl;
    return 0;
}
```
