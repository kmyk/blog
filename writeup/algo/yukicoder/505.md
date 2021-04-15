---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/505/
  - /blog/2017/04/22/yuki-505/
date: "2017-04-22T00:08:08+09:00"
tags: [ "competitive", "writeup", "yukicoder", "dp" ]
"target_url": [ "http://yukicoder.me/problems/no/505" ]
---

# Yukicoder No.505 カードの数式2

`case '/': nxt = cur + a[i+1]; break;` ってしたまま気付かず提出してWA。
`a[i+1] == 0`の場合の処理で脳内割り込みがかかったときにそのまま復帰を忘れたのだと思う。

## solution

動的計画法。最大値と最小値だけ覚えておけばよい。$O(N)$。

`std::set`とかで愚直$O(4^N)$しても通るようだ。
制約$N \le 16$より$4^N \le 4.3 \times 10^9$で要素の重複で軽くなる方が`std::set`の$O(\log N)$や`std::unordered_set`の定数倍より強かったということらしい。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <limits>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }
int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i,n) scanf("%d", &a[i]);
    ll cur_min = a[0];
    ll cur_max = a[0];
    repeat (i,n-1) {
        ll nxt_min = numeric_limits<ll>::max();
        ll nxt_max = numeric_limits<ll>::min();
        for (ll cur : { cur_min, cur_max }) {
            for (char op : "+-*/") {
                if (op == '/' and a[i+1] == 0) continue;
                ll nxt;
                switch (op) {
                    case '+': nxt = cur + a[i+1]; break;
                    case '-': nxt = cur - a[i+1]; break;
                    case '*': nxt = cur * a[i+1]; break;
                    case '/': nxt = cur / a[i+1]; break;
                }
                setmin(nxt_min, nxt);
                setmax(nxt_max, nxt);
            }
        }
        cur_min = nxt_min;
        cur_max = nxt_max;
    }
    printf("%lld\n", cur_max);
    return 0;
}
```
