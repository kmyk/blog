---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/316/
  - /blog/2016/11/25/yuki-316/
date: "2016-11-25T15:45:09+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "https://yukicoder.me/problems/no/316" ]
---

# Yukicoder No.316 もっと刺激的なFizzBuzzをください

全列挙を無理矢理最適化して$O(N)$で通すやつをしたかったが、だめだったので$O(\frac{\mathrm{lcm}(a,b,c)}{\min(a,b,c)})$になってしまった。
`i%a == 0 and i%b == 0 and i%c == 0`で打ち切れば`lcm`が消せるが、気付くのが遅かったためこのまま。

``` c++
#include <iostream>
typedef long long ll;
using namespace std;
template <typename T> T gcd(T a, T b) { while (a) { b %= a; swap(a, b); } return b; }
template <typename T> T lcm(T a, T b) { return (a * b) / gcd(a,b); }
int main() {
    int n, a, b, c; cin >> n >> a >> b >> c;
    ll l = lcm<ll>(a, lcm<ll>(b, c));
    int ans = 0;
    int x = -1; if (n/l) for (int i = 0; i < l+1;   i += min(a-i%a, min(b-i%b, c-i%c))) ++ x;
    int y = -1;          for (int i = 0; i < n%l+1; i += min(a-i%a, min(b-i%b, c-i%c))) ++ y;
    cout << (n/l)*x + y << endl;
    return 0;
}
```
