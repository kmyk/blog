---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/409/
  - /blog/2016/10/20/yuki-409/
date: "2016-10-20T02:01:51+09:00"
tags: [ "competitive", "writeup", "yukicoder", "dp" ]
"target_url": [ "http://yukicoder.me/problems/no/409" ]
---

# Yukicoder No.409 ダイエット

解説を見た。
$O(N \sqrt{N})$な方向は考えて実装までしたが、打ち切りの判定が下手だったのでTLEを食らっていた。

他の人らの解説には$l \le 1000$でいいよとあるが、証明が理解できないので自分で証明しようとしてみたところ、$l \le 1000$は(落ちないけど)疑わしいという結論になった。
また、writer解はconvex hull trickであった。

## solution

DP。二次関数は急なので途中で打ち切れて$O(N \sqrt{\frac{\max D_i + A}{B}})$。ただし$B = 0$なら$O(1)$。

最後に食べた日付からのDP: $\mathrm{dp} : N \to \mathbb{Z}$をする。
日付とストレス値からの愚直DP: $\mathrm{dp'} : N \times N \to \mathbb{Z}$は冗長なだけであり、実際$\mathrm{dp'}\_{t,s} = \mathrm{dp}\_{t-s} - A(s+1) + B\frac{(s+1)(s+2)}{2}$と導出できる。
これはDPの経路が一意に定まるのが主な原因である。

漸化式は次である。
$$
\begin{array}{lll}
\mathrm{dp}\_0 & = & w \\\\
\mathrm{dp}\_{i+1} & = & \min \left\\{ \mathrm{dp}\_j - A(i-j) + B\frac{(i-j)(i-j+1)}{2} + D_j \;\middle|\; j \lt i+1 \right\\}
\end{array}
$$
この更新には、$l = \min \\{ l \mid \mathrm{dp}\_{i-l} - Al + B\frac{l(l+1)}{2} \\}$を探せばよい。
ここで$l \lt 2\sqrt{\frac{\max D_i + A}{B}}$が言えるので間に合う。

証明。
時刻$t_1 \lt t_2 \lt t_3$をとる。
$t_1, t_3$でドーナツを食べかつその間$t_1 \lt t \lt t_3$では一度も食べていないと仮定する。
このとき$t_1 \le t \le t_3$間で得る体重は$D\_{t_1} + f(t_3 - t_1 - 1) + D\_{t_3}$である。
ただし$f(l) = - Al + B \frac{l(l+1)}{2}$とする。
$t_2$でもしドーナツを食べていたとすると、これは$D\_{t_1} + f(t_2 - t_1 - 1) + D\_{t_2} + f(t_3 - t_2 - 1) + D\_{t_3}$となる。
この差分に関して、$f(t_2 - t_1 - 1) + D\_{t_2} + f(t_3 - t_2 - 1) \le f(t_3 - t_1 - 1)$であれば$t_2$でドーナツを食べた方がよい。
この不等式は以下のように変形できる。
$$ \begin{array}{lll}
D\_{t_2} & \le & f(t_3 - t_1 - 1) - f(t_2 - t_1 - 1) - f(t_3 - t_2 - 1) \\\\
         &  =  & - A \left( (t_3 - t_1 - 1) - (t_2 - t_1 - 1) - (t_3 - t_2 - 1) \right) + \frac{B}{2} \left( (t_3 - t_1 - 1)(t_3 - t_1) - (t_2 - t_1 - 1)(t_2 - t_1) - (t_3 - t_2 - 1)(t_3 - t_2) \right) \\\\
         &  =  & - A + B(t_3 - t_2)(t_2 - t_1)
\end{array} $$
右辺が最大になるのは$\frac{l}{2} = \frac{t_3 - t_1}{2} = t_3 - t_2 = t_2 - t_1$のときである。$t_2$をそのように仮定し、$\sqrt{\frac{D\_{t_2} + A}{B}} \le \frac{l}{2}$であれば$t_2$でドーナツを食べるべきである。
よって、最適に選ぶ場合$l \lt 2\sqrt{\frac{\max D_t + A}{B}}$とできる。


## implementation

``` c++
#include <iostream>
#include <algorithm>
#include <vector>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
const ll inf = ll(1e18)+9;
int main() {
    // input
    int n, a, b, w; cin >> n >> a >> b >> w;
    vector<int> d(n); repeat (i,n) cin >> d[i];
    if (b == 0) {
        // output
        cout << w - a*(ll)n << endl;
    } else {
        // dp
        n += 1;
        d.push_back(0);
        int limit = 2 * sqrt((*whole(max_element, d) + a) / b) + 3;
        vector<ll> dp(n+1);
        dp[0] = w;
        repeat (i,n) {
            ll acc = inf;
            repeat_reverse (j,i+1) {
                setmin(acc, dp[j] - a *(ll) ll(i-j) + b *(ll) (i-j)*(i-j+1)/2);
                if (i-j > limit) break;
            }
            dp[i+1] = acc + d[i];
        }
        // output
        cout << dp[n] << endl;
    }
    return 0;
}
```
