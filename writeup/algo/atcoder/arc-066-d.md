---
layout: post
alias: "/blog/2018/04/05/arc-066-d/"
date: "2018-04-05T01:36:03+09:00"
tags: [ "competitive", "writeup", "arc", "dp", "digits-dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc066/tasks/arc066_b" ]
---

# AtCoder Regular Contest 066: D - Xor Sum

## solution

$a, b$を上から決めていく桁DP。$O(\log N)$。

-   次のような場合の数を$\mathrm{dp}(k, u\_{eq}, v\_{eq}, c)$とする。
    -   $63$桁目から逆順に$k$桁目まで決めて、
    -   それまでの部分だけ見たとき$u \equiv n$かどうかを$u\_{eq} \in \\{ f, t \\}$、
    -   それまでの部分だけ見たとき$v \equiv n$かどうかを$v\_{eq} \in \\{ f, t \\}$、
    -   $v$に関して下から繰り上がりがあった(と仮定した)かどうかを$c \in \\{ 0, 1 \\}$、
-   遷移は次の最大$12$通りの中で適切なものを足し込む。
    -   $a, b$の$k$桁目がどうなっているかの$3$通り ($a = 1 \land b = 0$ と $a = 0 \land b = 1$ は同じ対 $(u, v)$ を生むのでどちらかだけなため) と、
    -   ひとつ上の部分までだけ見たとき$u \equiv n$かどうかを$u\_{eq}' \in \\{ f, t \\}$、
    -   ひとつ上の部分までだけ見たとき$v \equiv n$かどうかを$v\_{eq}' \in \\{ f, t \\}$、
    -   ひとつ上の部分で繰り上がりが仮定されているかどうか$c' \in \\{ 0, 1 \\}$は他から自動的に定まる

## note

-   解説をちらっと覗いた。「$a, b$を上から決めていきます」と言われればはい
    -   初手で$b$を消去して $(u \oplus a) + a = v$ みたいな式をにらみ続けてた
    -   [pekempeyさん](https://pekempey.hatenablog.com/entry/2016/12/20/163837)が書いてる「a + b = u, a ⊕ b = v となる (a, b) が複数あるのが厄介なので、(a and b) = a, (a or b) = b という制約を付けておく。こうすることで (a, b) と (u, v) が一対一に対応するようになる。」みたいな話が効いているが、この一対一対応を作る方向を探さなかったのが敗因
-   典型桁DPって感じがする (このところなんでも典型に見えてきて困っている)

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using ll = long long;
using namespace std;

template <int32_t MOD>
struct mint {
    int32_t data;
    mint() = default;  // data is not initialized
    mint(int32_t value) : data(value) {}  // assume value is in proper range
    inline mint<MOD> operator + (mint<MOD> other) const { int32_t c = this->data + other.data; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->data += other.data; if (this->data >= MOD) this->data -= MOD; return *this; }
};

constexpr int MOD = 1e9 + 7;
mint<MOD> solve(ll n) {
    mint<MOD> dp[64][2][2][2] = {};
    dp[63][1][1][0] = 1;
    REP_R (k, 63) {
        REP (u_eq, 2) REP (v_eq, 2) REP (c_k, 2) {
            REP (a_k, 2) REP (b_k, 2) if (a_k <= b_k) {
                REP (u_eq1, 2) REP (v_eq1, 2) {
                    int n_k = bool(n & (1ll << k));
                    int u_k = a_k ^ b_k;
                    int v_k = (a_k + b_k + c_k) & 1;
                    int c_k1 = (a_k + b_k + c_k) >= 2;
                    if (u_eq  and not u_eq1) continue;
                    if (u_eq  and n_k != u_k) continue;
                    if (v_eq  and not v_eq1) continue;
                    if (v_eq  and n_k != v_k) continue;
                    if (u_eq1 and n_k == u_k and not u_eq) continue;
                    if (u_eq1 and n_k <  u_k) continue;
                    if (v_eq1 and n_k == v_k and not v_eq) continue;
                    if (v_eq1 and n_k <  v_k) continue;
                    dp[k][u_eq][v_eq][c_k] += dp[k + 1][u_eq1][v_eq1][c_k1];
                }
            }
        }
    }
    mint<MOD> answer = 0;
    REP (u_eq, 2) REP (v_eq, 2) answer += dp[0][u_eq][v_eq][0];
    return answer;
}

int main() {
    ll n; cin >> n;
    cout << solve(n).data << endl;
    return 0;
}
```
