---
layout: post
redirect_from:
  - /writeup/ctf/2017/twctf-2017-palindromes-pairs-challenge-phase/
  - /blog/2017/09/12/twctf-2017-palindromes-pairs-challenge-phase/
date: "2017-09-12T18:33:52+09:00"
tags: [ "ctf", "writeup", "ppc", "rolling-hash" ]
---

# Tokyo Westerns CTF 3rd 2017: Palindromes Pairs - Challenge Phase -

## note

次を参考にして解いた:

-   writeup: <https://gist.github.com/hellman/49510790103d96a8d5259e578ffc2579>
-   Yukicoder No.3014 多項式ハッシュに関する教育的な問題: <https://yukicoder.me/problems/no/3014/editorial>

問題鯖のfrontendはまだ生きているが、backendがもう落ちてるようでflagは見られなかった。

## problem

競プロの問題がある: $n$個の文字列$s\_1, \dots, s\_n$が与えられるので、結合$s\_i s\_j$が回文になるような組$(i, j)$の数を答えよ。

これに対して提出された次のコードをHackせよ。

``` c++
#include <iostream>
using namespace std;
#define REP(i,x) for(int i = 0; i < (int)x; i++)
#define M 8
int N;
string s[1000];
long q[M], p[M], hs[M][1000], hr[M][1000];

long mp(long a, long b, long c){
  long r=1;
  for(;b;b>>=1){
    if(b&1)r=r*a%c;
    a=a*a%c;
  }
  return r;
}

int main() {
  std::ios_base::sync_with_stdio(false);
  REP(i, M) {
    q[i]=rand();
    p[i]=rand();
  }
  cin>>N;
  REP(i,N) cin>>s[i];
  REP(i,N){
    REP(j,M){
      REP(k,s[i].size())hs[j][i]=(hs[j][i]*q[j]+s[i][k])%p[j];
      REP(k,s[i].size())hr[j][i]=(hr[j][i]*q[j]+s[i][s[i].size()-k-1])%p[j];
    }
  }
  long ans=0;
  REP(i,N){
    REP(j,N){
      bool o=true;
      REP(k,M){
        if(
          (hs[k][i]*mp(q[k],s[j].size(),p[k])+hs[k][j]
          -hr[k][j]*mp(q[k],s[i].size(),p[k])-hr[k][i])%p[k]){
          o=false;break;
        }
      }
      if(o)ans++;
    }
  }
  cout<<ans<<endl;
}
```

つまり複数のrolling hashを用いたそれを衝突させろという問題。

## solution

用いるパラメタは乱数に見える。
しかし`rand()`を用いていて`srand()`していないのでこれは固定。
これにより撃墜可能。

hashが衝突するような文字列を求める。
この実装で用いられているhash関数$H : \mathrm{String} \to \mathbb{N}^M$に対して$H(s) = H(\mathrm{reverse}(s))$な文字列$s$を見つけ、これを適当に切って$s\_1, s\_2$として提出すればよい。
$H$は具体的には$H(s) = (h\_{q\_0, p\_0}(s), h\_{q\_1, p\_1}(s), \dots, h\_{q\_{M-1}, p\_{M-1}}(s))$で$h\_{q, p}(s) = \sum\_{i \lt \|s\|} \mathrm{ord}(s\_i) q^{\|s\|-1-i} \bmod p$。

$M = 1$の場合の解説は見つかる: <https://yukicoder.me/problems/no/3014/editorial>。
$2$個の文字列でなくその差分を求めることに帰着し、差分の大きさに関する制約を緩和してその解のみを含む格子を作り、その格子上の原点に近い点を求めることで解く。
適当に長さ$L$を決めて格子を作り、その格子上の点で原点に近い多項式$f(x) = a\_0 x^{n-1} + a\_1 x^{n-2} + a\_{n-1}$(の係数からなるvector)を縮小された基底の中のvectorとしてLLL algorithmで求め、そこから文字列を復元する。
格子は
$$ \mathbb{B} = \left( \begin{matrix}
    - q & 1 & 0 & 0 & \dots & 0 & 0 \\\\
    0 & - q & 1 & 0 & \dots & 0 & 0 \\\\
    0 & 0 & - q & 1 & \dots & 0 & 0 \\\\
    \vdots & \vdots & \vdots & \vdots & \ddots & \vdots & \vdots \\\\
    0 & 0 & 0 & 0 & \dots & - q & 1 \\\\
    p & 0 & 0 & 0 & \dots & 0 & 0 \\\\
\end{matrix} \right) $$
の形。ただし行vectorのそれぞれが基底の要素。

$M = 8$の場合ではそのままは使えない。
なので修正をするのだが、行vectorの各要素が各文字に対応するようにしたい。
そこでまず$M = 1$の場合のまま行基本変形して
$$ \mathbb{B} \sim \mathbb{B}' = \left( \begin{matrix}
    - q & 1 & 0 & 0 & \dots & 0 & 0 \\\\
    - q^2 & 0 & 1 & 0 & \dots & 0 & 0 \\\\
    - q^3 & 0 & 0 & 1 & \dots & 0 & 0 \\\\
    \vdots & \vdots & \vdots & \vdots & \ddots & \vdots & \vdots \\\\
    - q^L & 0 & 0 & 0 & \dots & 0 & 1 \\\\
    p & 0 & 0 & 0 & \dots & 0 & 0 \\\\
\end{matrix} \right) $$
と見る。
ここから上手く$M = 8$に拡張する。
参考にしている問題であれば
$$ \mathbb{B}\_8
= \left( \begin{matrix}
    A & B \\\\
    C & D \\\\
\end{matrix} \right) = \left( \begin{matrix}
    A & I \\\\
    C & O \\\\
\end{matrix} \right) = \left( \begin{matrix}
    - q\_0   & - q\_1   & - q\_2   & \dots & - q\_{M-1}   & 1 & 0 & 0 & \dots & 0 \\\\
    - q\_0^2 & - q\_1^2 & - q\_2^2 & \dots & - q\_{M-1}^2 & 0 & 1 & 0 & \dots & 0 \\\\
    - q\_0^3 & - q\_1^3 & - q\_2^3 & \dots & - q\_{M-1}^3 & 0 & 0 & 1 & \dots & 0 \\\\
    \vdots & \vdots & \vdots & \ddots & \vdots & \vdots & \vdots & \vdots & \ddots & \vdots \\\\
    - q\_0^L & - q\_1^L & - q\_2^L & \dots & - q\_{M-1}^L & 0 & 0 & 0 & \dots & 1 \\\\
    p\_0 & 0 & 0 & \dots & 0 & 0 & 0 & 0 & \dots & 0 \\\\
    0 & p\_1 & 0 & \dots & 0 & 0 & 0 & 0 & \dots & 0 \\\\
    0 & 0 & p\_2 & \dots & 0 & 0 & 0 & 0 & \dots & 0 \\\\
    \vdots & \vdots & \vdots & \ddots & \vdots & \vdots & \vdots & \vdots & \ddots & \vdots \\\\
    0 & 0 & 0 & \dots & p\_{M-1} & 0 & 0 & 0 & \dots & 0 \\\\
\end{matrix} \right) $$
となるようなものが正解。
この格子上の点のvectorと文字列との対応を考える。
右から$L$個の要素はそれぞれ文字の差分に対応するが、左から$M$個はそうではない。
正確には左から$M$個はあるひとつの文字の差分と対応しているのだが、全て一致しなければならず、それは$M = 1$のときと違って自明ではない。
そこでこれらをすべて$0$にしてしまうことで解決する。
基底$b$の左から$M$列を適当な係数$k$倍して
$$ \mathbb{B}\_8'
= \left( \begin{matrix}
    kA & B \\\\
    kC & D \\\\
\end{matrix} \right) $$
とする。
このように張られた格子上の点はその左から$M$個の要素は常に$k$の倍数である。
$k$を十分大きくすればLLL algorithmは短かいvectorsを求めるためその位置を$k$や$-2k$ではなく$0$にしようとする。
これにより左$M$個が一致して$0$であるようなものを見つけられる。

最後に元の問題に合わせる。
格子は$- q\_i^j$を$q\_i^{L-1-j} - q\_i^j$と置き換えればよい。
文字列は$s\_1, s\_2$のふたつでなくひとつの文字列$s$なので、$s$の左半分を$s\_1$ 右半分を反転させたものを$s\_2$と見る。
これですべて解けた。

## implementation

``` python
#!/usr/bin/env sagemath
def solve(M, ps, qs, L=100):
    assert L % 2 == 0
    l = L // 2
    MULTIPLIER = 100

    # make the lattice
    a = matrix(ZZ, l, M)
    for y in range(l):
        for x, (q, p) in enumerate(zip(qs, ps)):
            a[y, x] = (pow(q, L - 1 - y, p) - pow(q, y, p)) % p
    b = identity_matrix(l)
    c = diagonal_matrix(ps)
    d = zero_matrix(M, l)
    B = matrix(ZZ, l + M, M + l)
    B.set_block(0, 0, a * MULTIPLIER)
    B.set_block(0, M, b)
    B.set_block(l, 0, c * MULTIPLIER)
    B.set_block(l, M, d)

    # use LLL algorithm to find a small vector on the lattice
    for f in B.LLL():
        if set(f[: 8]) == { 0 } and max(abs(a_i) for a_i in f[8 :]) < 26:

            # construct the palindrome
            sl = ''
            sr = ''
            for a_i in f[8 :]:
                if a_i >= 0:
                    sl += chr(ord('a') + a_i)
                    sr += 'a'
                else:
                    sl += 'a'
                    sr += chr(ord('a') - a_i)
            yield sl + ''.join(reversed(sr))

# params
M = 8
q = [ None ] * M
p = [ None ] * M
q[0] = 1804289383
p[0] = 846930886
q[1] = 1681692777
p[1] = 1714636915
q[2] = 1957747793
p[2] = 424238335
q[3] = 719885386
p[3] = 1649760492
q[4] = 596516649
p[4] = 1189641421
q[5] = 1025202362
p[5] = 1350490027
q[6] = 783368690
p[6] = 1102520059
q[7] = 2044897763
p[7] = 1967513926

# generate
s = next(solve(M, p, q))
print 2
print s[: 3], s[3 :]

# check
def h(P, B, s):
    acc = 0
    for c in s:
        acc = (acc * B + ord(c)) % P
    return acc
assert s != ''.join(reversed(s))
for q_i, p_i in zip(q, p):
    assert h(p_i, q_i, s) == h(p_i, q_i, ''.join(reversed(s)))
```

### q, p

``` c++
#include <iostream>
using namespace std;
#define REP(i,x) for(int i = 0; i < (int)x; i++)
#define M 8

int main() {
  std::ios_base::sync_with_stdio(false);
  REP(i, M) {
    cout << "q[" << i << "] = " << rand() << endl;
    cout << "p[" << i << "] = " << rand() << endl;
  }
}
```

<hr>

-   2017年  9月 13日 水曜日 16:52:17 JST
    -   記号等を修正
