---
category: blog
layout: post
date: "2017-01-17T04:06:26+09:00"
title: "Segment木の種類とその要件"
tags: [ "competitive", "segment-tree", "lazy-propagation" ]
---

## 単純なsegment木

ここで言う「単純な」とは、台集合上の列を$1$本のみ持てば実現できるもの。
分類すると以下になる。

-   点代入/区間総和
-   区間演算/点取得

特によく使われるのが上である。修飾なしでsegment木と言えばたいていこれ。
range minimum queryやrange maximum queryが例。
台集合はmonoidであればよい。
長さ$1$の区間を考えれば点取得も可能。
逆元が取れるならbinary indexed treeで代用でき、さらに更新が不要なら累積和で済む。

下は他のsegment木の構成要素としては出現するが、単体ではあまり見ない。
区間への一様加算などができる。
これも台はmonoidであればよい。
可換性を仮定すれば実装が楽になるが仮定しない場合は特有の操作が必要になり、この操作を指して特に遅延伝播[^1]と呼ばれる (詳細は下)。
点代入は逆元が取れるときのみ可能。

## 遅延伝播segment木

$2$種の単純なsegment木を並べて用いれば$2$種の区間操作を実現できる。
つまり

-   区間演算/区間総和

ができる。

台は総和の対象のmonoid $M$と演算を表現するmonoid $Q$のふたつとなる。
さらに$M$の要素$a \in M$と$Q$の要素$q \in Q$の間に適用演算$q(a) \in M$が定義されていて、

-   単位元 $e$ の存在 $e(a) = a$
-   分配律 $q(a \cdot b) = q(a) \cdot q(b)$
-   $2$演算間の結合律 $(q_2 \cdot q_1)(a) = q_2(q_1(a))$

あたりを満たすのが条件。
つまり$M$を半群やmagmaとして見ての自己準同型であればよい。ただし$Q$の積はきちんと関数合成になっているとする。

区間演算側が加算で区間総和側が$\max$のstarry sky treeが典型例。
$q(a) = q + a$と$a \cdot b = \max \\{ a, b \\}$なので例えば$q(a \cdot b) = q + \max \\{ a, b \\} = \max \\{ q + a, q + b \\} = q(a) \cdot q(b)$であるなど、要件を満たしていることが分かる。

また、演算の引数に区間の長さを加えることができる。木の実装を操作してもよいが、$M$を拡張して$M \times \mathbb{N}$とし台に長さを乗せてしまうことでも実現できる。

その実装方法について。
木の頂点に対応する区間$i$はそれぞれ$a_i \in M,\; q_i \in Q$を持つとする。
小区間$i_L = [l,m),\; i_R = [m,r)$からなる区間$i = [l,r)$についての操作を考える。
区間に一様か否かで場合分けして、以下のようになる。

-   区間全体の総和取得は、$a_i$を返せばよい
-   区間全体への演算$q\_\star$は、$a_i \gets q\_\star(a_i),\; q_i \gets q\_\star \cdot q_i$とする
-   区間の一部の総和取得は、左右の小区間$i_L, i_R$へ流して結果$a, b$を受け取り、$q_i(a + b)$が結果
-   区間の一部への演算$q\_\star$は、まず既にある演算$q_i$を左右の小区間$i_L, i_R$へ分割して適用し$q_i$を初期化$q_i \gets 1$、その後に$q\_\star$を適切に左右の小区間$i_L, i_R$に適用し、最後に$a_i$を更新 (遅延伝播)
    -   演算の可換性を仮定すれば、既にある演算を分割して適用する操作が不要
    -   $q \cdot 1 = 1 \cdot q$の可換性を作りだして利用している。これをせずに$q\_\star$を下に流すと、$q_i$と$q\_\star$の適用順序が逆転してしまう

## 付録: 参考実装

### 点代入/区間総和

``` c++
template <typename T>
struct segment_tree { // on monoid
    int n;
    vector<T> a;
    function<T (T,T)> append; // associative
    T unit; // unit
    segment_tree() = default;
    segment_tree(int a_n, T a_unit, function<T (T,T)> a_append) {
        n = pow(2,ceil(log2(a_n)));
        a.resize(2*n-1, a_unit);
        unit = a_unit;
        append = a_append;
    }
    void point_update(int i, T z) {
        a[i+n-1] = z;
        for (i = (i+n)/2; i > 0; i /= 2) {
            a[i-1] = append(a[2*i-1], a[2*i]);
        }
    }
    T range_concat(int l, int r) {
        return range_concat(0, 0, n, l, r);
    }
    T range_concat(int i, int il, int ir, int l, int r) {
        if (l <= il and ir <= r) {
            return a[i];
        } else if (ir <= l or r <= il) {
            return unit;
        } else {
            return append(
                    range_concat(2*i+1, il, (il+ir)/2, l, r),
                    range_concat(2*i+2, (il+ir)/2, ir, l, r));
        }
    }
};
```

### 区間演算/区間総和

``` c++
template <typename M, typename Q>
struct lazy_propagation_segment_tree { // on monoids
    int n;
    vector<M> a;
    vector<Q> q;
    function<M (M,M)> append_m; // associative
    function<Q (Q,Q)> append_q; // associative, not necessarily commutative
    function<M (Q,M)> apply; // distributive, associative
    M unit_m; // unit
    Q unit_q; // unit
    lazy_propagation_segment_tree() = default;
    lazy_propagation_segment_tree(int a_n, M a_unit_m, Q a_unit_q, function<M (M,M)> a_append_m, function<Q (Q,Q)> a_append_q, function<M (Q,M)> a_apply) {
        n = pow(2,ceil(log2(a_n)));
        a.resize(2*n-1,     a_unit_m);
        // q.resize(2*(n-1)-1, a_unit_q);
        q.resize(2*n-1, a_unit_q);
        unit_m = a_unit_m;
        unit_q = a_unit_q;
        append_m = a_append_m;
        append_q = a_append_q;
        apply = a_apply;
    }
    void range_apply(int l, int r, Q z) {
        range_apply(0, 0, n, l, r, z);
    }
    void range_apply(int i, int il, int ir, int l, int r, Q z) {
        if (l <= il and ir <= r) {
            a[i] = apply(z, a[i]);
            // if (i < q.size()) q[i] = append_q(z, q[i]);
            q[i] = append_q(z, q[i]);
        } else if (ir <= l or r <= il) {
            // nop
        } else {
            range_apply(2*i+1, il, (il+ir)/2, 0, n, q[i]);
            range_apply(2*i+1, il, (il+ir)/2, l, r, z);
            range_apply(2*i+2, (il+ir)/2, ir, 0, n, q[i]);
            range_apply(2*i+2, (il+ir)/2, ir, l, r, z);
            a[i] = append_m(a[2*i+1], a[2*i+2]);
            q[i] = unit_q;
        }
    }
    M range_concat(int l, int r) {
        return range_concat(0, 0, n, l, r);
    }
    M range_concat(int i, int il, int ir, int l, int r) {
        if (l <= il and ir <= r) {
            return a[i];
        } else if (ir <= l or r <= il) {
            return unit_m;
        } else {
            return apply(q[i], append_m(
                    range_concat(2*i+1, il, (il+ir)/2, l, r),
                    range_concat(2*i+2, (il+ir)/2, ir, l, r)));
        }
    }
};
```

[^1]: 遅延伝播と遅延伝搬で表記揺れがある。共にlazy propagationの訳語で、どちらが間違いという訳ではない。遅延評価という記述もあるが、こちらは複数の点でよくないので使わないほうがよいだろう。

---

-   2017年  5月 25日 木曜日 04:14:15 JST
    -   自己準同型
