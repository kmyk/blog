---
category: blog
layout: post
redirect_from:
    - "/blog/2019/04/26/max-flow-and-logic/"
date: "2019-04-27T00:00:00+09:00"
tags: [ "competitive", "max-flow" ]
---

# 最大流に帰着可能な問題に関しての、論理の言葉による整理

<small>
前提知識: 最大流問題とその双対定理、命題論理に関する基本的事項
</small>

## 最大流で解ける問題の論理の言葉での形式化

次のように形式化できる問題は最大流として解ける:

<i>
有限多重集合 $$T \subseteq _ \mathrm{fin} \{ (a \to b, c) \mid a, b \in \mathrm{PropVar} \cup \{ \top, \bot \}, c \in \mathbb{Z} \cup \{ \infty \} \}$$ が与えられる。
$$\{ \phi \mid \exists c. (\phi, c) \in T' \}$$ が無矛盾な $$T' \subseteq T$$ であって $$\sum \{ c \mid \exists \phi. (\phi, c) \in T' \}$$ を最小にするような $$T'$$ をひとつ求めよ。
</i>
    
信念 $$a_i \to b_i$$ がその強さ $$c_i$$ と共に与えられ、これが無矛盾になるように信念を捨てるときの負担を最小化する、と読める。

## 基本的な整理

基本的なものとして足せる信念は以下の形のみ:

-   $$a, b \in \mathrm{ProbVar}$$ として $$a \to b$$

さらに $$b = \bot$$ や $$a = \top$$ とすれば次が使える:

-   $$a \in \mathrm{ProbVar}$$ として $$\lnot a$$
-   $$b \in \mathrm{ProbVar}$$ として $$b$$

答えから定数 $$c \in \mathbb{Z}$$ を引くのは $$(\top \to \bot, c)$$ という組を加えれば可能。
$$c \le 0$$ であればその信念は常に除去してよいので、 $$c \gt 0$$ であると仮定してよい。

## 論理結合子を用いた含意 $$\to$$ の拡張

加えて、次の形の信念を足せる:

-   有限集合 $$A, B \subseteq \mathrm{PropVar}$$ に対し $$\bigvee A \to \bigwedge B$$

その系として次の形の信念を足せる:

-   $$a, a' \in \mathrm{PropVar}$$ に対し $$\lnot (a \lor a')$$
-   $$b, b' \in \mathrm{PropVar}$$ に対し $$b \land b'$$
-   $$a, a', b \in \mathrm{PropVar}$$ に対し $$a \lor a' \to b$$
-   $$a, b, b' \in \mathrm{PropVar}$$ に対し $$a \to b \land b'$$

これは次のような新しい命題変数 $$\dot{A}, \dot{B} \in \mathrm{PropVar}$$ を足すことで実現できる:

-   すべての $$a \in A$$ に対し信念 $$a \to \dot{A}$$ が強さ $$\infty$$ で存在する
-   すべての $$b \in B$$ に対し信念 $$\dot{B} \to b$$ が強さ $$\infty$$ で存在する

$$\bigvee A \to \bigwedge B$$ の形は $$a \to b$$ の形の自然な拡張になっている。
特にこの形は負の literal の有限集合 $$A \subseteq \{ \lnot a \mid a \in \mathrm{PropVar} \}$$ と正の literal の有限集合 $$B \subseteq \mathrm{PropVar}$$ を用いて $$\bigwedge A \lor \bigwedge B$$ と書かれることにも注意したい。

## 命題変数に関する双対性

次が成り立つ:

<i>
最大流で解ける制約に対し、出現するすべての命題変数 $$p$$ を同時にその否定 $$\lnot p$$ で置き換えても、なお最大流で解ける制約になる。その答えも一致する。
</i>

証明は明らか。
変数の一部の否定を取ることは一般には許されない。

## 何が嬉しいのか

以下の $$2$$ 点が嬉しい:

1.  $$\bigvee A \to \bigwedge B$$ の形の辺が使えること
2.  命題変数に関する双対性があること

前者は複雑な条件が利用可能であることを保証すると共に、考慮するべき頂点の数を減らしてくれる。
後者は頂点に割り当てる意味の選択を容易にする。特に、$$1$$ 種類の意味のみがある場合はその表裏を気にしなくてよいことを保証してくれる。

## 例題

例として問題 [Topcoder SRM594 Div1 Medium: FoxAndGo3](https://community.topcoder.com/stat?c=problem_statement&pm=12808&rd=15706) を考えよう。
これは診断人さんによるスライド [最小カットを使って「燃やす埋める問題」を解く](https://www.slideshare.net/shindannin/project-selection-problem) の例題でもあるのでそちらとも比較しながら見るとよい。

問題の前半部分を飛ばして、いま議論したい部分を抜き出すと次のようになる:

>   $$H \times W$$ のマス目に石をいくつか置く。石をひとつ置くと $$1$$ 減点される。
    マスの集合 $$B_j$$ ($$j = 1, 2, \dots, m$$) が与えられる。それぞれの $$j$$ について、$$B_j$$ に含まれるマスすべてに石を置くと $$p_j \ge 1$$ 加点される。
    点数の最大値を求めよ。

整理すると次のようになる:

-  「マス $$i$$ に石を置く」を $$b_i \in \mathrm{PropVar}$$ で表すとする
-  それぞれの $$i$$ について、 $$b_i$$ なら $$1$$ 点減点
-  それぞれの $$j$$ について、 $$\bigwedge _ {i \in B_j} b_i$$ なら $$p_j$$ 点加点

使うべき信念はこの場合自然に次のようになる:

-   $$\lnot b_i = b_i \to \bot$$ 「置かない」を強さ $$1$$ で
-   $$\bigwedge _ {j \in B_j} b_j = \top \to \bigwedge _ {j \in B_j} b_j$$ 「集合 $$B_j$$ のうちすべてに置く」を強さ $$p_j$$ で (ただし結果に $$p_j$$ 加算する)

これは最大流に乗る形であるので、解けた。

### 双対性

もし $$b_i$$ でなく「マス $$i$$ に石を置かない」ことを表す命題変数 $$a_i \in \mathrm{PropVar}$$ を使って整理した場合は解けるだろうか？
これが解けることは双対性から明らか。
実際、

-   $$a_i = \top \to a_i$$ 「置かない」を強さ $$1$$ で
-   $$\bigvee _ {i \in B_j} a_i \to \bot$$ 「集合 $$B_j$$ のうちすべてに置く」 (集合 $$B_j$$ のうちどれかに置かないということはない) を強さ $$p_j$$ で (ただし結果に $$p_j$$ 加算する)

となり、同様に最大流で解ける。

### $$\bigvee A \to \bigwedge B$$ の辺

比較として、 $$\bigvee A \to \bigwedge B$$ の形の辺を陽には張らない場合を考えよう。
この場合、「石を置く」に関する頂点に加えて、「組合せを達成する」に関する頂点が必要になる。
これはもともと暗な頂点 $$\bigwedge _ {j \in B_j} b_j$$ として隠れていたものである。
$$2$$ 種類の意味の頂点群を考慮しないといけないために、頂点に割り当てる意味として (双対性を利用したとしても) 「石を置く / 組合せを達成する」「石を置く / 組合せを達成しない」の $$2$$ 通りの両方を試す必要が発生してしまう。
