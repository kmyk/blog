---
category: blog
layout: post
date: 2020-03-07T00:00:00+09:00
tags: [ "competitive", "minimum-cat", "propositional-logic" ]
---

# 最小カットと命題論理

<div hidden>
$$
\newcommand{\bigdoublewedge}{
  \mathop{
    \mathchoice{\bigwedge\mkern-15mu\bigwedge}
               {\bigwedge\mkern-12.5mu\bigwedge}
               {\bigwedge\mkern-12.5mu\bigwedge}
               {\bigwedge\mkern-11mu\bigwedge}
    }
}
\newcommand{\bigdoublevee}{
  \mathop{
    \mathchoice{\bigvee\mkern-15mu\bigvee}
               {\bigvee\mkern-12.5mu\bigvee}
               {\bigvee\mkern-12.5mu\bigvee}
               {\bigvee\mkern-11mu\bigvee}
    }
}
$$
</div>

## はじめに

最小カットはふたつの頂点 $s, t$ の間の
以下では $\top$ および $\bot$ と書く。

## source や sink との辺: $A$ と $\lnot A$

![](/blog/2020/03/07/minimum-cut-and-propositional-logic/top-a-bot.svg)
![](/blog/2020/03/07/minimum-cut-and-propositional-logic/just-a.svg)

## ふたつの頂点の間の辺: $A \to B$ と $A \leftrightarrow B$

![](/blog/2020/03/07/minimum-cut-and-propositional-logic/a-implies-b.svg)
![](/blog/2020/03/07/minimum-cut-and-propositional-logic/a-iff-b.svg)

## 仮想的な頂点: $A \wedge B$ と $A \vee B$

![](/blog/2020/03/07/minimum-cut-and-propositional-logic/diamond.svg)
![](/blog/2020/03/07/minimum-cut-and-propositional-logic/a-and-not-b.svg)
![](/blog/2020/03/07/minimum-cut-and-propositional-logic/not-a-and-not-b.svg)
![](/blog/2020/03/07/minimum-cut-and-propositional-logic/not-a-and-b.svg)
![](/blog/2020/03/07/minimum-cut-and-propositional-logic/a-and-b.svg)

## 仮想的な頂点 (一般化): $\bigdoublevee_i A_i$ と $\bigdoublewedge_j B_j$

![](/blog/2020/03/07/minimum-cut-and-propositional-logic/not-sum.svg)
![](/blog/2020/03/07/minimum-cut-and-propositional-logic/product.svg)
![](/blog/2020/03/07/minimum-cut-and-propositional-logic/sum-implies-product.svg)

ただし $c = p(\bigdoublevee_i A_i \to \bigdoublewedge_j B_j)$

## まとめ

原子命題 $A, B$ に対し、次が書ける:

-   $A$
-   $\lnot A$
-   $A \to B$
-   $A \wedge B$
-   $\lnot (A \vee B)$

原子命題 $A_1, A_2, \dots, A_n, B_1, B_2, \dots, B_m$ に対し、次が書ける:

-   $\bigdoublevee_i A_i$
-   $\lnot \bigdoublewedge_j B_j$
-   $\bigdoublevee_i A_i \to \bigdoublewedge_j B_j$
