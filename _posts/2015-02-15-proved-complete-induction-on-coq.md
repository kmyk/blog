---
category: blog
layout: post
date: 2015-02-15T15:07:51+09:00
tags: [ "coq", "math", "induction", "proof" ]
math: true
---

# coqで完全帰納法書いた

完全帰納法, complete induction, strong inductionとか呼ばれるやつをcoqで証明した

$$ (\forall n. (\forall k. k \lt n \to P(k)) \to P(n)) \to \forall n. P(n) $$

``` coq
Theorem nat_compind
  (P : nat -> Prop)
  (H : forall n : nat, (forall k : nat, k < n -> P k) -> P n)
  (n : nat)
  : P n.
```

<!-- more -->

``` coq
Require Import Arith.
Theorem nat_compind
  (P : nat -> Prop)
  (H : forall n : nat, (forall k : nat, k < n -> P k) -> P n)
  (n : nat)
  : P n.
Proof.
  generalize dependent n.
  assert (forall n : nat, forall k : nat, k <= n -> P k).
  - induction n.
    + intros k Hk.
      apply (le_n_0_eq k) in Hk.
      subst.
      apply (H 0).
      intros k Hk.
      exfalso.
      exact (lt_n_0 k Hk).
    + intros k Hk.
      apply (H k).
      intros l Hl.
      apply (IHn l).
      apply (lt_le_S l k) in Hl.
      apply le_S_n.
      exact (le_trans (S l) k (S n) Hl Hk).
  - intros n.
    apply (H0 n n).
    exact (le_refl n).
Qed.
```

別に何ら特別なものではないはずだが、けっこう苦労した。論理学の教科書に論理式の深さに関する帰納法の詳細な証明が載ってたのでそれを参考に書いた。


9行目で`assert`する、 $$ H' : \forall n. (\forall k. k \le n \to P(k)) $$ が重要。
これの $n$を固定し$S n$ で置き換えると、仮定 $$ H : \forall n. (\forall k. k \lt n \to P(k)) \to P(n) $$ の仮定 $$ \forall k. k \lt n \to P(k) $$ と一致する。
この$H'$を$n$の構造に関する帰納法で示す。
$O$のときは$H$の仮定が空、$S n$のときは帰納法の仮定が$H$の仮定になっている。
さらに$H'$ から $$ \forall n. P(n) $$ は容易に導ける。

ところで、2重帰納法は`Theorem nat_double_ind`として標準libraryにあるのに何故これはないのだろうか。

---

# coqで完全帰納法書いた

ついでにlistの長さに関する帰納法も書いた。

``` coq
Require Import Arith.
Require Import List.
Theorem list_lenind
  (A : Type)
  (P : list A -> Prop)
  (H : forall xs : list A,
    (forall ys : list A, length ys < length xs -> P ys) -> P xs)
  (xs : list A)
  : P xs.
Proof.
  generalize dependent xs.
  assert (forall n : nat, forall xs : list A, length xs <= n -> P xs).
  - induction n.
    + intros xs Hxs.
      apply (H xs).
      intros ys Hys.
      exfalso.
      apply (le_n_0_eq _) in Hxs.
      rewrite <- Hxs in Hys.
      exact (lt_n_0 _ Hys).
    + intros ys Hys.
      apply (H ys).
      intros zs Hzs.
      apply (IHn zs).
      apply (lt_le_S _ _) in Hzs.
      apply le_S_n.
      exact (le_trans _ _ _ Hzs Hys).
  - intros xs.
    apply (H0 (length xs) xs).
    exact (le_refl _).
Qed.
```

## version

``` sh
$ coqc -v
The Coq Proof Assistant, version 8.4pl5 (January 2015)
compiled on Jan 27 2015 19:49:36 with OCaml 4.02.1
```
