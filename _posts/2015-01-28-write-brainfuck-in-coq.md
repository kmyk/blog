---
category: blog
layout: post
title: "coqでbrainfuck処理系書いた"
date: 2015-01-28T21:51:25+09:00
tags: [ "coq", "brainfuck", "esolang" ]
math: true
---

![](/blog/2015/01/28/write-brainfuck-in-coq/ss.png)

coqのいい感じの情報少ないし、頑張って書いたけどしばらく放置すると忘れてしまうので、詳しめにコメント書いて残しておきます。改善点は多分に残されているので注意しつつ読むこと。

-   [brainfuck.v](/blog/2015/01/28/write-brainfuck-in-coq/brainfuck.v)

<!-- more -->

## 解説

``` coq
Require Import Arith.
Require Import NArith.
Require Import Vector.
Require Import List.
Require Import Ascii.
Require Import String.
```

-   `Arith`
    -   `O`と`S`からなる自然数
-   `NArith`
    -   binaryで保持される自然数
-   `List`
    -   単方向連結list
    -   lisp, haskellのそれと同じ
-   `Vector`
    -   固定長
-   `Ascii`
    -   `bool`の8-tupleで表される文字
    -   `uint8_t`や$\mathbb{Z}/256\mathbb{Z}$を表す型が欲しかったけど見つけられなかった
    -   参考にした: [mzp/magpack-ocaml](https://github.com/mzp/msgpack-ocaml/blob/5518badf3d8c461b90454859a3e5e729f79a846c/proof/Object.v)
-   `String`
    -   `list ascii`と同型な文字列
-   `Require Import`の順は意味を持つらしい

``` coq
Inductive Brainfuck : Type :=
  | Incr : Brainfuck
  | Decr : Brainfuck
  | Next : Brainfuck
  | Prev : Brainfuck
  | Read : Brainfuck
  | Write : Brainfuck
  | While : list Brainfuck -> Brainfuck.
```

-   素直な定義

``` coq
Definition byte := ascii.

Function byte_succ (n : byte) := ascii_of_N (N.succ (N_of_ascii n)).
Function byte_pred (n : byte) := ascii_of_N (N.add 255 (N_of_ascii n)).
```

-   `ascii ~ (bool, bool, ..., bool)`を`byte`として使う
-   `byte_succ (byte_pred n) = n`のような定理が証明できない
    -   ただし256通りの場合分けを行なえば可能
    -   定義が悪いと思われる

``` coq
Definition Len : nat := 3000.
Inductive State : Type :=
  | Memory : Vector.t byte Len -> Fin.t Len -> string -> string -> State.
```

-   処理系の状態
    -   memory, program pointer, input, output
-   `Len`は確保する配列の長さ
    -   `30000`とすると型が巨大すぎて関数の定義が終わらないので少し小さめにしておく

``` coq
Function state_incr (s : State) : State ...
Function state_decr (s : State) : State ...
Function state_next (s : State) : option State ...
Function state_prev (s : State) : option State ...
Function state_read (s : State) : option State ...
Function state_write (s : State) : State ...
Function state_zerob (s : State) : bool ...
```

-   外部で`State`の処理を定義しておく
-   `option`はhaskellの`Maybe`

``` coq
Function state_prev (s : State) : option State :=
  state_update_pointer s (fun mem ptr =>
    match Fin.to_nat ptr with
    | exist i p =>
      match zerop i with
      | left  _ => None
      | right q => Some (Fin.of_nat_lt (lt_trans (Peano.pred i) i Len (lt_pred_n_n i q) p) : Fin.t Len)
      end
    end).
```

-   上で挙げた`state_prev`
-   `state_update_pointer`は自明な補助関数
-   `Fin.to_nat ptr : {i | i < m}`
    -   `Fin.t n`は`[1,n]`の範囲を持つ型
    -   条件を満たす値`i : nat`と条件を満たしていることの証明`p : i < Len`から構成されているので分解
-   `zerop i : { 0 = i } + { 0 < i }`
    -   証明`0 = i`あるいは証明`0 < i`のどちらかから構成されているので場合分け
-   `Fin.of_nat_lt ...`
    -   その型に合うように推移律で証明を合成

``` coq
Inductive EvalResult : Type :=
  | Success
  | Interrupted
  | LeftIndexExceeded
  | RightIndexExceeded
  | EndOfInput.
```

-   実行の結果の分類

``` coq
Fixpoint eval (n : nat) (s : State) (tss : list (list Brainfuck)) : EvalResult * nat * State * list (list Brainfuck) :=
  let failure e := (e, n, s, tss) in
  match n with
  | O => failure Interrupted
  | S n' =>
    match tss with
    | nil => failure Success
    | nil :: tss' => eval n' s tss'
    | (t :: ts) :: tss' =>
      let success s' := eval n' s' (ts :: tss') in
      let try x e :=
        match x with
        | None => failure e
        | Some s' => success s'
        end in
      match t with
      | Incr => success (state_incr s)
      | Decr => success (state_decr s)
      | Next => try (state_next s) RightIndexExceeded
      | Prev => try (state_prev s)  LeftIndexExceeded
      | Read => try (state_read s) EndOfInput
      | Write => success (state_write s)
      | While ts' => eval n' s (if state_zerob s then ts :: tss' else ts' :: tss)
      end
    end
  end.
```

-   本体
-   停止性を保証するために、step数`n : nat`を取りその数だけ実行する
    -   coqはturing完全でない
-   step数が`0`となり中断されても再び再開できるように、次に実行すべき命令を`list (list Brainfuck)`として受け渡す

``` coq
Function execute' (n : nat) (code : list Brainfuck) (input : string)
    : EvalResult * nat * State * list (list Brainfuck) ...
Function execute (n : nat) (code : list Brainfuck) (input : string) : option string ...
```

-   wrapper

``` coq
Fixpoint parse' (code : string) (top : list Brainfuck) (stack : list (list Brainfuck)) : option (list Brainfuck) :=
  match code with
  | EmptyString =>
    match stack with
    | nil => Some top
    | _ => None
    end
  | String "+" code' => parse' code' (top ++ Incr  :: nil) stack
  | String "-" code' => parse' code' (top ++ Decr  :: nil) stack
  | String ">" code' => parse' code' (top ++ Next  :: nil) stack
  | String "<" code' => parse' code' (top ++ Prev  :: nil) stack
  | String "," code' => parse' code' (top ++ Read  :: nil) stack
  | String "." code' => parse' code' (top ++ Write :: nil) stack
  | String "[" code' => parse' code' nil (top :: stack)
  | String "]" code' =>
    match stack with
    | nil => None
    | x :: xs => parse' code' (x ++ While top :: nil) xs
    end
  | String _ code' => parse' code' top stack
  end.

Fixpoint parse (code : string) : option (list Brainfuck) := parse' code nil nil.
```

-   本体と同じくらい面倒だった
-   coqにとって停止性が明らかであるように、stackに積みながら1度のみ舐める
-   rose tree様の構造である`Brainfuck`を停止性を認識させつつ逆にする関数の定義を諦めた
    -   単方向連結listの末尾に毎回追加することで解決した
    -   当然ながら可能らしい: [Recursive definitions over an inductive type with nested components - Stack Exchange](http://cs.stackexchange.com/questions/104/recursive-definitions-over-an-inductive-type-with-nested-components)

``` coq
Function execute_string (n : nat) (code : string) (input : string) : option string := option_bind (parse code) (fun code => execute n code input).

Definition A_code := "++++++++[>++++++++<-]>+."%string.
Theorem test_A : execute_string 1000 A_code EmptyString = Some "A"%string.
Proof. compute. trivial. Qed.

Definition helloworld_code := "++++[>++++[>++++>++++++>++<<<-]>++>+<<<-]>>.>+.+++++++..+++.>.<<-<++++[>++++<-]>.>.+++.------.--------.>+."%string.
Theorem test_helloworld : execute_string 10000 helloworld_code EmptyString = Some "Hello World!"%string.
Proof. compute. trivial. Qed.
```

-   unittest
    -   証明ではない
-   この単純な処理系に関しては、証明の余地はほぼなかったように思う
    -   標準libraryにあるべきだが欠落している汎用関数のそれは別とする
-   helloworldのcodeは短さのため[BrainFuck \<\[+-.,\]\> >>197](http://pc11.2ch.net/test/read.cgi/tech/1036013915/197)から拝借

## links

-   <https://coq.inria.fr/library/index.html>
-   <http://ja.wikipedia.org/wiki/Brainfuck>

## version

``` sh
$ coqc -v
The Coq Proof Assistant, version 8.4pl5 (January 2015)
compiled on Jan 27 2015 19:49:36 with OCaml 4.02.1
```
