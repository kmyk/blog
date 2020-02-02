---
category: blog
layout: post
title: "haskellのlensの使い方 (詳しめ)"
date: 2014-12-14T00:00:00+09:00
tags: [ "haskell", "lens" ]
---

`Lens`,`Getter`,`Setter`から`Equality`,`Iso`,`Prism`,`Review`に関して

[Haskellのlensの使い方 (基本)](/blog/2014/12/14/how-to-use-lens-a/)の続き

<!-- more -->

## Equality

``` haskell
type Equality s t a b = forall p f. p a (f b) -> p s (f t)
```

>   A witness that `(a ~ s, b ~ t)`.

-   図の一番下にある。
-   `a`と`s`,`b`と`t`が等しいことを示す。同時に2つの等号を表すのはlensとして使うためであろう。

``` haskell
type Equality s t a b = forall p f.               p a (f b) -> p s (f t)
type Lens     s t a b = forall   f. Functor f => (a -> f b) -> s -> f t
```

のように`Lens`と比較すると、その`(->)`と`Functor`の制約が取り除かれていることが分かる。型は、任意の二項型構築子`p`に対し`a`,`b`から`s`,`t`へはその上で変換できる、と言っている。このようなことが可能であるのはつまり、`a`と`s`,`b`と`t`が同一である時のみである。(あるいは型`a`,`b`を持つ値が存在しない時。)

-   抽象的過ぎて制約が強く逆に分かりやすい
-   data `Identical`は、その値が存在することと`a`と`s`,`b`と`t`が同一であることが同値であるようにGADTsで定義されている
    -   面白い

``` haskell
type Foo = Int
fooIsInt :: Equality' Foo Int
fooIsInt = id
fooIsDouble :: Equality' Foo Double
fooIsDouble = id -- Couldn't match type `Double' with `Int'
```

## Iso

``` haskell
type Iso s t a b = forall p f. (Profunctor p, Functor f) => p a (f b) -> p s (f t)
iso :: (s -> a) -> (b -> t) -> Iso s t a b
from :: Iso s t a b -> Iso b a t s
```

<small>Mon Dec 22 23:05:12 JST 2014 : `Iso`の型が`Lens`のそれになっていたので修正 [@minpou\_](https://twitter.com/minpou_)氏に感謝します</small>

>   Isomorphism families can be composed with another `Lens` using `(.)` and `id`.

-   `Equality`と`Lens`の間にある。同型を表わす
    -   同型とはざっくり言うとこの場合その型を持つ値の数が等しいことである
-   逆向きでも使える`Lens`
    -   `from`は向きをひっくり返す
    -   ひっくり返してもなお`Iso`
-   これも普通`Iso s t a b`でなく`Iso' s a`を使うと思う
    -   そもそも`s = t, a = b`でないと`Getter`のmethodが使えない
-   関数`iso`は右向きと左向きの2つの関数を与え、`Iso`を作る
    -   合成しても`id`にならないものを与えることもできるが止めるべき
-   `makeLenses`は可能ならば`Iso`を作る

``` haskell
data Tribool = TTrue | TFalse | TUnkown
tribool :: Iso' (Maybe Bool) Tribool
tribool = iso f g where
    f (Just True)  = TTrue
    f (Just False) = TFalse
    f Nothing      = TUnkown
    g TTrue   = Just True
    g TFalse  = Just False
    g TUnkown = Nothing
```

<!-- -->

``` haskell
>>> (Just True) ^. tribool
TTrue
>>> TUnkown ^. from tribool
Nothing
```

## Lens

``` haskell
type Lens s t a b = forall f. Functor f => (a -> f b) -> s -> f t
lens :: (s -> a) -> (s -> b -> t) -> Lens s t a b
```

>   A `Lens s t a b` is a purely functional reference.

-   純粋関数的参照
-   `Getter`かつ`Setter`


### 依存

lens類全般に言えることだが、単なる関数であるのでlens packageに依存していなくても`Lens`は作れる。

``` haskell
lens :: (s -> a) -> (s -> b -> t) -> (forall f. Functor f => (a -> f b) -> s -> f t)
lens sa sbt afb s = sbt s <$> afb (sa s)
```

なので、例えば

``` haskell
data Foo a = Foo { _bar :: Int, _baz :: Int, _quux :: a }
bar :: forall f. Functor f => (Int -> f Int) -> Foo a -> f (Foo a)
bar f s = (\ b -> s { _bar = b }) <$> f (_bar s)
```

のようにすると`Lens`ができる


## Prism

``` haskell
type Prism s t a b = forall p f. (Choice p, Applicative f) => p a (f b) -> p s (f t)
prism  :: (b -> t) -> (s -> Either t a) -> Prism s t a b
prism' :: (b -> s) -> (s -> Maybe a)    -> Prism s s a b
```

>   A `Prism l` is a `Traversal` that can also be turned around with `re` to obtain a `Getter` in the opposite direction.

-   (値の範囲的な意味での)包含
    -   `Integetr`と`Natural`とか
-   `Lens`の隣り
-   `Lens`と同じぐらい便利

作成:

``` haskell
import Numeric.Natural
nat :: Prism' Integer Natural
nat = prism toInteger $ \ i ->
    if i < 0
    then Left i
    else Right (fromInteger i)
```

左から右へは変換できないことがあるが、右から左へは必ず変換できる。

``` haskell
>>> (3 :: Integer) ^? nat :: Maybe Natural
Just 3
>>> (-3 :: Integer) ^? nat :: Maybe Natural
Nothing
>>> (3 :: Natural) ^. re nat :: Integer
3
```

無理矢理`Maybe`を剥がすこともできるし、添えることもできる。

``` haskell
>>> (3 :: Integer) ^?! nat :: Maybe Natural
3
>>> (-3 :: Integer) ^? nat :: Maybe Natural
*** Exception: (^?!): empty Fold
>>> (3 :: Natural) ^? re nat :: Maybe Integer
Just 3
```

`re`は`Review`の、`(^?)`,`(^?!)`は`Fold`のmethodである。また`Setter`でもあり、`Natural`であるときだけ2倍するといった操作も可能。

``` haskell
>>> (-3 :: Integer) & nat %~ (* 2)
-3
>>> (3 :: Integer) & nat %~ (* 2)
6
```

### template haskell

`makeLenses`の対応物`makePrisms`が存在する。

``` haskell
data ABC = A | B Int | C Double String
makePrisms ''ABC
```

すると

``` haskell
_A :: Prism' ABC ()
_B :: Prism' ABC Int
_C :: Prism' ABC (Double, String)
```

が定義される。便利。


## Review

``` haskell
type Review t b = forall p f. (Choice p, Bifunctor p, Settable f) => Optic' p f t b
unto :: (b -> t) -> Review s t a b
re :: Review s a -> Getter a s
un :: Getter s a -> Review a s
review :: Review t b -> b -> t
```

>   This is a limited form of a `Prism` that can only be used for `re` operations.

-   `Prism`の上、親はいない
    -   `re`だけできる`Prism`
-   `re`すると`Getter`になる
    -   逆に`Getter`を`un`すると`Review`になる
    -   といっても`Review`にしてもどうせ使うときは`Getter`に戻して使ってる
-   `review`も、`re`して`Getter`にして`view`してるだけ

``` haskell
>>> "hoge" ^. re (unto length)
4
```

ただし、

``` haskell
  re (unto length)
= (re . un . to) length
= (re . un) (to length)
= to length
```

である。


## Getter

``` haskell
type Getter s a = forall f. Gettable f => (a -> f a) -> s -> f s
to :: (s -> a) -> Getter s a
view :: Getter s a -> s-> a
(^.) = flip view
```

<small>Sun Dec 21 20:35:39 JST 2014 : `view, (^.) :: s -> Getter s a -> a`と表記していたので訂正</small>

>   A `Getter s a` is just any function `(s -> a)`, which ...

-   つまるところただの関数
-   `Lens`や`Iso`は`Getter`
-   `Review`と仲良し
-   `view`,`(^.)`で元の普通の関数に戻る

``` haskell
>>> False ^. to show
"False"
```

つまり

``` haskell
x ^. to f = f x
```

である。

### State

`State`の上でも使える (正確には`MonadState s`)

``` haskell
use :: Getter s a -> State s a
```

## Setter

``` haskell
type Setter s t a b = forall f. Settable f => (a -> f b) -> s -> f t
sets :: ((a -> b) -> s -> t) -> Setter s t a b
mapped :: Functor f => Setter (f a) (f b) a b
set, (.~) :: Setter s t a b -> b -> s -> t
over, (%~) :: Setter s t a b -> (a -> b) -> s -> t
```

>   A `Setter s t a b` is a generalization of `fmap` from `Functor`.

-   曰く関手
    -   `mapped`の型を見ると分かりやすい
-   `set`は値を代入
-   `over`は値を更新

``` haskell
>>> [1,2,3,4] & sets (\ f (x : xs) -> f x : xs) .~ 10
[10,2,3,4]
>>> [1,2,3,4] & mapped %~ (+ 10)
[11,12,13,14]
```

``` haskell
>>> [1,2,3,4] & mapped .~ 10
[10,10,10,10]
```

`mapped`の例ではまさに`map`しているのが分かる。

### State

`Getter`の`use`同様、`State`の上でも使える

``` haskell
assign, (.=) :: Setter s s a b -> b -> State s ()
(%=) :: Setter s s a b -> (a -> b) -> m ()
```

## まとめ

-   `Getter`は関数
-   `Setter`は関手
-   `Lens`は`Getter`かつ`Setter`
-   `Review`は逆向きの`Getter`
-   `Prism`は`Review`かつ`Setter`
-   `Iso`は同型
-   `Equality`は同一性

## This post is the No.15 article of [Haskell Advent Calendar 2014](http://qiita.com/advent-calendar/2014/haskell)
- Day 13: [mr\_konnさん](http://qiita.com/mr_konn)
- Day 15: [ruiccさん](http://qiita.com/ruicc)

---

-   Sun Jun 21 01:59:23 JST 2015
    -   次記事へのlinkを削除
