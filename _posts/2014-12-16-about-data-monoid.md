---
category: blog
layout: post
title: "Data.Monoidを眺めた"
date: 2014-12-16T18:20:40+09:00
tags: [ "haskell", "monoid", "prelude" ]
math: true
---

haskellの`Monoid`のまとめ

``` haskell
Monoid Ordering
Monoid ()
Monoid Any
Monoid All
Monoid a => Monoid (Maybe a)
Monoid (Last a)
Monoid (First a)
Num a => Monoid (Product a)
Num a => Monoid (Sum a)
Monoid (Endo a)
Monoid a => Monoid (Dual a)
Monoid b => Monoid (a -> b)
(Monoid a, Monoid b) => Monoid (a, b)
(Monoid a, Monoid b, Monoid c) => Monoid (a, b, c)
```

``` haskell
instance MonadPlus []
instance MonadPlus Maybe
```

<!-- more -->

## モノイド(monoid)とは

数学的には

-   台集合 $M$
-   二項演算 $\cdot : M \times M \to M$
    -   結合律を満たす
-   単位元 $e$

の組$(M,\cdot,e)$のこと。つまり

$$
    \begin{array}
        \forall x, y, z \in M. x \cdot (y \cdot z) =  (x \cdot y) \cdot z \\
        \exists e \in M \mbox{ such that } \forall x \in M. e \cdot x = x \cdot e = x
    \end{array}
$$

haskellでは

``` haskell
class Monoid a where
    mappend :: a -> a -> a
    mempty  :: a
```

と定義され、

``` haskell
x `mappend` (y `mappend` z) = (x `mappend` y) `mappend` z
mempty `mappend` x = x `mappend` mempty = x
```

を満たすことが期待される。

単位元を除くと半群(semigroup)、逆元の存在を加えると群(group)になる。

``` haskell
(<>) :: Monoid a => a -> a -> a
(<>) = mappend
mconcat :: Monoid a => [a] -> a
mconcat = foldr mappend mempty
```

という便利な関数も定義されている。

## Sum, Product

haskellの`Num`は`*`と`+`を持っており環(ring)なので、どちらを使うのかnewtypeで包んで明示する必要がある。

``` haskell
>>> getSum (Sum 3 <> Sum 4)
7
>>> getProduct (Product 3 <> Product 4)
12
>>> getSum mempty
0
>>> getProduct mempty
1
```

## All, Any

`Bool`は`&&`と`||`を持っており環なので、`Sum`, `Product`同様wrapperが必要。

## Ordering

``` haskell
instance Monoid Ordering where
    EQ `mappend` y = y
    x  `mappend` y = x
    mempty = EQ
```

``` haskell
>>> mconcat [EQ, EQ, EQ, GT, EQ, LT]
GT
>>> zipWith compare "aabc" "abcd"
[EQ,LT,LT,LT]
>>> let f x y = mconcat (zipWith compare x y) <> (compare `on` length) x y in f "aabc" "abcd"
LT
```

まあまあ便利。


## Endo

``` haskell
newtype Endo a = Endo (a -> a)
```

始域と終域が同じ関数の集合は、合成に関して閉じるので恒等関数を単位元としてモノイドをなす。

``` haskell
mappend ~ (.)
mempty  ~ id
```

``` haskell
>>> (appEndo . mconcat . map Endo) [(+ 1), (* 4), (+ 3)] 0
13
```

以外と便利。

## Dual

任意のモノイド$(M,\cdot,e)$に対しその二項演算$\cdot$の引数の順を逆にした二項演算$b \star a := a \cdot b$を考えると、$(M,\star,e)$もまたモノイド。

``` haskell
>>> "foo" <> "bar"
"foobar"
>>> Dual "foo" <> Dual "bar"
Dual "barfoo"
```

## ()

任意の単元集合$\{e\}$は$e \cdot e = e$とするとモノイド。自明なモノイドと呼ばれる。

``` haskell
>>> () <> ()
()
>>> mempty :: ()
()
```

## (,), (,,)

``` haskell
instance (Monoid a, Monoid b) => Monoid (a, b)
```

モノイドとモノイドの直積もモノイドになる。

``` haskell
>>> (Sum 3, Product 3) <> (Sum 4, Product 4)
(Sum 7, Product 12)
```

## x -> a

``` haskell
instance Monoid a => Monoid (x -> a)
```

任意の集合からモノイドへの関数はモノイド。$f \star g := \lambda x. f(x) \cdot g(x)$とする。単位元は$\lambda x. e$。

上の積の例の一般化と言える。hom集合には値域の性質が入る。

## First, Last

任意の集合$S$に対し、そのある特別な要素$e \in S$を定めると、

$$
    \begin{array}
        \forall a \in S. a \cdot e = e \cdot a = a \\
        \forall a \in S \setminus \{e\}, b \in S. a \cdot b = a
    \end{array}
$$

とするとモノイド$(S,\cdot,e)$をなす。単位元でない最も左の要素が結果となるので左自明モノイドと呼ばれる。同様に右自明モノイドも考えられる。

haskellでは一般のデータに定義するため`Maybe`に包み単位元として`Nothing`を使う。`First`が左自明モノイド、`Last`が右自明モノイドとしてinstance宣言されている。

``` haskell
>>> First (Just 'A') <> First (Just 'B')
First (Just 'A')
>>> (getLast . mconcat . map Last) [Just 'A', Nothing, Just 'B', Nothing, Nothing]
Just 'B'
```

## [a]

``` haskell
instance Monoid [a]
```

任意の集合上の列は結合と空列に対しモノイドをなす。

``` haskell
(<>) = (++)
mempty = []
```

要素が何であれモノイドの公理を満たし、かつ余分な等式を作らないので、自由モノイドと呼ばれる。例えば点を加えて左自明モノイドを作ると$\forall a \in S \setminus \{e\}. \forall b, c \in S. a \cdot b = a \cdot c$のような等式ができるが、そういうものがないということ。

## Maybe a

任意の半群に単位元として一点足せばモノイドになる。

のだけど、haskellの標準には`Semigroup`がないので`Monoid`で代用している。`mempty`が定義されていない`Monoid`を`Maybe`に突っ込むとちゃんとした`Monoid`がでてくる。邪悪。

``` haskell
instance Monoid a => Monoid (Maybe a)
```

## MonadPlus

``` haskell
class Monad m => MonadPlus m where
    mplus :: m a -> m a -> m a
    mzero :: m a
```

`Monad`かつ引数与えると`Monoid`。モノイドと同様、結合律と単位元を要求する。

``` haskell
instance MonadPlus []
instance MonadPlus Maybe
```

であり、`[]`は自由モノイド、`Maybe`は左自明モノイドを生成する。


---

## 参考

-   [base-4.7.0.1 Control.Monad](http://hackage.haskell.org/package/base-4.7.0.1/docs/Control-Monad.html)
-   [モノイド - Wikipedia](http://ja.wikipedia.org/wiki/%E3%83%A2%E3%83%8E%E3%82%A4%E3%83%89)
-   [単一代入のモノイド、スタンピングモナド、モナド工場 - 檜山正幸のキマイラ飼育記](http://d.hatena.ne.jp/m-hiyama/20090701/1246410984)
    -   右自明モノイド 左自明モノイド

モノイドからモナドが作れるだとか、左/右自明モノイドと単一代入/破壊的代入が関連するとか聞いたりして、今一度見てみたら面白かったので書いた。

記述時の`base`は`4.7.0.1`でした
