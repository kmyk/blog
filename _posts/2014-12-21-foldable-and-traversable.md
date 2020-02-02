---
category: blog
layout: post
title: "FoldableとTraversable"
date: 2014-12-21T22:28:50+09:00
tags: [ "haskell", "foldable", "traversable" ]
---

-   `Data.Foldable`
-   `Data.Traversable`

`lens`の`Fold`,`Traversal`の、前提を(私が)理解するために書かれた記事

<!-- more -->

## Foldable

``` haskell
class Foldable t where
    foldMap :: Monoid m => (a -> m) -> t a -> m
    foldr :: (a -> b -> b) -> b -> t a -> b
-- Minimal complete definition: foldMap or foldr.
```

>   Class of data structures that can be folded to a summary value.

畳み込んで一点に潰す演算の可能な型クラス。`Prelude.foldr`の一般化。満たすべき制約はない。

具体例をコードで示す。

``` haskell
instance Foldable [] where
    foldMap _ [] = mempty
    foldMap f (x : xs) = f x <> foldMap xs
```

``` haskell
instance Foldable Maybe where
    foldMap _ Nothing  = mempty
    foldMap f (Just x) = f x
```

``` haskell
instance Foldable Identity where
    foldMap f (Identity x) = f x
```

``` haskell
data Tree a = Leaf a | Tree (Tree a) (Tree a)
instance Foldable Tree where
    foldMap f (Leaf x) = f x
    foldMap f (Tree l r) = foldMap f l <> foldMap f r
```

``` haskell
>>> foldMap show (Tree (Tree (Leaf 18) (Leaf 19)) (Leaf 20))
"181920"
```

他に`Either a`,`(,) a`,`Proxy *`,`Const a`もinstanceである。`base`に限ると今挙げたもので全てである。

## Traversable

``` haskell
class (Functor t, Foldable t) => Traversable t where
    traverse :: Applicative f => (a -> f b) -> t a -> f (t b)
    sequenceA :: Applicative f => t (f a) -> f (t a)
-- Minimal complete definition: traverse or sequenceA.
```

>   Class of data structures that can be traversed from left to right, performing an action on each element.

左から右へなめて作用を各点ごとに評価可能な型クラス。`Prelude.sequence`の一般化。構造を保つことが期待される。

``` haskell
instance Traversable [] where
    traverse f [] = pure []
    traverse f (x:xs) = (:) <$> f x <*> traverse f xs
```

``` haskell
instance Traversable Maybe where
    traverse f Nothing = pure Nothing
    traverse f (Just x) = Just <$> f x
```

``` haskell
instance Traversable Identity where
    traverse f (Identity x) = Identity <$> f x
```

``` haskell
data Tree a = Leaf a | Tree (Tree a) (Tree a)
instance Traversable Tree where
    traverse f (Leaf x) = Leaf <$> f x
    traverse f (Tree l r) = Tree <$> traverse f l <*> traverse f r
```

``` haskell
>>> traverse (\ n -> print n >> return (n ^ 2)) (Tree (Tree (Leaf 18) (Leaf 19)) (Leaf 20))
18
19
20
Tree (Tree (Leaf 324) (Leaf 361)) (Leaf 400)
```

上で挙げた`Foldable`のinstanceは全て`Traversable`でもある。


### 制約

`traverse`は構造を保たなければならない。

#### identity

``` haskell
traverse Identity = Identity
```

#### naturality

``` haskell
t . traverse f = traverse (t . f) -- for every applicative transformation t
```

ただし`t`は`-XRank2Types`を有効にし明示的に全称量化すること

型内訳

``` haskell
Applicative f
Traversable t
a, b
t :: forall x y. f x -> f y
f :: a -> f b
```

舐めてからmapしても舐めるときにmapしても同じ

#### composition

``` haskell
traverse (Compose . fmap g . f) = Compose . fmap (traverse g) . traverse f
```

ただし`Compose`は関手の合成

``` haskell
newtype Compose f g a = Compose (f (g a))
instance (Traversable f, Traversable g) => Traversable (Compose f g)
```

``` haskell
Applicative f, g
Traversable t
a, b, c
f :: a -> f b
g :: b -> g c
```

まとめて舐めても一段ずつ舐めても同じ



## 関係

### Traversableからのdefault実装

-   `Traversable`なら`Functor`
-   `Traversable`なら`Foldable`

それぞれ`fmapDefault`, `foldMapDefault`という名前で実装が与えられており、`Traversable`のinstanceを書けば`fmap`, `foldMap`は与えられる。

``` haskell
fmapDefault    f = runIdentity . traverse (Identity . f)
foldMapDefault f = getConst    . traverse (Const    . f)
```

### FoldableであるがFunctorでない例

``` haskell
data Iter a = Iter (a -> a) a

instance Foldable Iter where
    foldMap f (Iter g a) = mconcat . map f $ iterate g a
```

`a -> a`という形で`a`が正の位置と負の位置両方に出てくるので関手ではない

また、`Set`も`Ord`制約のため`Functor`にできない

[Haskell : An example of a Foldable which is not a Functor (or not Traversable)? - Stack Overflow](http://stackoverflow.com/questions/8359115/haskell-an-example-of-a-foldable-which-is-not-a-functor-or-not-traversable)

### FoldableであるがTraversableでない例

`Set`は`Ord`を抜きにしても`Traversable`でない。mapの結果同じ要素ができて潰れると構造が変化してしまうためである。

[\[Haskell-cafe\] Non-traversable foldables - Google グループ](https://groups.google.com/forum/#!topic/fa.haskell/ZJDJIqUvWY8)


## 参考
-   [The Typeclassopedia (和訳) - #3](http://snak.tdiary.net/20091020.html#p02)
    -   型クラスの網羅的解説、`Fold`,`Traversal`を含む
-   [base Data.Foldable](https://hackage.haskell.org/package/base/docs/Data-Foldable.html)
-   [base Data.Traversable](https://hackage.haskell.org/package/base/docs/Data-Traversable.html)
-   [transformers Data.Functor.Compose](https://hackage.haskell.org/package/transformers/docs/Data-Functor-Compose.html)

記述時の`base`は`4.7.0.1`
