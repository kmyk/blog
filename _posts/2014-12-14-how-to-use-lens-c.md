---
category: blog
layout: post
title: "haskellのlensの使い方 (やばめ)"
date: 2014-12-14T00:00:00+09:00
tags: [ "haskell", "lens" ]
---

`Traversal`,`Fold`,`MonadicFold`,`Action`に関して

[Haskellのlensの使い方 (詳しめ)](/blog/2014/12/14/how-to-use-lens-b/)の続き ちょっとだけ

<!-- more -->

[Lens で Haskell をもっと格好良く！ for 2013/3/31 ekmett 勉強会 ちゅーん](http://www.slideshare.net/itsoutoftunethismymusic/ekmett-17955009)

## Fold

``` haskell
type Fold s a = forall f. (Contravariant f, Applicative f) => (a -> f a) -> s -> f s
folded :: Foldable t => Fold (t a) a
foldMapOf :: Monoid m => Fold s a -> (a -> m) -> s -> m
view :: Monoid m => Fold s m -> s -> m
```

>   A `Fold` s a is a generalization of something `Foldable`.

>   A `Fold` describes how to retrieve multiple values in a way that can be composed with other `LensLike` constructions.

-   `Foldable`の一般化
-   `Applicative`制約はエラーメッセージとかの都合であって本質的ではない
-   `Contravariant`は反変関手
-   任意の`Getter`は`Fold`


## 参考
-   <https://hackage.haskell.org/package/lens>
-   <https://hackage.haskell.org/package/base>
-   `lens-4.6.0.1`
-   `base-4.7.0.1`

---

-   Sun Jun 21 01:52:37 JST 2015
    -   もっと詳しく書きたす予定だったけど、たぶんその機会はないので修正

[1]: <https://hackage.haskell.org/package/base/docs/Data-Foldable.html>
[2]: <https://hackage.haskell.org/package/base/docs/Data-Traversable.html>
