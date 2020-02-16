---
category: blog
layout: post
date: 2014-05-16T22:23:42+09:00
tags: [ "idris", "haskell", "proof", "type" ]
---

# idrisに挑戦した

再挑戦する日のため、敗北した過程のメモ

``` sh
$ idris
     ____    __     _
    /  _/___/ /____(_)____
    / // __  / ___/ / ___/     Version 0.9.12-git:dae7d7d
  _/ // /_/ / /  / (__  )      http://www.idris-lang.org/
 /___/\__,_/_/  /_/____/       Type :? for help
```

<!-- more -->

## install
``` sh
$ git clone git://github.com/edwinb/Idris-dev.git idris
$ cd idris
$ echo 'CABALFLAGS += -f FFI -f curses' > custom.mk
$ make
```

`custom.mk`にFFIを加えていないと`:x`で`IO`を評価できなかった  
それ以外は簡単ですね


## replで遊ぶ

### head

``` haskell
Idris> :total List.head
Prelude.List.head is Total
Idris> :type List.head
Prelude.List.head : (l : List a) -> (isCons l = True) -> a
Idris> with List head [42, 64] refl
42 : Integer
Idris> with List head [] refl
(input):1:16:When elaborating argument ok to function Prelude.List.head:
        Can't unify ...
Idris> :doc refl
refl : x = x
    A proof that x in fact equals x. ...
```

listとそれがnilでないことの証明を引数にとるため、headが全域関数 すごい

overloadできるので`with`構文とか`the`関数とかが必要  
`[3] : List Int`のような型注釈はできない  
`:type refl`したら怒られたので`refl`何者

### IO

``` haskell
Idris> print "foo"
MkIO (\{w0} => mkForeignPrim (FFun "putStr" [FString] FUnit) "\"foo\"\n" w) : IO ()
Idris> :x print "foo"
"foo"
MkIO (\{w0} => prim__IO ()) : IO ()
```

`:x`で実行を促さない限り副作用ありません

簡約後の式をreplに渡すと`w`や`{w0}`の辺りで怒られた

## quine
``` haskell
module Main
main : IO ()
main = putStrLn (s ++ show (the String s)) where
  s = "module Main\nmain : IO ()\nmain = putStrLn (s ++ show (the String s)) where\n  s = "
```

``` sh
$ idris quine.idr -o a.out
$ diff quine.idr <(./a.out)
```

haskell同様、`show`と`where`のおかげで非常にquineが書きやすい

`s`の型注釈が要るのは何故だ


## fibonacci

``` haskell
module Main
fibs : Stream Nat
fibs = map fib [0..]

main : IO ()
main = recur fibs where
  recur (x :: xs) = do
    print x
    recur xs
```

`fib : Nat -> Nat`が`Prelude`にあるという恐ろしさよ

haskellの`mapM_`が`traverse_`に吸収された 良い  
また、`[0..]`が無限長なため全域関数`traverse_`では扱えず、`IO`の中で処理せねばならない


### applicative style

しかし、haskellでは等価な以下のような別表現は動かない

``` haskell
main' : IO ()
main' = recur fibs where
  recur (x :: xs) = print x $> recur xs

main'' : IO ()
main'' = recur fibs where
  recur (x :: xs) = print x >>= const (recur xs)
```

replで試すと `do` `$>` `>>=` それぞれ以下のような簡約結果になる

``` haskell
Idris> do { putStrLn "hoge" ; print 3 }
io_bind (MkIO (\{w0} => mkForeignPrim (FFun "putStr" [FString] FUnit) "hoge\n" w))
        (\{bindx0} => MkIO (\{w0} => mkForeignPrim (FFun "putStr" [FString] FUnit) "3\n" w)) : IO ()
Idris> putStrLn "hoge" $> print 3
io_bind (io_bind (MkIO (\{w0} => mkForeignPrim (FFun "putStr" [FString] FUnit) "hoge\n" w)) (\{b0} => io_return id))
        (\f' => io_bind (MkIO (\{w0} => mkForeignPrim (FFun "putStr" [FString] FUnit) "3\n" w)) (\a' => io_return (f' a'))) : IO ()
Idris> putStrLn "hoge" >>= const (print 3)
io_bind (MkIO (\{w0} => mkForeignPrim (FFun "putStr" [FString] FUnit) "hoge\n" w))
        (\v => MkIO (\{w0} => mkForeignPrim (FFun "putStr" [FString] FUnit) "3\n" w)) : IO ()
```

末尾再帰最適化が絡んでいるのかなと思ったが、下も動くので全く分からない

``` haskell
main''' : IO ()
main''' = recur fibs where
  recur (x :: xs) = do
    print x
    recur xs
    putStrLn "foo"
```


## fizzbuzz
`Prelude`に`Semigroup`やばい  
あるからには使わねばならない

``` haskell
module Main

data FizzBuzz = Fizz | Buzz | Fizzbuzz

fizz : Nat -> Maybe FizzBuzz
fizz n = if (n `mod` 3) == 0 then Just Fizz else Nothing
buzz : Nat -> Maybe FizzBuzz
buzz n = if (n `mod` 5) == 0 then Just Buzz else Nothing

instance Eq FizzBuzz where
  Fizzbuzz == Fizzbuzz = True
  Fizz == Fizz = True
  Buzz == Buzz = True
  _ == _ = False

instance Semigroup FizzBuzz where
  a <+> b = if a == b then a else Fizzbuzz

fizzbuzz : Nat -> Maybe FizzBuzz
fizzbuzz n = fizz n <+> buzz n

instance Show FizzBuzz where
  show Fizz = "fizz"
  show Buzz = "buzz"
  show Fizzbuzz = "fizzbuzz"

main : IO ()
main = recur 1 where
  recur : Nat -> IO ()
  recur n = do
    putStrLn $ fromMaybe (show n) (map show $ fizzbuzz n)
    recur $ succ n
```

半群なので結合律が必要なのですが、何故か後から追加で証明を与える仕様になっている  
結合律の有無がよく分からないならそれはmagmaだと思うのですが、なにか理由があるのでしょう

そして肝心の証明はよく分からなかったので全列挙しました

``` haskell
instance VerifiedSemigroup FizzBuzz where
  semigroupOpIsAssociative Fizz     Fizz     Fizz     = refl
  semigroupOpIsAssociative Fizz     Fizz     Buzz     = refl
  semigroupOpIsAssociative Fizz     Fizz     Fizzbuzz = refl
  semigroupOpIsAssociative Fizz     Buzz     Fizz     = refl
  semigroupOpIsAssociative Fizz     Buzz     Buzz     = refl
  semigroupOpIsAssociative Fizz     Buzz     Fizzbuzz = refl
  semigroupOpIsAssociative Fizz     Fizzbuzz Fizz     = refl
  semigroupOpIsAssociative Fizz     Fizzbuzz Buzz     = refl
  semigroupOpIsAssociative Fizz     Fizzbuzz Fizzbuzz = refl
  semigroupOpIsAssociative Buzz     Fizz     Fizz     = refl
  semigroupOpIsAssociative Buzz     Fizz     Buzz     = refl
  semigroupOpIsAssociative Buzz     Fizz     Fizzbuzz = refl
  semigroupOpIsAssociative Buzz     Buzz     Fizz     = refl
  semigroupOpIsAssociative Buzz     Buzz     Buzz     = refl
  semigroupOpIsAssociative Buzz     Buzz     Fizzbuzz = refl
  semigroupOpIsAssociative Buzz     Fizzbuzz Fizz     = refl
  semigroupOpIsAssociative Buzz     Fizzbuzz Buzz     = refl
  semigroupOpIsAssociative Buzz     Fizzbuzz Fizzbuzz = refl
  semigroupOpIsAssociative Fizzbuzz Fizz     Fizz     = refl
  semigroupOpIsAssociative Fizzbuzz Fizz     Buzz     = refl
  semigroupOpIsAssociative Fizzbuzz Fizz     Fizzbuzz = refl
  semigroupOpIsAssociative Fizzbuzz Buzz     Fizz     = refl
  semigroupOpIsAssociative Fizzbuzz Buzz     Buzz     = refl
  semigroupOpIsAssociative Fizzbuzz Buzz     Fizzbuzz = refl
  semigroupOpIsAssociative Fizzbuzz Fizzbuzz Fizz     = refl
  semigroupOpIsAssociative Fizzbuzz Fizzbuzz Buzz     = refl
  semigroupOpIsAssociative Fizzbuzz Fizzbuzz Fizzbuzz = refl
```

証明力足りない


## 所感
現段階では、方が強すぎて書きにくく感じる  
haskellで少し気をつけながら書くほうが楽である

定理照明系に明るくないのが問題なのだろう  
まずはcoqに習熟すべきかと思う

また、document周りが不満  
主にapi-documentがweb上に見つからないこと


## refs
-   [Idris -](http://www.idris-lang.org/)
-   [idris-lang/Idris-dev](https://github.com/idris-lang/Idris-dev)
    -   [Home · idris-lang/Idris-dev Wiki](https://github.com/idris-lang/Idris-dev/wiki)
-   [記事一覧 - M59のブログ](http://mandel59.hateblo.jp/search?q=idris)
    -   [こわくない Idris (1) - M59のブログ](http://mandel59.hateblo.jp/entry/2013/09/02/184831)
