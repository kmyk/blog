---
category: blog
layout: post
date: 2014-06-10T21:38:12+09:00
tags: [ "haskell", "type" ]
math: true
---

# 関数をEnumにして遊んだ

全域関数 $ f : \mathbb{A} \to \mathbb{B} $ は $ { \left|
\mathbb{B} \right|
}^{ \left|
\mathbb{A} \right|
} $ 個存在します  
なので例えば型`Bool -> Bool`を持つ関数は $ {\left| \mathbb{Bool} \right|}^{\left| \mathbb{Bool} \right|} = 2^2 = 4 $ 個であり、十分列挙可能  
ゆえにinstancingしました

``` haskell
instance (..) => Enum (a -> b) where ..
```

<!-- more -->

## 必要物

``` haskell
{-# LANGUAGE ScopedTypeVariables #-}
import Data.Monoid (mconcat)
```

## 補助関数

``` haskell
habitant :: (Enum a, Bounded a) => a -> Int
habitant a = f maxBound - f minBound + 1 where
    f x = fromEnum (x `asTypeOf` a)

habitants :: forall a. (Enum a, Bounded a) => [a]
habitants = [minBound :: a .. maxBound]

digit :: Int -> [Int] -> Int
digit n = sum . zipWith (\ ix x -> x * pow n ix) [0 :: Int ..] where
    pow _ 0 = 1
    pow x y = x * pow x (y - 1)

unndigit :: Int -> Int -> [Int]
unndigit n = f where
    f 0 = []
    f x = f (x `div` n) ++ [x `mod` n]

decode :: forall dom cod. (Enum dom, Bounded dom, Enum cod, Bounded cod) => Int -> dom -> cod
decode n = if n < 0 || (cod ^ dom) <= n
        then error "wrong index of functions"
        else toEnum . (funcs !!) . fromEnum where
    dom = habitant (undefined :: dom)
    cod = habitant (undefined :: cod)
    funcs = let xs = unndigit cod n in replicate (dom - length xs) 0 ++ xs

encode :: forall dom cod. (Enum dom, Bounded dom, Enum cod, Bounded cod) => (dom -> cod) -> Int
encode f = digit cod . map (fromEnum . f) . reverse $ enumFrom minDom where
    cod = habitant (undefined :: cod)
    minDom = minBound :: dom
```

`digit`/`undigit`は、listと自然数を相互変換し、 `decode`/`encode`は、関数とlistを相互変換します

具体的には

1.  列挙型から列挙型への関数を、
2.  `fromEnum`/`toEnum`により、自然数から自然数への関数へ変換し、
3.  添字を引数と見ることで、自然数のlistへ変換し、
4.  listをdom進数cod桁の数と見て、1つの自然数に変換します


## instancing

``` haskell
instance (Enum a, Bounded a, Enum b, Bounded b) => Enum (a, b) where
    fromEnum (a, b) = fromEnum a * habitant b + fromEnum b
    toEnum n = (toEnum (n `div` m), toEnum (n `mod` m)) where
        m = habitant (undefined :: b)
    enumFrom x       = map toEnum [fromEnum x .. fromEnum (maxBound :: (a, b))]
    enumFromThen x y = map toEnum [fromEnum x, fromEnum y .. fromEnum (maxBound :: (a, b))]

instance (Enum a, Bounded a, Eq b) => Eq (a -> b) where
    f == g = all (\ x -> f x == g x) habitants

instance (Enum a, Bounded a, Ord b) => Ord (a -> b) where
    f `compare` g = mconcat $ map (\ x -> f x `compare` g x) habitants

instance (Bounded a, Bounded b) => Bounded (a -> b) where
    minBound = const minBound
    maxBound = const maxBound

instance (Enum a, Bounded a, Enum b, Bounded b) => Enum (a -> b) where
    fromEnum = encode
    toEnum = decode
    enumFrom x       = map toEnum [fromEnum x .. fromEnum (maxBound :: (a, b))]
    enumFromThen x y = map toEnum [fromEnum x, fromEnum y .. fromEnum (maxBound :: (a, b))]
```

## 利用

``` haskell
false', not', id', true' :: Bool -> Bool
false' = decode 0
id'    = decode 1
not'   = decode 2
true'  = decode 3

main :: IO ()
main = do
    print $ not' True
    print $ fromEnum (toEnum 3 :: Bool -> Bool -> Bool)
    print $ map (\ f -> f True True) [(&&) .. (==) :: Bool -> Bool -> Bool]
```

闇っぽい


## 問題
-   `Integer`や`[a]`等の要素の数が無限なものは、この方法では列挙できない
-   `Int`は有限だが、`toEnum`/`fromEnum`が`Int`を使うため、overflowし列挙できない
-   `minBound == 0`等、`Enum`や`Bounded`に仮定多すぎ
