---
layout: post
alias: "/blog/2016/03/28/hackerrank-lambda-calculi-march-2016-simplify-the-algebraic-expressions/"
date: 2016-03-28T15:27:48+09:00
tags: [ "competitive", "writeup", "hackerrank", "lambda-calculi", "haskell" ]
"target_url": [ "https://www.hackerrank.com/contests/lambda-calculi-march-2016/challenges/simplify-the-algebraic-expressions" ]
---

# Lambda Calculi - March 2016: Simplify the Algebraic Expressions

## 感想

明らかな糞。
問題文はひどく曖昧。
作問者は競プロの初心者のようなので問題が駄目な感じなのはまあいいとして、「全完者でてるのでtie-breakerとしてケース追加するよ。」は許されない。
問題が曖昧なのだから、参加者は嘘っぽい解法を書くしかない。それを後から咎めるのは間違っている。
しかも追加されたのは3日間あるコンテストの2日目で、連絡等はなくこっそりと追加された。1日目に全完した人間が追加に気付けるとは思えない、不公平である。
これのおかげで2位から1位になったが、釈然としない。

## 実装

parsecに投げた。
やる気のない実装だが問題相応だと思われる。

``` haskell
#!/usr/bin/env runhaskell
{-# LANGUAGE FlexibleContexts #-}
module Main where
import Control.Exception (assert)
import Control.Monad
import Control.Applicative
import Data.Maybe
import Data.Ratio
import qualified Data.Map as M
import Text.Parsec hiding ((<|>))
import Text.Parsec.Expr

data Expr
    = Var Integer Integer
    | Add Expr Expr
    | Sub Expr Expr
    | Mul Expr Expr
    | Div Expr Expr
    | Pow Expr Expr
    deriving Show

symbol c = try $ spaces >> char c
parens = try . between (symbol '(') (symbol ')')
natural = (<?> "nat") . try $ do
    spaces
    n <- many1 digit
    return (read n :: Integer)
constant = (<?> "constant") $ do
    n <- natural
    return $ Var n 0
var = (<?> "var") $ do
    symbol 'x'
    return $ Var 1 1
table =
    let op c f = Infix ( symbol c >> return f ) AssocLeft in
    [ [ op '^' Pow
      ]
    , [ op '*' Mul
      , op '/' Div
      , Infix ( return Mul ) AssocLeft
      ]
    , [ op '+' Add
      , op '-' Sub
      , Prefix ( symbol '-' >> return (Mul (Var (-1) 0)) ) 
      ]
    ]
expr = try (buildExpressionParser table term <?> "expr")
term = try
    (parens expr
    <|> var
    <|> constant)
    <?> "term"
parseExpr :: String -> Expr
parseExpr s = case parse expr s s of
    Right e -> e
    Left err -> error $ show err

unsafeRatioToInt :: Integral a => Ratio a -> a
unsafeRatioToInt q = assert (denominator q == 1) $ numerator q

calculateExpr :: Expr -> M.Map Integer Rational
calculateExpr (Var a n) = M.singleton n (fromIntegral a)
calculateExpr (Add e e') = M.unionWith (+) (calculateExpr e) (calculateExpr e')
calculateExpr (Sub e e') = M.unionWith (+) (calculateExpr e) (M.map negate $ calculateExpr e')
calculateExpr (Mul e e') =
    M.fromListWith (+) $ do
        (n, a) <- M.toList $ calculateExpr e
        (m, b) <- M.toList $ calculateExpr e'
        [(n + m, a * b)]
calculateExpr (Div e e') =
    M.fromListWith (+) $ do
        (n, a) <- M.toList $ calculateExpr e
        (m, b) <- M.toList $ calculateExpr e'
        [(n - m, a / b)]
calculateExpr (Pow e e') =
    M.fromListWith (+) $ do
        (n, a) <- M.toList $ calculateExpr e
        (0, b) <- M.toList $ calculateExpr e'
        let b' = unsafeRatioToInt b -- ???
        [(n * b', a ^ b')]

formatTerm :: (Integer, Rational) -> String
formatTerm (n, q) = case (n, unsafeRatioToInt q) of
    (_,  0) -> ""
    (1,  1) ->  "x"
    (n,  1) ->  "x^" ++ show n
    (1, -1) -> "-x"
    (n, -1) -> "-x^" ++ show n
    (0,  q) -> show q
    (1,  q) -> show q ++ "x"
    (n,  q) -> show q ++ "x^" ++ show n

putPlus :: String -> String
putPlus "" = ""
putPlus ('-' : s) = " - " ++ s
putPlus s = " + " ++ s

formatTerms :: M.Map Integer Rational -> String
formatTerms e =
    let ts = map formatTerm $ M.toDescList e
    in concat (head ts : map putPlus (tail ts))

simplify :: String -> String
simplify = formatTerms . calculateExpr . parseExpr
-- simplify = show . parseExpr


main :: IO ()
main = do
    t <- readLn
    replicateM_ t $ do
        s <- getLine
        putStrLn $ simplify s
```
