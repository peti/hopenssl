module Main ( main ) where

import OpenSSL.Digest
import OpenSesame

import Test.HUnit

main :: IO ()
main = runTestTT (TestList tests) >> return ()

tests :: [Test]
tests = map (uncurry (mkTest "open sesame")) opensesame

mkTest :: String -> String -> String -> Test
mkTest input algoName expect = TestCase $
  case digestByName' algoName of
    Nothing -> return ()
    Just algo -> assertEqual algoName expect (digestString algo input >>= toHex)
