module Main ( main ) where

import OpenSesame

import OpenSSL.EVP.Digest
import OpenSSL.Util

import Control.Exception
import Foreign
import Foreign.C.String
import Test.HUnit

main :: IO ()
main = runTestTT (TestList tests) >> return ()

tests :: [Test]
tests = map (uncurry (mkTest "open sesame")) opensesame

mkTest :: String -> String -> String -> Test
mkTest input algoName expect = TestCase $
  case digestByName' algoName of
    Nothing -> return ()
    Just algo -> digest algo input >>= assertEqual algoName expect

digest :: Algorithm -> String -> IO String
digest algo input = do
  let mdSize = digestSize algo
  md <- bracket newContext freeContext $ \ctx -> do
    initDigest algo ctx
    withCStringLen input $ \(ptr,len) -> updateDigest ctx ptr (fromIntegral len)
    allocaArray mdSize $ \md -> do
      finalizeDigest ctx md
      peekArray mdSize md
  return (md >>= toHex)
