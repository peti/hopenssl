module Main ( main ) where

import OpenSSL.EVP.Digest
import OpenSesame

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

digest :: DigestDescription -> String -> IO String
digest algo input = do
  let digestSize = _digestSize (getDigestDescription algo)
  md <- alloca $ \ctx' -> do
    let ctx = digestContext ctx'
    bracket_ (initContext ctx) (cleanupContext ctx) $ do
      initDigest algo ctx
      withCStringLen input $ \(ptr,len) -> updateDigest ctx (castPtr ptr) (fromIntegral len)
      allocaArray (fromIntegral digestSize) $ \md -> do
        finalizeDigest ctx md
        peekArray (fromIntegral digestSize) md
  return (md >>= toHex)
