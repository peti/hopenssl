module Main ( main ) where

import OpenSSL.EVP.Digest

import Control.Exception
import Foreign
import Foreign.C.String
import Test.HUnit

main :: IO ()
main = _addAllDigests >> runTestTT (TestList tests) >> return ()

tests :: [Test]
tests = map (uncurry (mkTest "open sesame")) opensesame

mkTest :: String -> String -> String -> Test
mkTest input algoName expect = TestCase $ do
  algo' <- getDigestByName algoName
  case algo' of
    Nothing -> return ()
    Just algo -> digest algo input >>= assertEqual algoName expect

opensesame :: [(String, String)]
opensesame = [ ("MD5",       "54ef36ec71201fdf9d1423fd26f97f6b")
             , ("SHA",       "2ccefef64c76ac0d42ca1657457977675890c42f")
             , ("SHA1",      "5bcaff7f22ff533ca099b3408ead876c0ebba9a7")
             , ("DSS",       "5bcaff7f22ff533ca099b3408ead876c0ebba9a7")
             , ("DSS1",      "5bcaff7f22ff533ca099b3408ead876c0ebba9a7")
             , ("RIPEMD160", "bdb2bba6ec93bd566dc1181cadbc92176aa78382")
             , ("MDC2",      "112db2200ce1e9db3c2d132aea4ef7d0")
             , ("SHA224",    "1ee0f9d93a873a67fe781852d716cb3e5904e015aafaa4d1ff1a81bc")
             , ("SHA256",    "41ef4bb0b23661e66301aac36066912dac037827b4ae63a7b1165a5aa93ed4eb")
             , ("SHA384",    "ae2a5d6649035c00efe2bc1b5c97f4d5ff97fa2df06f273afa0231c425e8aff30e4cc1db5e5756e8d2245a1514ad1a2d")
             , ("SHA512",    "8470cdd3bf1ef85d5f092bce5ae5af97ce50820481bf43b2413807fec37e2785b533a65d4c7d71695b141d81ebcd4b6c4def4284e6067f0b9ddc318b1b230205")
             ]

digest :: DigestDescription -> String -> IO String
digest algo input = do
  let digestSize = _digestSize (getDigestDescription algo)
  md <- alloca $ \ctx' -> do
    let ctx = digestContext ctx'
    bracket_ (initContext ctx) (cleanupContext ctx) $ do
      initDigest ctx algo
      withCStringLen input $ \(ptr,len) -> updateDigest ctx (castPtr ptr) (fromIntegral len)
      allocaArray (fromIntegral digestSize) $ \md -> do
        finalizeDigest ctx md
        peekArray (fromIntegral digestSize) md
  return (md >>= toHex)
