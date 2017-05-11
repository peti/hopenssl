module CheckSamples where

import OpenSSL.Digest

import Data.Word
import Distribution.TestSuite

tests :: IO [Test]
tests = return $ [ mkTest t "open sesame" expect | (t,expect) <- opensesame ]

mkTest t input expect = Test $ TestInstance
  { name = unwords [show t, show input]
  , run = do x <- hash t input
             return $ Finished $ if x == expect
                                    then Pass
                                    else Fail $ unwords ["got", x, "but expected", expect]
  , tags = []
  , options = []
  , setOption = \_ _ -> Left "unsupported option"
  }

hash :: MessageDigest -> String -> IO String
hash t x = fmap (>>= toHex) (digest t (map (toEnum . fromEnum) x))

opensesame :: [(MessageDigest, String)]
opensesame =
  [ (Null,      "")
  , (MD5,       "54ef36ec71201fdf9d1423fd26f97f6b")
  , (SHA,       "2ccefef64c76ac0d42ca1657457977675890c42f")
  , (SHA1,      "5bcaff7f22ff533ca099b3408ead876c0ebba9a7")
  , (DSS,       "5bcaff7f22ff533ca099b3408ead876c0ebba9a7")
  , (DSS1,      "5bcaff7f22ff533ca099b3408ead876c0ebba9a7")
  , (RIPEMD160, "bdb2bba6ec93bd566dc1181cadbc92176aa78382")
  , (MDC2,      "112db2200ce1e9db3c2d132aea4ef7d0")
  , (SHA224,    "1ee0f9d93a873a67fe781852d716cb3e5904e015aafaa4d1ff1a81bc")
  , (SHA256,    "41ef4bb0b23661e66301aac36066912dac037827b4ae63a7b1165a5aa93ed4eb")
  , (SHA384,    "ae2a5d6649035c00efe2bc1b5c97f4d5ff97fa2df06f273afa0231c425e8aff30e4cc1db5e5756e8d2245a1514ad1a2d")
  , (SHA512,    "8470cdd3bf1ef85d5f092bce5ae5af97ce50820481bf43b2413807fec37e2785b533a65d4c7d71695b141d81ebcd4b6c4def4284e6067f0b400000001b230205")
  ]
