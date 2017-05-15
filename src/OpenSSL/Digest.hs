{-# LANGUAGE FlexibleInstances #-}

{- |
   Maintainer:  simons@cryp.to
   Stability:   provisional
   Portability: portable

   This module proivdes a high-level API to the message digest algorithms found
   in OpenSSL's @crypto@ library.

   Here is a short example program which runs all available digests on a
   string:

   > example :: (Enum a) => [a] -> IO [String]
   > example input = mapM hash [minBound .. maxBound]
   >   where
   >   hash f = fmap (fmt f) (digest f (toWord input))
   >   fmt f  = shows f . (":    \t"++) . (>>=toHex)
   >   toWord = map (toEnum . fromEnum)

   And when called, the function prints:

   > *Digest> example "open sesame" >>= putStr . unlines
   > Null:
   > MD5:       54ef36ec71201fdf9d1423fd26f97f6b
   > SHA:       2ccefef64c76ac0d42ca1657457977675890c42f
   > SHA1:      5bcaff7f22ff533ca099b3408ead876c0ebba9a7
   > DSS:       5bcaff7f22ff533ca099b3408ead876c0ebba9a7
   > DSS1:      5bcaff7f22ff533ca099b3408ead876c0ebba9a7
   > RIPEMD160: bdb2bba6ec93bd566dc1181cadbc92176aa78382
   > MDC2:      112db2200ce1e9db3c2d132aea4ef7d0
   > SHA224:    1ee0f9d93a873a67fe781852d716cb3e5904e015aafaa4d1ff1a81bc
   > SHA256:    41ef4bb0b23661e66301aac36066912dac037827b4ae63a7b1165a5aa93ed4eb
   > SHA384:    ae2a5d6649035c00efe2bc1b5c97f4d5ff97fa2df06f273afa0231c425e8aff30e4cc1db5e5756e8d2245a1514ad1a2d
   > SHA512:    8470cdd3bf1ef85d5f092bce5ae5af97ce50820481bf43b2413807fec37e2785b533a65d4c7d71695b141d81ebcd4b6c4def4284e6067f0b400000001b230205
-}

module OpenSSL.Digest
  ( -- * Generic digest API
    Digestable(..), digestByName, digestByName', DigestDescription
  , StrictByteString, LazyByteString
  , -- * Special instances
    digestCStringLen, digestString
  , -- * Helper Types and Functions
    toHex, digest', DigestablePointeeType, DigestableSizeType
  )
  where

import OpenSSL.EVP.Digest

import Control.Exception
import Control.Monad
import Foreign
import Foreign.C
import System.IO.Unsafe as IO
import qualified Data.ByteString as Strict ( ByteString )
import qualified Data.ByteString.Lazy as Lazy ( ByteString, toChunks )
import Data.ByteString.Unsafe ( unsafeUseAsCStringLen )

-- $setup
-- >>> import Data.Maybe

-- Generic Class API ----------------------------------------------------------

class Digestable a where
  {-# MINIMAL digestMany #-}

  digest :: DigestDescription -> a -> [Word8]
  digest algo = digestMany algo . return

  digestMany :: DigestDescription -> [a] -> [Word8]

instance (DigestablePointeeType a, DigestableSizeType b) => Digestable (Ptr a, b) where
  digestMany algo chunks = digest' algo (forM_ [ (castPtr ptr, fromIntegral len) | (ptr,len) <- chunks ])

instance Digestable StrictByteString where
  digestMany algo chunks = digest' algo $ \update ->
    forM_ chunks $ \chunk ->
      unsafeUseAsCStringLen chunk $ \(ptr,len) ->
        update (castPtr ptr, fromIntegral len)

instance Digestable LazyByteString where
  digestMany algo chunks = digest' algo $ \update ->
    forM_ chunks $ \chunk' ->
      forM_ (Lazy.toChunks chunk') $ \chunk ->
         unsafeUseAsCStringLen chunk $ \(ptr,len) ->
           update (castPtr ptr, fromIntegral len)

-- |We do not define a 'Digestable' instance for 'CStringLen', because there is
-- no one obviously correct way to encode Unicode characters for purposes of
-- calculating a digest. This specialized function is provided for convenience,
-- though. It is implemented on top of 'withCStringLen'. This means that the
-- representation of Unicode characters depends on the process locale
-- configuration a.k.a. it's non-deterministc!

digestCStringLen :: DigestDescription -> CStringLen -> [Word8]
digestCStringLen algo (ptr,len) = digest algo (castPtr ptr :: Ptr (), len)

-- |We do not define a 'Digestable' instance for 'String', because there is no
-- one obviously correct way to encode Unicode characters for purposes of
-- calculating a digest. It would feel silly, though, to offer digest functions
-- for all kinds of types /except/ @String@, so here is a specialized function
-- that computes a digest over a @String@ relying on 'digestCStringLen'.
--
-- >>> digestString (digestByName "sha1") "Hello, world." >>= toHex
-- "2ae01472317d1935a84797ec1983ae243fc6aa28"

digestString :: DigestDescription -> String -> [Word8]
digestString algo str = IO.unsafePerformIO $
  withCStringLen str (return . digestCStringLen algo)

-- Helper functions -----------------------------------------------------------

type StrictByteString = Strict.ByteString

type LazyByteString = Lazy.ByteString

digest' :: DigestDescription -> (((Ptr (), CSize) -> IO ()) -> IO ()) -> [Word8]
digest' algo consumer = IO.unsafePerformIO $
    bracket createContext destroyContext $ \ctx -> do
      initDigest algo ctx
      consumer (uncurry (updateDigest ctx))
      let mdSize = fromIntegral (_digestSize (getDigestDescription algo))
      allocaArray mdSize $ \md -> do
        finalizeDigest ctx md
        peekArray mdSize md

class DigestablePointeeType a
instance DigestablePointeeType ()
instance DigestablePointeeType Word8

class Integral a => DigestableSizeType a
instance DigestableSizeType CSize
instance DigestableSizeType CUInt
instance DigestableSizeType Int
