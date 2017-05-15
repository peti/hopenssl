{-# LANGUAGE FlexibleInstances #-}

{- |
   Maintainer:  simons@cryp.to
   Stability:   provisional
   Portability: portable

   This module provides a generic high-level API to the message digest
   algorithms found in OpenSSL's @crypto@ library. There are two functions of
   particular interest: 'digestByName' and 'digest'. The former can be used to
   retrieve a 'DigestDescription', i.e. an OpenSSL object that implements a
   particular algorithm. That type can then be used to compute actual message
   digests:

   >>> import Data.ByteString.Char8 ( pack )
   >>> digest (digestByName "md5") (pack "Hello, world.")
   [8,10,239,131,155,149,250,207,115,236,89,147,117,233,45,71]

   Neat pretty-printing can be achieved by running @'concatMap' 'toHex'@ over
   the @[Word8]@ fingerprint returned by 'digest':

   >>> digest (digestByName "md5") (pack "Hello, world.") >>= toHex
   "080aef839b95facf73ec599375e92d47"
   >>> digest (digestByName "sha1") (pack "Hello, world.") >>= toHex
   "2ae01472317d1935a84797ec1983ae243fc6aa28"

   The precise set of available digest algorithms provided by OpenSSL depends
   on the version of the library installed into the system, obviously, but it's
   reasonable to expect the following algorithms to be present: MD5, RIPEMD160,
   SHA1, SHA224, SHA256, SHA384, and SHA512. If an algorithm is not available,
   'digestByName' will throw an 'DigestAlgorithmNotAvailableInOpenSSL'
   exception. If you don't like exceptions, use the tamer 'digestByName''
   variant:

   >>> digestByName' "i bet this algorithm won't exist"
   Nothing

   'DigestDescription' is an instance of 'IsString', so with the proper GHC
   extensions installed it's possible to simplify the call to 'digest' even
   further:

   >>> :set -XOverloadedStrings
   >>> digest "sha256" (pack "this can be simplified further") >>= toHex
   "727311383e8fcc55da1f3b5a0afb6051b39e9cae3a72c89df3f4b40ce45f0a9a"

   Last but not least, 'digest' is actually a class method of 'Digestable',
   which collects things we can compute digests of. The defaults are
   conservative, i.e. we support all things that correspond roughly to C's
   construct of "void pointer plus a length". @digest@ can use with any of the
   following signatures:

   >>> shape1 = digest :: DigestDescription -> (Ptr (),    CSize) -> [Word8]
   >>> shape2 = digest :: DigestDescription -> (Ptr Word8, CSize) -> [Word8]
   >>> shape3 = digest :: DigestDescription -> (Ptr Word8, CUInt) -> [Word8]
   >>> shape4 = digest :: DigestDescription -> (Ptr (),    Int)   -> [Word8]
   >>> shape5 = digest :: DigestDescription -> StrictByteString   -> [Word8]
   >>> shape6 = digest :: DigestDescription -> LazyByteString     -> [Word8]

   'StrictByteString' and 'LazyByteString' are also instances of 'IsString' and
   therefore subject to implicit construction from string literals:

   >>> shape5 "sha256" "hello" == shape6 "sha256" "hello"
   True

   What we /don't/ offer are overloaded 'digest' versions for 'String' or
   'CString'. These types produce non-deterministic results for Unicode strings
   because their exact binary representation depends on the system's locale.
   For those who absolutely want to hash 'String', the following specialized
   function is provided:

   >>> digestString "md5" "no Digestable instance for this sucker" >>= toHex
   "a74827f849005794565f83fbd68ad189"

   If you don't mind orphaned instances, however, feel free to shoot yourself
   in the foot:

   >>> :set -XFlexibleInstances
   >>> :{
        instance Digestable String where
          digestMany algo chunks = digest' algo $ \update ->
            forM_ chunks $ \chunk ->
              withCStringLen chunk $ \(ptr,len) ->
                update (castPtr ptr, fromIntegral len)
       :}

   Now 'digest' works with 'String's:

   >>> digest "sha256" ("now we can hash strings"::String) >>= toHex
   "7f2989f173125810aa917c4ffe0e26ae1b5f7fb852274829c210297a43dfc7f9"
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
