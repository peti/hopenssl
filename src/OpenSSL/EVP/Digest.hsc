{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE DeriveDataTypeable #-}

{- |
   Maintainer:  simons@cryp.to
   Stability:   provisional
   Portability: portable

   Computing message digests with OpenSSL's EVP interface involves the
   following types:

    * Every digest algorithm has an description, 'OpaqueDigestDescription' that
      can be looked up by name. We can do very few things with that type. We
      can use it to retrieve the size of the algorithm's output, '_digestSize'

    * TODO: complete this when I know what the high-level API looks like.

-}

module OpenSSL.EVP.Digest where

import Control.Concurrent.MVar
import Control.Exception
import Control.Monad
import Data.Maybe
import Data.String ( IsString(..) )
import Data.Typeable ( Typeable )
import Foreign
import Foreign.C
import Numeric ( showHex )
import System.IO.Unsafe as IO

#include "openssl/opensslv.h"
#include "openssl/evp.h"

#if __GLASGOW_HASKELL__ < 800
#  let alignment t = "%lu", (unsigned long)offsetof(struct {char x__; t (y__); }, y__)
#endif

-- * Low-level API

#if OPENSSL_VERSION_NUMBER < 0x1010000f
-------------------------------------------------------------------------------
-- ** OpenSSL Library Initialization
-------------------------------------------------------------------------------

-- | Initialize the OpenSSL EVP engine and register all known digest types in
-- the internal data structures. This function must be called before
-- '_digestByName' can succeed. Calling it multiple times is probably not
-- harmful, but it certainly unnecessary and should be avoided. Users of
-- 'digestByName'' and 'digestByName' don't have to worry about this.

foreign import ccall unsafe "openssl/evp.h OpenSSL_add_all_digests" _addAllDigests :: IO ()
#endif

-------------------------------------------------------------------------------
-- ** Accessing the Supported Digest Types
-------------------------------------------------------------------------------

data OpaqueDigestDescription

-- | Look up a 'Digest' by name.
#if OPENSSL_VERSION_NUMBER < 0x1010000f
-- Be sure to call '_addAllDigests' before you use this function.
#endif

foreign import ccall unsafe "openssl/evp.h EVP_get_digestbyname" _digestByName :: CString -> Ptr OpaqueDigestDescription

-- | Return the size of the digest the given algorithm will produce.

foreign import ccall unsafe "openssl/evp.h EVP_MD_size" _digestSize :: Ptr OpaqueDigestDescription -> CInt

-- | Return the block size the the given algorithm operates with.

foreign import ccall unsafe "openssl/evp.h EVP_MD_block_size" _digestBlockSize :: Ptr OpaqueDigestDescription -> CInt

-- | The largest possible digest size of any of the algorithms supported by
-- this library. So if you want to store a digest without bothering to retrieve
-- the appropriate size with '_digestSize' first, allocate a buffer of that
-- size.

maxDigestSize :: Int
maxDigestSize = #{const EVP_MAX_MD_SIZE}

-- | We don't support choosing specific engines. Always pass 'nullPtr' where
-- such a thing is expected to get the default engine for the given algorithm.

data OpaqueDigestEngine

-------------------------------------------------------------------------------
-- ** Digest Contexts
-------------------------------------------------------------------------------

-- | A context in which -- when initialized -- digest computations can be run.
-- Use '_newContext' and '_freeContext' to allocate/deallocate this type.

data OpaqueDigestContext

-- | Allocate and initialize an 'OpaqueDigestContext' for use in a digest
-- computation on the heap. Release its underlying memory after use with
-- '_freeContext'.

foreign import ccall unsafe
#if OPENSSL_VERSION_NUMBER < 0x1010000f
  "openssl/evp.h EVP_MD_CTX_create"
#else
  "openssl/evp.h EVP_MD_CTX_new"
#endif
  _newContext :: IO (Ptr OpaqueDigestContext)

#if OPENSSL_VERSION_NUMBER >= 0x1010000f
-- | Re-initialize a previously created 'OpaqueDigestContext' for use in a new
-- digest computation.

foreign import ccall unsafe "openssl/evp.h EVP_MD_CTX_reset" _resetContext :: Ptr OpaqueDigestContext -> IO ()
#endif

-- | Release all resources associated with a digest computation's context and
-- the context structure itself. Use this only for context's acquired with
-- '_newContext'.

foreign import ccall unsafe
#if OPENSSL_VERSION_NUMBER < 0x1010000f
  "openssl/evp.h EVP_MD_CTX_destroy"
#else
  "openssl/evp.h EVP_MD_CTX_free"
#endif
  _freeContext :: Ptr OpaqueDigestContext -> IO ()

-------------------------------------------------------------------------------
-- ** State of a Digest Computation
-------------------------------------------------------------------------------

-- | Configure the given digest context to use the given message digest
-- algorithm. The third parameter allows developers to choose a specific engine
-- for that digest, too, but these bindings don't support choosing any specific
-- engine, so pass 'nullPtr' here to the default choice determined by OpenSSL.

foreign import ccall unsafe "openssl/evp.h EVP_DigestInit_ex" _initDigest :: Ptr OpaqueDigestContext -> Ptr OpaqueDigestDescription -> Ptr OpaqueDigestEngine -> IO CInt

-- | Hash the given block of memory and update the digest state accordingly.
-- Naturally, this function can be called many times. Then use
-- '_finalizeDigest' to retrieve the actual hash value.

foreign import ccall unsafe "openssl/evp.h EVP_DigestUpdate" _updateDigest :: Ptr OpaqueDigestContext -> Ptr a -> CSize -> IO CInt

-- | Finalize the digest calculation and return the result in the 'Word8' array
-- passed as an argument. Naturally, that array is expected to be large enough
-- to contain the digest. '_digestSize' or 'maxDigestSize' are your friends. If
-- the 'CUInt' pointer is not 'nullPtr', then the actual size of the generated
-- digest is written into that integer. This function does /not/ clean up the
-- digest context; this has to be done with an explicit call to '_freeContext'.
-- However, it does invalidate the digest state so that no further calls of
-- '_digestUpdate' can be made without re-initializing the state with
-- '_resetDigest' first.

foreign import ccall unsafe "openssl/evp.h EVP_DigestFinal_ex" _finalizeDigest :: Ptr OpaqueDigestContext -> Ptr Word8 -> Ptr CUInt -> IO CInt

-------------------------------------------------------------------------------
-- * High-level interface
-------------------------------------------------------------------------------

newtype DigestDescription = DigestDescription { getDigestDescription :: Ptr OpaqueDigestDescription }
  deriving (Show, Eq)

digestByName :: String -> DigestDescription
digestByName algo =
  fromMaybe (throw (DigestAlgorithmNotAvailableInOpenSSL algo))
            (digestByName' algo)

digestByName' :: String -> Maybe DigestDescription
digestByName' algo = if ptr == nullPtr then Nothing else Just (DigestDescription ptr)
  where ptr = IO.unsafePerformIO $ withCString algo $ \name -> do
#if OPENSSL_VERSION_NUMBER < 0x1010000f
                modifyMVar_ isDigestEngineInitialized $ \isInitialized ->
                  unless isInitialized _addAllDigests >> return True
#endif
                return (_digestByName name)

newtype DigestContext = DigestContext { getDigestContext :: Ptr OpaqueDigestContext }

digestContext :: Ptr OpaqueDigestContext -> DigestContext
digestContext ptr
  | ptr == nullPtr = throw AttemptToConstructDigestContextFromNullPointer
  | otherwise      = DigestContext ptr

#if OPENSSL_VERSION_NUMBER >= 0x1010000f
resetContext :: DigestContext -> IO ()
resetContext (DigestContext ctx) = _resetContext ctx
#endif

newContext :: IO DigestContext
newContext =
  fmap DigestContext (throwIfNull "OpenSSL.EVP.Digest.newContext failed" _newContext)

-- | Simplified variant of '_initDigest' that (a) always chooses the default
-- digest engine and (b) reports failure by means of an exception.

initDigest :: DigestDescription -> DigestContext -> IO ()
initDigest (DigestDescription algo) (DigestContext ctx) =
  throwIfZero "OpenSSL.EVP.Digest.initDigest" (_initDigest ctx algo nullPtr)

freeContext :: DigestContext -> IO ()
freeContext (DigestContext ctx) = _freeContext ctx

updateDigest :: DigestContext -> Ptr a -> CSize -> IO ()
updateDigest (DigestContext ctx) ptr len =
  throwIfZero "OpenSSL.EVP.Digest.updateDigest" (_updateDigest ctx ptr len)

finalizeDigest :: DigestContext -> Ptr Word8 -> IO ()
finalizeDigest (DigestContext ctx) ptr =
  throwIfZero "OpenSSL.EVP.Digest.finalizeDigest" (_finalizeDigest ctx ptr nullPtr)

-- * Helper Types and Functions

-- | Most OpenSSL functions return an approximation of @Bool@ to signify
-- failure. This wrapper makes it easier to move the error handling to the
-- exception layer where appropriate.

throwIfZero :: String -> IO CInt -> IO ()
throwIfZero fname =
  throwIf_ (==0) (const (showString fname " failed with error code 0"))

-- |Neat helper to pretty-print digests into the common hexadecimal notation:
--
-- >>> [0..15] >>= toHex
-- "000102030405060708090a0b0c0d0e0f"

toHex :: Word8 -> String
toHex w = case showHex w "" of
           [w1,w2] -> [w1, w2]
           [w2]    -> ['0', w2]
           _       -> "showHex returned []"

{-# NOINLINE isDigestEngineInitialized #-}
isDigestEngineInitialized :: MVar Bool
isDigestEngineInitialized = IO.unsafePerformIO $ newMVar False

-- | This instance allows the compiler to translate the string @"sha256"@ into
-- @digestByName "sha256"@ whenever a 'String' is passed in a location that
-- expects a 'DigestDescription'. If that digest engine does not exist, then an
-- exception is thrown. This feature requires the @OverloadedStrings@ extension
-- enabled.

instance IsString DigestDescription where
  fromString = digestByName

-- | A custom exception type which is thrown by 'digestByName' in case the
-- requested digest algorithm is not available in the OpenSSL system library.

newtype DigestAlgorithmNotAvailableInOpenSSL = DigestAlgorithmNotAvailableInOpenSSL String
  deriving (Show, Typeable)

instance Exception DigestAlgorithmNotAvailableInOpenSSL

-- | A custom exception type thrown by 'digestContext' if the function is used
-- to construct a 'DigestContext' from a 'nullPtr'.

data AttemptToConstructDigestContextFromNullPointer = AttemptToConstructDigestContextFromNullPointer
  deriving (Show, Typeable)

instance Exception AttemptToConstructDigestContextFromNullPointer
