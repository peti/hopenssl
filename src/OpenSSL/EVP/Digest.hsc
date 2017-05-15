{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls #-}

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

#include "openssl/evp.h"

#if __GLASGOW_HASKELL__ < 800
#  let alignment t = "%lu", (unsigned long)offsetof(struct {char x__; t (y__); }, y__)
#endif

-- * Low-level API

-------------------------------------------------------------------------------
-- ** OpenSSL Library Initialization
-------------------------------------------------------------------------------

-- | Initialize the OpenSSL EVP engine and register all known digest types in
-- the internal data structures. This function must be called before
-- '_digestByName' can succeed. Calling it multiple times is probably not
-- harmful, but it certainly unnecessary and should be avoided. Users of
-- 'digestByName'' and 'digestByName' don't have to worry about this.

foreign import ccall unsafe "openssl/evp.h OpenSSL_add_all_digests" _addAllDigests :: IO ()

-------------------------------------------------------------------------------
-- ** Accessing the Supported Digest Types
-------------------------------------------------------------------------------

data OpaqueDigestDescription

-- | Look up a 'Digest' by name. Be sure to call '_addAllDigests' before you
-- use this function.

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
-- There is a 'Storable' solely for the benefit of being able to create that
-- type with 'alloca' and '_init' instead of having to use '_create', which
-- uses the heap. Anyway, that instance does not define 'peek' nor 'poke' since
-- those make no sense.

data OpaqueDigestContext

instance Storable OpaqueDigestContext where
   sizeOf _ = #{size EVP_MD_CTX}
   alignment _ = #{alignment EVP_MD_CTX}
   peek _ = error "Don't do this. OpaqueDigestContext is, like, opaque."
   poke _ _ = error "Don't do this. OpaqueDigestContext is, like, opaque."

-- | Allocate an (initialized) 'OpaqueDigestContext' for use in a digest
-- computation on the heap. Release its underlying memory after use with
-- '_destroy'.

foreign import ccall unsafe "openssl/evp.h EVP_MD_CTX_create" _createContext :: IO (Ptr OpaqueDigestContext)

-- | Initialize an 'OpaqueDigestContext' for use in a digest computation. The
-- type can be allocated on the stack with 'alloca' or on the heap with
-- '_create'.

foreign import ccall unsafe "openssl/evp.h EVP_MD_CTX_init" _initContext :: Ptr OpaqueDigestContext -> IO ()

-- | Release all resources associated with a digest computation's context, but
-- don't release the underlying digest context structure. This allows the context
-- to be re-initiaized for use another computation.

foreign import ccall unsafe "openssl/evp.h EVP_MD_CTX_cleanup" _cleanupContext :: Ptr OpaqueDigestContext -> IO CInt

-- | Release all resources associated with a digest computation's context and the
-- context structure itself. Use this only for context's acquired with '_create'.

foreign import ccall unsafe "openssl/evp.h EVP_MD_CTX_destroy" _destroyContext :: Ptr OpaqueDigestContext -> IO ()

-------------------------------------------------------------------------------
-- ** State of a Digest Computation
-------------------------------------------------------------------------------

-- | Configure the given /initialized/ digest context to use the given message
-- digest algorithm. The third parameter allows developers to choose a specific
-- engine for that digest, too, but these bindings don't support choosing any
-- specific engine, so pass 'nullPtr' here to the default choice determined by
-- OpenSSL.

foreign import ccall unsafe "openssl/evp.h EVP_DigestInit_ex" _initDigest :: Ptr OpaqueDigestContext -> Ptr OpaqueDigestDescription -> Ptr OpaqueDigestEngine -> IO CInt

-- | Hash the given block of memory and update the digest state accordingly.
-- Naturally, this function can be called many times. Then use
-- '_finalizeDigest' to retrieve the actual hash value.

foreign import ccall unsafe "openssl/evp.h EVP_DigestUpdate" _updateDigest :: Ptr OpaqueDigestContext -> Ptr () -> CSize -> IO CInt

-- | Finalize the digest calculation and return the result in the 'Word8' array
-- passed as an argument. Naturally, that array is expected to be large enough
-- to contain the digest. '_digestSize' or 'maxDigestSize' are your friends. If
-- the 'CUInt' pointer is not 'nullPtr', then the actual size of the generated
-- digest is written into that integer. This function does /not/ clean up the
-- digest context; this has to be done with an explicit call to
-- '_cleanupContext' or '_destroyContext'. However, it does invalidate the
-- digest state so that no further calls of '_digestUpdate' can be made without
-- re-initializing the state with '_initDigest' first.

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

digestByName' :: String -> (Maybe DigestDescription)
digestByName' algo = if ptr == nullPtr then Nothing else Just (DigestDescription ptr)
  where ptr = IO.unsafePerformIO $ withCString algo $ \name -> do
                modifyMVar_ isDigestEngineInitialized $ \isInitialized ->
                  when (not isInitialized) _addAllDigests >> return True
                return (_digestByName name)

newtype DigestContext = DigestContext { getDigestContext :: Ptr OpaqueDigestContext }

digestContext :: Ptr OpaqueDigestContext -> DigestContext
digestContext ptr
  | ptr == nullPtr = throw AttemptToConstructDigestContextFromNullPointer
  | otherwise      = DigestContext ptr

initContext :: DigestContext -> IO ()
initContext (DigestContext ctx) = _initContext ctx

createContext :: IO DigestContext
createContext =
  fmap DigestContext (throwIfNull "OpenSSL.EVP.Digest.createContext failed" _createContext)

-- | Simplified variant of '_initDigest' that (a) always chooses the default
-- digest engine and (b) reports failure by means of an exception.

initDigest :: DigestDescription -> DigestContext -> IO ()
initDigest (DigestDescription algo) (DigestContext ctx) =
  throwIfZero "OpenSSL.EVP.Digest.initDigest" (_initDigest ctx algo nullPtr)

cleanupContext :: DigestContext -> IO ()
cleanupContext (DigestContext ctx) =
  throwIfZero "OpenSSL.EVP.Digest.cleanupContext" (_cleanupContext ctx)

destroyContext :: DigestContext -> IO ()
destroyContext (DigestContext ctx) = _destroyContext ctx

updateDigest :: DigestContext -> Ptr () -> CSize -> IO ()
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

-- |Neat helper to print digests with:
-- @
--   \\ws :: [Word8] -> ws >>= toHex
-- @

toHex :: Word8 -> String
toHex w = case showHex w "" of
            w1:w2:[] -> w1:w2:[]
            w2:[]    -> '0':w2:[]
            _        -> error "showHex returned []"

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
