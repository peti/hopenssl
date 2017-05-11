{-# LANGUAGE ForeignFunctionInterface #-}

{- |
   Module      :  OpenSSL.Digest
   Copyright   :  (c) 2014 by Peter Simons
   License     :  BSD3

   Maintainer  :  simons@cryp.to
   Stability   :  provisional
   Portability :  portable

   This module proivdes a high-level API to the message
   digest algorithms found in OpenSSL's @crypto@ library.
   Link with @-lcrypto@ when using this module.

   Here is a short example program which runs all available
   digests on a string:

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

module OpenSSL.Digest where

import Control.Exception ( bracket )
import Foreign
import Foreign.C
import Control.Monad.State
import Numeric ( showHex )

-- * High-level API

-- |The message digest algorithms we support.

data MessageDigest
  = Null         -- ^ 0 bit
  | MD5          -- ^ 128 bit
  | SHA          -- ^ 160 bit
  | SHA1         -- ^ 160 bit
  | DSS          -- ^ other name for SHA1
  | DSS1         -- ^ other name for SHA1
  | RIPEMD160    -- ^ 160 bit
  | MDC2         -- ^ 128 bit
  | SHA224       -- ^ 224 bit
  | SHA256       -- ^ 256 bit
  | SHA384       -- ^ 384 bit
  | SHA512       -- ^ 512 bit
  deriving (Show, Eq, Enum, Bounded)

-- |A convenience wrapper which computes the given digest
-- over a list of 'Word8'. Unlike the monadic interface,
-- this function does not allow the computation to be
-- restarted.

digest :: MessageDigest -> [Word8] -> IO [Word8]
digest mdType xs =
  mkDigest mdType $ evalStateT (update xs >> final)

-- |A monadic interface to the digest computation.

type Digest a = StateT DigestState IO a

-- |The internal EVP context.

newtype DigestState = DST (Ptr OpaqueContext)

-- |Run an 'IO' computation with an initialized
-- 'DigestState'. All resources will be freed when the
-- computation returns.

mkDigest :: MessageDigest -> (DigestState -> IO a) -> IO a
mkDigest mdType f =
  bracket ctxCreate ctxDestroy $ \ctx -> do
    when (ctx == nullPtr) (fail "Digest.mkDigest: ctxCreate failed")
    md <- toMDEngine mdType
    when (md == nullPtr) (fail ("Digest.mkDigest: can't access "++show mdType))
    rc <- digestInit ctx md
    when (rc == 0) (fail ("Digest.mkDigest: can't initialize "++show mdType))
    f (DST ctx)

-- |Update the internal state with a block of data. This
-- function is just a wrapper for 'update'', which creates
-- an array in memory using 'withArray'.

update :: [Word8] -> Digest ()
update xs = do
  st <- get
  liftIO $
    withArray xs $ \p ->
      evalStateT (update' (p, length xs)) st

-- |Update the internal state with a block of data from
-- memory. This is the /faster/ version of 'update'.

update' :: (Ptr Word8, Int) -> Digest ()
update' (p,n) = do
  DST ctx <- get
  rc <- liftIO $ digestUpdate ctx p (toEnum (fromEnum n))
  when (rc == 0) (fail "Digest.update failed")

-- |Wrap up the computation, add padding, do whatever has to
-- be done, and return the final hash. The length of the
-- result depends on the chosen 'MessageDigest'. Do not call
-- more than once!

final :: Digest [Word8]
final = do
  DST ctx <- get
  liftIO $
    allocaArray maxMDSize $ \p ->
      allocaArray (sizeOf (undefined :: CUInt)) $ \i -> do
        rc <- digestFinal ctx p i
        when (rc == 0) (fail "Digest.Final failed")
        i' <- peek i
        peekArray (fromEnum i') p

-- * Low-level API

-- |The EVP context used by OpenSSL is opaque for us; we
-- only access it through a 'Ptr'.

data OpaqueContext = OpaqueContext
type Context = Ptr OpaqueContext

-- |The message digest engines are opaque for us as well.

data OpaqueMDEngine = OpaqueMDEngine
type MDEngine = Ptr OpaqueMDEngine

-- |Maximum size of all message digests supported by
-- OpenSSL. Allocate a buffer of this size for 'digestFinal'
-- if you want to stay generic.

maxMDSize :: Int
maxMDSize = 36

-- |Create an EVP context. May be 'nullPtr'.

foreign import ccall unsafe "EVP_MD_CTX_create" ctxCreate ::
  IO Context

-- |Initialize an EVP context.

foreign import ccall unsafe "EVP_MD_CTX_init" ctxInit ::
  Context -> IO ()

-- |Destroy an EVP context and free the allocated resources.

foreign import ccall unsafe "EVP_MD_CTX_destroy" ctxDestroy ::
  Context -> IO ()

-- |Set the message digest engine for 'digestUpdate' calls.
-- Returns @\/=0@ in case of an error.

foreign import ccall unsafe "EVP_DigestInit" digestInit ::
  Context -> MDEngine -> IO CInt

-- |Update the internal context with a block of input.
-- Returns @\/=0@ in case of an error.

foreign import ccall unsafe "EVP_DigestUpdate" digestUpdate ::
  Context -> Ptr Word8 -> CUInt -> IO CInt

-- |Wrap up the digest computation and return the final
-- digest. Do not call repeatedly on the same context!
-- Returns @\/=0@ in case of an error. The pointer to the
-- unsigned integer may be 'nullPtr'. If it is not,
-- 'digestFinal' will store the length of the computed
-- digest there.

foreign import ccall unsafe "EVP_DigestFinal" digestFinal ::
  Context -> Ptr Word8 -> Ptr CUInt -> IO CInt

-- ** Message Digest Engines

foreign import ccall unsafe "EVP_dss"       mdDSS       :: IO MDEngine
foreign import ccall unsafe "EVP_dss1"      mdDSS1      :: IO MDEngine
foreign import ccall unsafe "EVP_md5"       mdMD5       :: IO MDEngine
foreign import ccall unsafe "EVP_md_null"   mdNull      :: IO MDEngine
foreign import ccall unsafe "EVP_mdc2"      mdMDC2      :: IO MDEngine
foreign import ccall unsafe "EVP_ripemd160" mdRIPEMD160 :: IO MDEngine
foreign import ccall unsafe "EVP_sha"       mdSHA       :: IO MDEngine
foreign import ccall unsafe "EVP_sha1"      mdSHA1      :: IO MDEngine
foreign import ccall unsafe "EVP_sha224"    mdSHA224    :: IO MDEngine
foreign import ccall unsafe "EVP_sha256"    mdSHA256    :: IO MDEngine
foreign import ccall unsafe "EVP_sha384"    mdSHA384    :: IO MDEngine
foreign import ccall unsafe "EVP_sha512"    mdSHA512    :: IO MDEngine

-- |Map a 'MessageDigest' type into the the corresponding
-- 'MDEngine'.

toMDEngine :: MessageDigest -> IO MDEngine
toMDEngine Null      = mdNull
toMDEngine MD5       = mdMD5
toMDEngine SHA       = mdSHA
toMDEngine SHA1      = mdSHA1
toMDEngine DSS       = mdDSS
toMDEngine DSS1      = mdDSS1
toMDEngine RIPEMD160 = mdRIPEMD160
toMDEngine MDC2      = mdMDC2
toMDEngine SHA224    = mdSHA224
toMDEngine SHA256    = mdSHA256
toMDEngine SHA384    = mdSHA384
toMDEngine SHA512    = mdSHA512

-- * Helper Functions

-- |Neat helper to print digests with:
-- @
--   \\ws :: [Word8] -> ws >>= toHex
-- @

toHex :: Word8 -> String
toHex w = case showHex w "" of
            w1:w2:[] -> w1:w2:[]
            w2:[]    -> '0':w2:[]
            _        -> error "showHex returned []"
