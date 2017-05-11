{- |
   Module      :  OpenSSL.Digest.ByteString
   Copyright   :  (c) 2010 by Peter Simons
   License     :  BSD3

   Maintainer  :  simons@cryp.to
   Stability   :  provisional
   Portability :  portable

   Wrappers for "OpenSSL.Digest" that supports 'ByteString'.
 -}

module OpenSSL.Digest.ByteString where

import OpenSSL.Digest hiding ( update )
import Control.Monad.State ( evalStateT, lift, get )
import Foreign.Ptr ( castPtr )
import Data.Word ( Word8 )
import Data.ByteString ( ByteString )
import Data.ByteString.Unsafe ( unsafeUseAsCStringLen )

-- |A convenience wrapper which computes the given digest type of a
-- 'ByteString'. Unlike the monadic interface, this function does not
-- allow the computation to be restarted.

digest :: MessageDigest -> ByteString -> IO [Word8]
digest mdType xs =
  mkDigest mdType $ evalStateT (update xs >> final)

-- |Update the internal state with a block of data.

update :: ByteString -> Digest Int
update bs = do
    DST ctx <- get
    l <- lift $
      unsafeUseAsCStringLen bs $ \(ptr, len) ->
        digestUpdate ctx (castPtr ptr) (fromIntegral len)
    return (fromEnum l)
