{- |
   Module      :  OpenSSL.Digest.ByteString.Lazy
   Copyright   :  (c) 2010 by Peter Simons
   License     :  BSD3

   Maintainer  :  simons@cryp.to
   Stability   :  provisional
   Portability :  portable

   Wrappers for "OpenSSL.Digest" that supports lazy 'ByteString'.
 -}

module OpenSSL.Digest.ByteString.Lazy where

import OpenSSL.Digest hiding ( update )
import Data.Word ( Word8 )
import Control.Monad.State ( evalStateT )
import qualified OpenSSL.Digest.ByteString as BS ( update )
import Data.ByteString.Lazy ( ByteString, toChunks )

-- |A convenience wrapper which computes the given digest type of a
-- 'ByteString'. Unlike the monadic interface, this function does not
-- allow the computation to be restarted.

digest :: MessageDigest -> ByteString -> IO [Word8]
digest mdType xs =
  mkDigest mdType $ evalStateT (update xs >> final)

-- |Update the internal state with a block of data.

update :: ByteString -> Digest Int
update = fmap sum . mapM BS.update . toChunks

-- ----- Configure Emacs -----
--
-- Local Variables: ***
-- haskell-program-name: "ghci -ignore-package hopenssl -Wall -lcrypto" ***
-- End: ***
