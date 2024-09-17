module Data.Binary.Put.Integer
  ( putIntegerbe
  ) where

import Data.Binary.Put ( Put, putByteString )
import Data.Bits ( shiftR )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Data.Word ( Word8 )
import Prelude

-- | Encode an 'Integer' to a 'ByteString' as big endian.
--
-- Ripped from [haskoin-core-1.1.0](https://hackage.haskell.org/package/haskoin-core-1.1.0/docs/src/Haskoin.Util.Helpers.html#integerToBS).
integerToBS :: Integer -> ByteString
integerToBS 0 = BS.pack [0]
integerToBS i
  | i > 0 = BS.reverse $ BS.unfoldr f i
  | otherwise = error "integerToBS not defined for negative values"
  where
    f 0 = Nothing
    f x = Just (fromInteger x :: Word8, x `shiftR` 8)

-- | Write an 'Integer' in big endian format
putIntegerbe :: Integer -> Put
putIntegerbe = putByteString . integerToBS
{-# INLINE putIntegerbe #-}
