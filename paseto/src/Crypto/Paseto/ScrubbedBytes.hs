{-# LANGUAGE DataKinds #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ViewPatterns #-}

module Crypto.Paseto.ScrubbedBytes
  ( ScrubbedBytes32 (ScrubbedBytes32)
  , mkScrubbedBytes32
  , fromSizedBytes
  , toBytes
  , toSizedBytes
  , generateScrubbedBytes32
  ) where

import Basement.NormalForm ( NormalForm )
import Control.DeepSeq ( NFData (..) )
import qualified Crypto.Random as Crypto
import Data.ByteArray ( ByteArrayAccess, ScrubbedBytes )
import qualified Data.ByteArray as BA
import Data.ByteArray.Sized
  ( ByteArrayN (..), SizedByteArray, sizedByteArray, unSizedByteArray )
import Prelude

-- | Simple wrapper around a 32-byte (256-bit) 'ScrubbedBytes' value.
--
-- Note that this type's 'Eq' instance performs a constant-time equality check.
newtype ScrubbedBytes32 = MkScrubbedBytes32
  { unScrubbedBytes32 :: SizedByteArray 32 ScrubbedBytes }
  deriving newtype (Show, Eq, Ord, NormalForm, ByteArrayAccess)

instance NFData ScrubbedBytes32 where
  rnf (MkScrubbedBytes32 bs) = rnf (unSizedByteArray bs)

instance ByteArrayN 32 ScrubbedBytes32 where
  allocRet p f = do
    (a, ba) <- allocRet p f
    pure (a, MkScrubbedBytes32 ba)

pattern ScrubbedBytes32 :: ScrubbedBytes -> ScrubbedBytes32
pattern ScrubbedBytes32 bs <- (unSizedByteArray . unScrubbedBytes32 -> bs)

{-# COMPLETE ScrubbedBytes32 #-}

-- | Construct a 32-byte (256-bit) 'ScrubbedBytes' value from an array of
-- bytes.
mkScrubbedBytes32 :: ByteArrayAccess b => b -> Maybe ScrubbedBytes32
mkScrubbedBytes32 = (MkScrubbedBytes32 <$>) . sizedByteArray . BA.convert

-- | Construct a 'ScrubbedBytes32' value from a 'SizedByteArray' of
-- 'ScrubbedBytes'.
fromSizedBytes :: SizedByteArray 32 ScrubbedBytes -> ScrubbedBytes32
fromSizedBytes bs = MkScrubbedBytes32 bs

-- | Convert a 'ScrubbedBytes32' value to 'ScrubbedBytes'.
toBytes :: ScrubbedBytes32 -> ScrubbedBytes
toBytes (ScrubbedBytes32 bs) = bs

-- | Convert a 'ScrubbedBytes32' value to a 'SizedByteArray' of
-- 'ScrubbedBytes'.
toSizedBytes :: ScrubbedBytes32 -> SizedByteArray 32 ScrubbedBytes
toSizedBytes (MkScrubbedBytes32 bs) = bs

-- | Randomly generate a 'ScrubbedBytes32' value.
generateScrubbedBytes32 :: IO ScrubbedBytes32
generateScrubbedBytes32 = do
  bs <- Crypto.getRandomBytes 32 :: IO ScrubbedBytes
  case mkScrubbedBytes32 bs of
    Just x -> pure x
    Nothing -> error "generateScrubbedBytes32: impossible: failed to randomly generate 32 bytes"
