module Test.Crypto.Paseto.ScrubbedBytes.Gen
  ( genScrubbedBytes32
  ) where

import Crypto.Paseto.ScrubbedBytes ( ScrubbedBytes32, mkScrubbedBytes32 )
import Hedgehog ( Gen )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude

genScrubbedBytes32 :: Gen (ScrubbedBytes32)
genScrubbedBytes32 = do
  bs <- Gen.bytes (Range.singleton 32)
  case mkScrubbedBytes32 bs of
    Nothing -> fail "failed to generate a ScrubbedBytes32"
    Just x -> pure x
