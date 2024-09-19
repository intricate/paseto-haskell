module Test.Crypto.Paseto.Token.Claims.Gen
  ( genClaims
  , genNonEmptyClaims
  ) where

import Crypto.Paseto.Token.Claims ( Claims, fromList )
import Hedgehog ( Gen )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude
import Test.Crypto.Paseto.Token.Claim.Gen ( genClaim )

genClaims :: Gen Claims
genClaims = fromList <$> Gen.list (Range.constant 0 32) genClaim

genNonEmptyClaims :: Gen Claims
genNonEmptyClaims = fromList <$> Gen.list (Range.constant 1 32) genClaim
