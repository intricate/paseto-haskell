module Test.Crypto.Paseto.Keys.V3.Gen
  ( genScalarP384
  , genPrivateKeyP384
  , genKeyPairP384
  , genPointCompression
  ) where

import Crypto.Paseto.Keys.V3
  ( PointCompression (..)
  , PrivateKeyP384
  , PublicKeyP384
  , curveP384
  , fromPrivateKeyP384
  , isScalarValidP384
  , mkPrivateKeyP384
  )
import qualified Crypto.PubKey.ECC.ECDSA as Crypto
import qualified Crypto.PubKey.ECC.Types as Crypto
import Hedgehog ( Gen )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude

-- | Generate a valid scalar value for curve P384.
genScalarP384 :: Gen Integer
genScalarP384 =
  Gen.filter isScalarValidP384 (Gen.integral (Range.constant 1 (n - 1)))
  where
    n :: Integer
    n = Crypto.ecc_n (Crypto.common_curve curveP384)

-- | Generate a 'PrivateKeyP384'.
genPrivateKeyP384 :: Gen PrivateKeyP384
genPrivateKeyP384 = do
  s <- genScalarP384
  case mkPrivateKeyP384 (Crypto.PrivateKey curveP384 s) of
    Nothing -> fail "Failed to generate a scalar value"
    Just x -> pure x

genKeyPairP384 :: Gen (PublicKeyP384, PrivateKeyP384)
genKeyPairP384 = toKeyPair <$> genPrivateKeyP384
  where
    toKeyPair privateKey = (fromPrivateKeyP384 privateKey, privateKey)

genPointCompression :: Gen PointCompression
genPointCompression = Gen.element [PointCompressed, PointUncompressed]
