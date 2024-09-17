{-# LANGUAGE DataKinds #-}

module Test.Crypto.Paseto.Keys.Gen
  ( genSymmetricKeyV3
  , genSigningKeyV3
  , genSymmetricKeyV4
  , genSigningKeyV4
  ) where

import qualified Crypto.Error as Crypto
import Crypto.Paseto.Keys ( SigningKey (..), SymmetricKey (..) )
import Crypto.Paseto.Mode ( Version (..) )
import qualified Crypto.PubKey.Ed25519 as Crypto.Ed25519
import Hedgehog ( Gen )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude
import Test.Crypto.Paseto.Keys.V3.Gen ( genPrivateKeyP384 )
import Test.Crypto.Paseto.ScrubbedBytes.Gen ( genScrubbedBytes32 )

genSymmetricKeyV3 :: Gen (SymmetricKey V3)
genSymmetricKeyV3 =
  SymmetricKeyV3 <$> genScrubbedBytes32

genSigningKeyV3 :: Gen (SigningKey V3)
genSigningKeyV3 =
  SigningKeyV3 <$> genPrivateKeyP384

genSymmetricKeyV4 :: Gen (SymmetricKey V4)
genSymmetricKeyV4 =
  SymmetricKeyV4 <$> genScrubbedBytes32

genSigningKeyV4 :: Gen (SigningKey V4)
genSigningKeyV4 = do
  bs <- Gen.bytes (Range.singleton 32)
  case Crypto.eitherCryptoError (Crypto.Ed25519.secretKey bs) of
    Left err -> fail $ "could not generate a secret key: " <> show err
    Right x -> pure (SigningKeyV4 x)
