{-# LANGUAGE TemplateHaskell #-}

module Test.Crypto.Paseto.Keys.V3
  ( tests
  ) where

import Crypto.Paseto.Keys.V3
  ( decodePrivateKeyP384
  , decodePublicKeyP384
  , encodePrivateKeyP384
  , encodePublicKeyP384
  )
import Hedgehog
  ( Property, checkParallel, discover, forAll, property, tripping )
import Prelude
import Test.Crypto.Paseto.Keys.V3.Gen ( genKeyPairP384 )

tests :: IO Bool
tests = checkParallel $$(discover)

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

-- | Test that 'encodePrivateKeyP384' and 'decodePrivateKeyP384' round trip.
prop_roundTrip_encodeDecodePrivateKeyP384 :: Property
prop_roundTrip_encodeDecodePrivateKeyP384 = property $ do
  (_, privKey) <- forAll genKeyPairP384
  tripping privKey encodePrivateKeyP384 decodePrivateKeyP384

-- | Test that 'encodePublicKeyP384' and 'decodePublicKeyP384' round trip.
prop_roundTrip_encodeDecodePublicKeyP384 :: Property
prop_roundTrip_encodeDecodePublicKeyP384 = property $ do
  (pubKey, _) <- forAll genKeyPairP384
  tripping pubKey encodePublicKeyP384 decodePublicKeyP384
