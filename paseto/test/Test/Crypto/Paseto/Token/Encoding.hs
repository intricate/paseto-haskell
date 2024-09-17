{-# LANGUAGE TemplateHaskell #-}

module Test.Crypto.Paseto.Token.Encoding
  ( tests
  ) where

import Crypto.Paseto.Token.Encoding ( encodeSomeToken )
import Crypto.Paseto.Token.Parser ( parseSomeToken )
import Hedgehog
  ( Property, checkParallel, discover, forAll, property, tripping )
import Prelude
import Test.Crypto.Paseto.Token.Gen ( genSomeToken )

tests :: IO Bool
tests = checkParallel $$(discover)

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

-- | Test that 'encodeSomeToken' and 'parseSomeToken' round trip.
prop_roundTrip_encodeParse :: Property
prop_roundTrip_encodeParse = property $ do
  token <- forAll genSomeToken
  tripping token encodeSomeToken parseSomeToken
