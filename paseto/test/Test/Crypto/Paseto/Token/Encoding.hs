{-# LANGUAGE TemplateHaskell #-}

module Test.Crypto.Paseto.Token.Encoding
  ( tests
  ) where

import Crypto.Paseto.Token.Encoding ( encode, encodeSomeToken )
import Crypto.Paseto.Token.Parser
  ( parseSomeToken
  , parseTokenV3Local
  , parseTokenV3Public
  , parseTokenV4Local
  , parseTokenV4Public
  )
import Hedgehog
  ( Property, checkParallel, discover, forAll, property, tripping )
import Prelude
import Test.Crypto.Paseto.Token.Gen
  ( genSomeToken
  , genTokenV3Local
  , genTokenV3Public
  , genTokenV4Local
  , genTokenV4Public
  )

tests :: IO Bool
tests = checkParallel $$(discover)

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

-- | Test that 'encode' and 'parseTokenV3Local' round trip.
prop_roundTrip_encodeParseTokenV3Local :: Property
prop_roundTrip_encodeParseTokenV3Local = property $ do
  token <- forAll genTokenV3Local
  tripping token encode parseTokenV3Local

-- | Test that 'encode' and 'parseTokenV3Public' round trip.
prop_roundTrip_encodeParseTokenV3Public :: Property
prop_roundTrip_encodeParseTokenV3Public = property $ do
  token <- forAll genTokenV3Public
  tripping token encode parseTokenV3Public

-- | Test that 'encode' and 'parseTokenV4Local' round trip.
prop_roundTrip_encodeParseTokenV4Local :: Property
prop_roundTrip_encodeParseTokenV4Local = property $ do
  token <- forAll genTokenV4Local
  tripping token encode parseTokenV4Local

-- | Test that 'encode' and 'parseTokenV4Public' round trip.
prop_roundTrip_encodeParseTokenV4Public :: Property
prop_roundTrip_encodeParseTokenV4Public = property $ do
  token <- forAll genTokenV4Public
  tripping token encode parseTokenV4Public

-- | Test that 'encodeSomeToken' and 'parseSomeToken' round trip.
prop_roundTrip_encodeParseSomeToken :: Property
prop_roundTrip_encodeParseSomeToken = property $ do
  token <- forAll genSomeToken
  tripping token encodeSomeToken parseSomeToken
