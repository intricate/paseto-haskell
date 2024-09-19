{-# LANGUAGE TemplateHaskell #-}

module Test.Crypto.Paseto.Token.Claim
  ( tests
  ) where

import Control.Monad ( void )
import Crypto.Paseto.Token.Claim
  ( ClaimKey (..)
  , mkUnregisteredClaimKey
  , parseClaimKey
  , renderClaimKey
  , renderUnregisteredClaimKey
  )
import Hedgehog
  ( Property
  , checkParallel
  , discover
  , evalMaybe
  , forAll
  , property
  , tripping
  , (===)
  )
import Prelude
import Test.Crypto.Paseto.Token.Claim.Gen
  ( genClaimKey, genUnregisteredClaimKey )

tests :: IO Bool
tests = checkParallel $$(discover)

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

-- | Test that 'renderClaimKey' and 'parseClaimKey' round trip.
prop_roundTrip_renderParseClaimKey :: Property
prop_roundTrip_renderParseClaimKey = property $ do
  k <- forAll genClaimKey
  tripping k renderClaimKey (Just . parseClaimKey)

-- | Test that 'renderUnregisteredClaimKey' and 'mkUnregisteredClaimKey' round
-- trip.
prop_roundTrip_renderMkUnregisteredClaimKey :: Property
prop_roundTrip_renderMkUnregisteredClaimKey = property $ do
  k <- forAll genUnregisteredClaimKey
  tripping k renderUnregisteredClaimKey mkUnregisteredClaimKey

-- | Test that it isn't possible to construct an 'UnregisteredClaimKey' that
-- is a registered/reserved claim key.
prop_unregisteredClaimKeyCannotBeRegistered :: Property
prop_unregisteredClaimKeyCannotBeRegistered = property $ do
  k <- forAll genClaimKey
  case k of
    CustomClaimKey _ ->
      -- @k@ is a custom/unregistered claim key, so we should be able to render
      -- it and successfully re-construct an 'UnregisteredClaimKey'.
      void $ evalMaybe (mkUnregisteredClaimKey $ renderClaimKey k)
    _ ->
      -- @k@ is a registered claim key, so we shouldn't be able to render it
      -- and construct an 'UnregisteredClaimKey'.
      Nothing === mkUnregisteredClaimKey (renderClaimKey k)
