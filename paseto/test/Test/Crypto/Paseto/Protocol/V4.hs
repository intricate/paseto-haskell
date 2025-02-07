{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE TemplateHaskell #-}

module Test.Crypto.Paseto.Protocol.V4
  ( tests
  ) where

import Crypto.Paseto.Keys ( SigningKey (..), SymmetricKey (..), fromSigningKey )
import Crypto.Paseto.Mode ( Purpose (..), Version (..) )
import Crypto.Paseto.Protocol.V4 ( decrypt, encryptPure, sign, verify )
import Crypto.Paseto.Token ( Footer (..), Payload (..), Token (..) )
import Hedgehog
  ( Property, checkParallel, discover, forAll, forAllWith, property, tripping )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude
import Test.Crypto.Paseto.Keys.Gen ( genSigningKeyV4, genSymmetricKeyV4 )
import Test.Crypto.Paseto.Token.Claims.Gen ( genClaims )
import Test.Crypto.Paseto.Token.Gen ( genFooter, genImplicitAssertion )
import Test.Golden ( goldenTestPaseto )

tests :: IO Bool
tests = checkParallel $$(discover)

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

-- | Test that 'encryptPure' (a pure variant of 'encrypt') and 'decrypt' round
-- trip.
prop_roundTrip_encryptDecrypt :: Property
prop_roundTrip_encryptDecrypt = property $ do
  n <- forAll $ Gen.bytes (Range.singleton 32)
  k <- forAllWith unsafeRenderSymmetricKey genSymmetricKeyV4
  claims <- forAll $ genClaims
  f <- forAll $ Gen.maybe genFooter
  i <- forAll $ Gen.maybe genImplicitAssertion
  tripping claims (\cs -> encryptPure n k cs f i) (\t -> decrypt k t f i)

-- | Test that 'signPure' (a pure variant of 'sign') and 'verify' round trip.
prop_roundTrip_signVerify :: Property
prop_roundTrip_signVerify = property $ do
  sk <- forAllWith unsafeRenderSigningKey genSigningKeyV4
  let vk = fromSigningKey sk
  claims <- forAll $ genClaims
  f <- forAll $ Gen.maybe genFooter
  i <- forAll $ Gen.maybe genImplicitAssertion
  tripping claims (\cs -> sign sk cs f i) (\t -> verify vk t f i)

prop_golden_TokenV4Local :: Property
prop_golden_TokenV4Local = goldenTestPaseto goldenTokenV4Local "test/golden/paseto/v4-local/golden.txt"

prop_golden_TokenV4Public :: Property
prop_golden_TokenV4Public = goldenTestPaseto goldenTokenV4Public "test/golden/paseto/v4-public/golden.txt"

------------------------------------------------------------------------------
-- Golden examples
------------------------------------------------------------------------------

goldenTokenV4Local :: Token V4 Local
goldenTokenV4Local =
  TokenV4Local
    (Payload "\223eH\DC2\186\196\146f8%R\v\162\246\230|\245\202[\220\DC3\212\231Pz\152\204L/\204:\216\192\226H\170\195\191\237q\163\140\228cDrt\241\151\173\SYN\136\SI+w| \NAK#[\253GI=x\233\206m\n[\218#3\151\248;i\145\188M\136s\a\143\248\244]\160x\221\231\228G\n!1GR\n\234\222\169Y 9\GS}\176\141\189\207\251\DC2\208\131\146\185}\229\STX_\131\246~\149J\221\146\214\NAK\179\DC2\197")
    (Just (Footer "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}"))

goldenTokenV4Public :: Token V4 Public
goldenTokenV4Public =
  TokenV4Public
    (Payload "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}\191rm\242l\DELM\211\&6q\228\198\162\172+\135\140\131\SYN}\ETB\176{\239W\240\244\SO\220\DLE\197Z\201\DLE\DC3%\208]\156h\a`\158\146\165\183\138{\196\EM\241\212w\SO\249#\232\240S\233\219^\a\SI")
    (Just (Footer "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}"))

------------------------------------------------------------------------------
-- Helpers
------------------------------------------------------------------------------

unsafeRenderSymmetricKey :: SymmetricKey v -> String
unsafeRenderSymmetricKey k =
  case k of
    SymmetricKeyV3 bs -> "SymmetricKeyV3 " <> show bs
    SymmetricKeyV4 bs -> "SymmetricKeyV4 " <> show bs

unsafeRenderSigningKey :: SigningKey v -> String
unsafeRenderSigningKey sk =
  case sk of
    SigningKeyV3 k -> "SigningKeyV3 " <> show k
    SigningKeyV4 bs -> "SigningKeyV4 " <> show bs
