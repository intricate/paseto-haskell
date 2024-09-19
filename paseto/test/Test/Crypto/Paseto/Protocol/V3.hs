{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE TemplateHaskell #-}

module Test.Crypto.Paseto.Protocol.V3
  ( tests
  ) where

import Crypto.Paseto.Keys ( SigningKey (..), SymmetricKey (..), fromSigningKey )
import Crypto.Paseto.Mode ( Purpose (..), Version (..) )
import Crypto.Paseto.Protocol.V3 ( decrypt, encryptPure, signPure, verify )
import Crypto.Paseto.Token
  ( Footer (..), ImplicitAssertion, Payload (..), Token (..) )
import Crypto.Paseto.Token.Claims ( Claims )
import Data.ByteString ( ByteString )
import Hedgehog
  ( Property, checkParallel, discover, forAll, forAllWith, property, tripping )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude
import Test.Crypto.Paseto.Keys.Gen ( genSigningKeyV3, genSymmetricKeyV3 )
import Test.Crypto.Paseto.Keys.V3.Gen ( genScalarP384 )
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
  k <- forAllWith unsafeRenderSymmetricKey genSymmetricKeyV3
  claims <- forAll $ genClaims
  f <- forAll $ Gen.maybe genFooter
  i <- forAll $ Gen.maybe genImplicitAssertion
  tripping claims (\cs -> unsafeEncryptPure n k cs f i) (\t -> decrypt k t f i)
  where
    unsafeEncryptPure
      :: ByteString
      -> SymmetricKey V3
      -> Claims
      -> Maybe Footer
      -> Maybe ImplicitAssertion
      -> Token V3 Local
    unsafeEncryptPure n k cs f i =
      case encryptPure n k cs f i of
        Left err -> error $ "impossible: could not encrypt: " <> show err
        Right encrypted -> encrypted

-- | Test that 'signPure' (a pure variant of 'sign') and 'verify' round trip.
prop_roundTrip_signVerify :: Property
prop_roundTrip_signVerify = property$ do
  k <- forAll genScalarP384
  sk <- forAllWith unsafeRenderSigningKey genSigningKeyV3
  let vk = fromSigningKey sk
  claims <- forAll $ genClaims
  f <- forAll $ Gen.maybe genFooter
  i <- forAll $ Gen.maybe genImplicitAssertion
  tripping claims (\cs -> unsafeSignPure k sk cs f i) (\t -> verify vk t f i)
  where
    unsafeSignPure
      :: Integer
      -> SigningKey V3
      -> Claims
      -> Maybe Footer
      -> Maybe ImplicitAssertion
      -> Token V3 Public
    unsafeSignPure k sk cs f i =
      case signPure k sk cs f i of
        Left err -> error $ "impossible: could not sign: " <> show err
        Right signed -> signed

prop_golden_TokenV3Local :: Property
prop_golden_TokenV3Local = goldenTestPaseto goldenTokenV3Local "test/golden/paseto/v3-local/golden"

prop_golden_TokenV3Public :: Property
prop_golden_TokenV3Public = goldenTestPaseto goldenTokenV3Public "test/golden/paseto/v3-public/golden"

------------------------------------------------------------------------------
-- Golden examples
------------------------------------------------------------------------------

goldenTokenV3Local :: Token V3 Local
goldenTokenV3Local =
  TokenV3Local
    (Payload "&\247U3TH*\GS\145\212xF'\133K\141\166\184\EOT*yfR<+@N\141\187\231\247\242\240c\191/Bp\218\138\223\144\250\200\225\ETB\207\GS\ESC`t_\238\SI\220G1\CANy\252\195\&3\219N\186\142lxr\160\170c\203w0e\f\203v,\DC1\177\209\n\229 \239\151M\191\RS5\138%m\168\168c\SO@\153\146xC)\132E\135\139\vC(\151\237\131\141N\212_\aj\223\188\145\SI6d\128\f\SYN\169\&1\246\174U\145iqfG\189g3\SOHm\189\217\157\250")
    (Just (Footer "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}"))

goldenTokenV3Public :: Token V3 Public
goldenTokenV3Public =
  TokenV3Public
    (Payload "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}\190\182\171OKA>\233\139\177Hy\136\145\131\f~\236\"C\228\213\245\188\DC2>\145\218?\188\140\RS\235\146@\137\200B\177p\195O'\152\203\186\179\239e,\209t\182\254!\175\216\217\133\218\189\142\251\197\178\243%\STXd\ETX\252\227%\230+w\201\150Cn(:\153-\179P\172\179u\218\239\135\&3\254=\192")
    Nothing

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
