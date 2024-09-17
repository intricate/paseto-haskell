module Test.Crypto.Paseto.TestVectors
  ( Base16ByteString (..)
  , LocalTestVector (..)
  , PublicTestVector (..)
  , TestVector (..)
  , TestVectors (..)
  , mkV3TestVectorProperties
  , mkV4TestVectorProperties
  ) where

import Control.Monad.Except ( ExceptT, runExceptT )
import Control.Monad.Trans.Except.Extra ( left )
import Crypto.Paseto.Keys
  ( bytesToSymmetricKeyV3
  , bytesToSymmetricKeyV4
  , bytesToVerificationKeyV3
  , bytesToVerificationKeyV4
  )
import Crypto.Paseto.Token ( Footer (..), ImplicitAssertion (..) )
import Crypto.Paseto.Token.Encoding
  ( ValidatedToken (..)
  , decodeAndValidateTokenV3Local
  , decodeAndValidateTokenV3Public
  , decodeAndValidateTokenV4Local
  , decodeAndValidateTokenV4Public
  )
import Data.Aeson ( FromJSON (..), withObject, withText, (.:), (.:?) )
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Types as Aeson
import Data.ByteArray ( ByteArrayAccess )
import qualified Data.ByteArray as BA
import Data.ByteString ( ByteString )
import qualified Data.ByteString.Base16 as B16
import Data.Text ( Text )
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Hedgehog ( PropertyT, (===) )
import Prelude

emptyToNothing :: (ByteString -> a) -> ByteString -> Maybe a
emptyToNothing _ "" = Nothing
emptyToNothing f bs = Just (f bs)

data ExpectedFailure = ExpectedFailure

handlePropertyWithExpectedFailure
  :: PropertyT IO (Either ExpectedFailure ())
  -> PropertyT IO ()
handlePropertyWithExpectedFailure prop = do
  res <- prop
  case res of
    Left ExpectedFailure -> pure ()
    Right () -> pure ()

-- | 'ByteString' that was decoded from base16-encoded text.
newtype Base16ByteString = Base16ByteString
  { unBase16ByteString :: ByteString }
  deriving newtype (Show, Eq, ByteArrayAccess)

instance FromJSON Base16ByteString where
  parseJSON = withText "Base16ByteString" $ \t ->
    case B16.decode (TE.encodeUtf8 t) of
      Left err -> fail $ "error decoding text as base16: " <> err
      Right x -> pure (Base16ByteString x)

-- | Test vector for a local PASETO token.
data LocalTestVector = LocalTestVector
  { ltvName :: !Text
  , ltvExpectFail :: !Bool
  , ltvKey :: !Base16ByteString
  , ltvNonce :: !Base16ByteString
  , ltvToken :: !Text
  , ltvPayload :: !(Maybe Text)
  , ltvFooter :: !(Maybe Footer)
  , ltvImplicitAssertion :: !(Maybe ImplicitAssertion)
  } deriving stock (Show, Eq)

instance FromJSON LocalTestVector where
  parseJSON = withObject "LocalTestVector" $ \v ->
    LocalTestVector
      <$> v .: "name"
      <*> v .: "expect-fail"
      <*> v .: "key"
      <*> v .: "nonce"
      <*> v .: "token"
      <*> v .: "payload"
      <*> (emptyToNothing Footer . TE.encodeUtf8 <$> v .: "footer")
      <*> (emptyToNothing ImplicitAssertion . TE.encodeUtf8 <$> v .: "implicit-assertion")

mkV3LocalTestVectorProperty :: LocalTestVector -> (String, PropertyT IO ())
mkV3LocalTestVectorProperty ltv =
  (T.unpack ltvName, handlePropertyWithExpectedFailure (runExceptT mkProp))
  where
    LocalTestVector
      { ltvName
      , ltvKey
      , ltvToken
      , ltvPayload
      , ltvFooter
      , ltvImplicitAssertion
      } = ltv

    mkProp :: ExceptT ExpectedFailure (PropertyT IO) ()
    mkProp = do
      key <-
        case bytesToSymmetricKeyV3 (BA.convert ltvKey) of
          Nothing -> fail "invalid version 3 symmetric key"
          Just k -> pure k

      case decodeAndValidateTokenV3Local key [] ltvFooter ltvImplicitAssertion ltvToken of
        Left err ->
          case ltvPayload of
            Nothing -> left ExpectedFailure
            Just _ -> fail $ "invalid version 3 local token (" <> T.unpack ltvToken <> "): " <> show err
        Right ValidatedToken{ vtClaims } ->
          case ltvPayload of
            Nothing -> fail "expected token decoding failure"
            Just expectedPayload -> do
              expectedClaims <-
                case Aeson.eitherDecodeStrict (TE.encodeUtf8 expectedPayload) of
                  Left err -> fail $ "invalid claims payload: " <> show err
                  Right x -> pure x
              expectedClaims === vtClaims

mkV4LocalTestVectorProperty :: LocalTestVector -> (String, PropertyT IO ())
mkV4LocalTestVectorProperty ltv =
  (T.unpack ltvName, handlePropertyWithExpectedFailure (runExceptT mkProp))
  where
    LocalTestVector
      { ltvName
      , ltvKey
      , ltvToken
      , ltvPayload
      , ltvFooter
      , ltvImplicitAssertion
      } = ltv

    mkProp :: ExceptT ExpectedFailure (PropertyT IO) ()
    mkProp = do
      key <-
        case bytesToSymmetricKeyV4 (BA.convert ltvKey) of
          Nothing -> fail "invalid version 4 symmetric key"
          Just k -> pure k

      case decodeAndValidateTokenV4Local key [] ltvFooter ltvImplicitAssertion ltvToken of
        Left err ->
          case ltvPayload of
            Nothing -> left ExpectedFailure
            Just _ -> fail $ "invalid version 4 local token (" <> T.unpack ltvToken <> "): " <> show err
        Right ValidatedToken{ vtClaims } ->
          case ltvPayload of
            Nothing -> fail "expected token decoding failure"
            Just expectedPayload -> do
              expectedClaims <-
                case Aeson.eitherDecodeStrict (TE.encodeUtf8 expectedPayload) of
                  Left err -> fail $ "invalid claims payload: " <> show err
                  Right x -> pure x
              expectedClaims === vtClaims

-- | Test vector for a public PASETO token.
data PublicTestVector = PublicTestVector
  { ptvName :: !Text
  , ptvExpectFail :: !Bool
  , ptvPublicKey :: !Base16ByteString
  , ptvSecretKey :: !Base16ByteString
  , ptvPublicKeyPem :: !Text
  , ptvSecretKeyPem :: !Text
  , ptvToken :: !Text
  , ptvPayload :: !(Maybe Text)
  , ptvFooter :: !(Maybe Footer)
  , ptvImplicitAssertion :: !(Maybe ImplicitAssertion)
  } deriving stock (Show, Eq)

instance FromJSON PublicTestVector where
  parseJSON = withObject "PublicTestVector" $ \v ->
    PublicTestVector
      <$> v .: "name"
      <*> v .: "expect-fail"
      <*> v .: "public-key"
      <*> v .: "secret-key"
      <*> v .: "public-key-pem"
      <*> v .: "secret-key-pem"
      <*> v .: "token"
      <*> v .: "payload"
      <*> (emptyToNothing Footer . TE.encodeUtf8 <$> v .: "footer")
      <*> (emptyToNothing ImplicitAssertion . TE.encodeUtf8 <$> v .: "implicit-assertion")

mkV3PublicTestVectorProperty :: PublicTestVector -> (String, PropertyT IO ())
mkV3PublicTestVectorProperty ptv =
  (T.unpack ptvName, handlePropertyWithExpectedFailure (runExceptT mkProp))
  where
    PublicTestVector
      { ptvName
      , ptvPublicKey
      , ptvToken
      , ptvPayload
      , ptvFooter
      , ptvImplicitAssertion
      } = ptv

    mkProp :: ExceptT ExpectedFailure (PropertyT IO) ()
    mkProp = do
      vk <-
        case bytesToVerificationKeyV3 (unBase16ByteString ptvPublicKey) of
          Left err -> fail $ "invalid version 3 verification key: " <> show err
          Right k -> pure k

      case decodeAndValidateTokenV3Public vk [] ptvFooter ptvImplicitAssertion ptvToken of
        Left err ->
          case ptvPayload of
            Nothing -> left ExpectedFailure
            Just _ -> fail $ "invalid version 3 public token (" <> T.unpack ptvToken <> "): " <> show err
        Right ValidatedToken{ vtClaims } ->
          case ptvPayload of
            Nothing -> fail "expected token decoding failure"
            Just expectedPayload -> do
              expectedClaims <-
                case Aeson.eitherDecodeStrict (TE.encodeUtf8 expectedPayload) of
                  Left err -> fail $ "invalid claims payload: " <> show err
                  Right x -> pure x
              expectedClaims === vtClaims

mkV4PublicTestVectorProperty :: PublicTestVector -> (String, PropertyT IO ())
mkV4PublicTestVectorProperty ptv =
  (T.unpack ptvName, handlePropertyWithExpectedFailure (runExceptT mkProp))
  where
    PublicTestVector
      { ptvName
      , ptvPublicKey
      , ptvToken
      , ptvPayload
      , ptvFooter
      , ptvImplicitAssertion
      } = ptv

    mkProp :: ExceptT ExpectedFailure (PropertyT IO) ()
    mkProp = do
      vk <-
        case bytesToVerificationKeyV4 (unBase16ByteString ptvPublicKey) of
          Nothing -> fail "invalid version 4 verification key"
          Just k -> pure k

      case decodeAndValidateTokenV4Public vk [] ptvFooter ptvImplicitAssertion ptvToken of
        Left err ->
          case ptvPayload of
            Nothing -> left ExpectedFailure
            Just _ -> fail $ "invalid version 4 public token (" <> T.unpack ptvToken <> "): " <> show err
        Right ValidatedToken{ vtClaims } ->
          case ptvPayload of
            Nothing -> fail "expected token decoding failure"
            Just expectedPayload -> do
              expectedClaims <-
                case Aeson.eitherDecodeStrict (TE.encodeUtf8 expectedPayload) of
                  Left err -> fail $ "invalid claims payload: " <> show err
                  Right x -> pure x
              expectedClaims === vtClaims

-- | Test vector.
data TestVector
  = -- | Test vector for a local PASETO token.
    TestVectorLocal !LocalTestVector
  | -- | Test vector for a public PASETO token.
    TestVectorPublic !PublicTestVector
  deriving stock (Show, Eq)

instance FromJSON TestVector where
  parseJSON v = withObject "TestVector" f v
    where
      f o = do
        symmetricKey <- o .:? "key" :: Aeson.Parser (Maybe Base16ByteString)
        case symmetricKey of
          Just _ -> TestVectorLocal <$> parseJSON v
          Nothing -> TestVectorPublic <$> parseJSON v

mkV3TestVectorProperty :: TestVector -> (String, PropertyT IO ())
mkV3TestVectorProperty tv =
  case tv of
    TestVectorLocal ltv -> mkV3LocalTestVectorProperty ltv
    TestVectorPublic ptv -> mkV3PublicTestVectorProperty ptv

mkV4TestVectorProperty :: TestVector -> (String, PropertyT IO ())
mkV4TestVectorProperty tv =
  case tv of
    TestVectorLocal ltv -> mkV4LocalTestVectorProperty ltv
    TestVectorPublic ptv -> mkV4PublicTestVectorProperty ptv

-- | List of 'TestVector's.
newtype TestVectors = TestVectors
  { unTestVectors :: [TestVector] }
  deriving newtype (Show, Eq)

instance FromJSON TestVectors where
  parseJSON = withObject "TestVectors" $ \v -> do
    TestVectors <$> v .: "tests"

mkV3TestVectorProperties :: TestVectors -> [(String, PropertyT IO ())]
mkV3TestVectorProperties = map mkV3TestVectorProperty . unTestVectors

mkV4TestVectorProperties :: TestVectors -> [(String, PropertyT IO ())]
mkV4TestVectorProperties = map mkV4TestVectorProperty . unTestVectors
