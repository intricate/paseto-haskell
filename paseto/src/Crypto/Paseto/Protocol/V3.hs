{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}

-- | Implementation of
-- [PASETO version 3](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version3.md)
-- (modern NIST cryptography).
module Crypto.Paseto.Protocol.V3
  ( -- * Local purpose
    v3LocalTokenHeader
  , EncryptionError (..)
  , renderEncryptionError
  , encrypt
  , encryptPure
  , DecryptionError (..)
  , decrypt

    -- * Public purpose
  , v3PublicTokenHeader
  , SigningError (..)
  , sign
  , signPure
  , VerificationError (..)
  , verify
  ) where

import Control.Monad ( unless, when )
import Control.Monad.Except ( ExceptT, liftIO )
import Control.Monad.Trans.Except.Extra ( hoistEither )
import qualified Crypto.Cipher.AES as Crypto
import qualified Crypto.Cipher.Types as Crypto
import qualified Crypto.Error as Crypto
import qualified Crypto.Hash as Crypto
import qualified Crypto.KDF.HKDF as Crypto
import qualified Crypto.MAC.HMAC as Crypto
import Crypto.Paseto.Keys
  ( SigningKey (..)
  , SymmetricKey (..)
  , VerificationKey (..)
  , fromSigningKey
  , verificationKeyToBytes
  )
import Crypto.Paseto.Keys.V3
  ( PrivateKeyP384 (..)
  , PublicKeyP384 (..)
  , generateScalarP384
  , isScalarValidP384
  )
import Crypto.Paseto.Mode ( Purpose (..), Version (..) )
import qualified Crypto.Paseto.PreAuthenticationEncoding as PAE
import Crypto.Paseto.Token
  ( Footer (..), ImplicitAssertion (..), Payload (..), Token (..) )
import Crypto.Paseto.Token.Claims ( Claims )
import qualified Crypto.PubKey.ECC.ECDSA as Crypto
import qualified Crypto.Random as Crypto
import qualified Data.Aeson as Aeson
import Data.Bifunctor ( first )
import Data.Binary.Put ( runPut )
import Data.Binary.Put.Integer ( putIntegerbe )
import Data.Bits ( shiftL, (.|.) )
import qualified Data.ByteArray as BA
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Data.Text ( Text )
import qualified Data.Text as T
import Prelude

maybeToEither :: a -> Maybe b -> Either a b
maybeToEither _ (Just b) = Right b
maybeToEither a Nothing = Left a

------------------------------------------------------------------------------
-- Local purpose
------------------------------------------------------------------------------

v3LocalTokenHeader :: ByteString
v3LocalTokenHeader = "v3.local."

encryptionKeyHkdfInfoPrefix :: ByteString
encryptionKeyHkdfInfoPrefix = "paseto-encryption-key"

authenticationKeyHkdfInfoPrefix :: ByteString
authenticationKeyHkdfInfoPrefix = "paseto-auth-key-for-aead"

mkAes256Cipher :: ByteString -> Either Crypto.CryptoError Crypto.AES256
mkAes256Cipher ek = Crypto.eitherCryptoError (Crypto.cipherInit ek)

-- | PASETO version 3 encryption error.
data EncryptionError
  = -- | 'Crypto.CryptoError' that occurred during encryption.
    EncryptionCryptoError !Crypto.CryptoError
  | -- | Initialization vector is of an invalid size.
    EncryptionInvalidInitializationVectorSizeError
      -- | Expected size.
      !Int
      -- | Actual size.
      !Int
  deriving stock (Show, Eq)

-- | Render an 'EncryptionError' as 'Text'.
renderEncryptionError :: EncryptionError -> Text
renderEncryptionError err =
  case err of
    EncryptionCryptoError e ->
      "Encountered a cryptographic error: " <> T.pack (show e)
    EncryptionInvalidInitializationVectorSizeError expected actual ->
      "Initialization vector length is expected to be "
        <> T.pack (show expected)
        <> ", but it was "
        <> T.pack (show actual)
        <> "."

-- | Pure variant of 'encrypt'.
--
-- For typical usage, please use 'encrypt'.
encryptPure
  :: ByteString
  -- ^ Random 32-byte nonce.
  --
  -- It is recommended to generate this from the operating system's CSPRNG.
  -> SymmetricKey V3
  -- ^ Symmetric key.
  -> Claims
  -- ^ Claims to be encrypted.
  -> Maybe Footer
  -- ^ Optional footer to authenticate and encode within the resulting token.
  -> Maybe ImplicitAssertion
  -- ^ Optional implicit assertion to authenticate.
  -> Either EncryptionError (Token V3 Local)
encryptPure n (SymmetricKeyV3 k) cs f i = do
  let h :: ByteString
      h = v3LocalTokenHeader

      m :: ByteString
      m = BS.toStrict (Aeson.encode cs)

      prk :: Crypto.PRK Crypto.SHA384
      prk = Crypto.extract BS.empty k

      ek :: ByteString
      n2 :: ByteString
      (ek, n2) = BS.splitAt 32 $ Crypto.expand prk (encryptionKeyHkdfInfoPrefix <> n) 48

      ak :: ByteString
      ak = Crypto.expand prk (authenticationKeyHkdfInfoPrefix <> n) 48

  aes256 <- first EncryptionCryptoError (mkAes256Cipher ek)
  iv <-
    maybeToEither
      (EncryptionInvalidInitializationVectorSizeError (Crypto.blockSize aes256) (BS.length n2))
      (Crypto.makeIV n2)
  let c :: ByteString
      c = Crypto.ctrCombine aes256 iv m

      preAuth :: ByteString
      preAuth = PAE.encode [h, n, c, maybe BS.empty unFooter f, maybe BS.empty unImplicitAssertion i]

      t :: Crypto.HMAC Crypto.SHA384
      t = Crypto.hmac ak preAuth

      payload :: Payload
      payload = Payload (n <> c <> BA.convert t)

  pure $ TokenV3Local payload f

-- | [PASETO version 3 encryption](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version3.md#encrypt).
--
-- This is an authenticated encryption with associated data (AEAD)
-- algorithm which combines the @AES-256-CTR@ block cipher with the
-- @HMAC-SHA384@ message authentication code.
--
-- Note that this function essentially just calls 'encryptPure' with a random
-- 32-byte nonce generated from the operating system's CSPRNG.
encrypt
  :: SymmetricKey V3
  -- ^ Symmetric key.
  -> Claims
  -- ^ Claims to be encrypted.
  -> Maybe Footer
  -- ^ Optional footer to authenticate and encode within the resulting token.
  -> Maybe ImplicitAssertion
  -- ^ Optional implicit assertion to authenticate.
  -> ExceptT EncryptionError IO (Token V3 Local)
encrypt k cs f i = do
  n <- liftIO (Crypto.getRandomBytes 32 :: IO ByteString)
  hoistEither (encryptPure n k cs f i)

-- | PASETO version 3 decryption error.
data DecryptionError
  = -- | Invalid token footer.
    DecryptionInvalidFooterError
      -- | Expected footer.
      !(Maybe Footer)
      -- | Actual footer.
      !(Maybe Footer)
  | -- | Invalid @HKDF-HMAC-SHA384@ nonce size.
    DecryptionInvalidHkdfNonceSizeError !Int
  | -- | Invalid @HMAC-SHA384@ message authentication code size.
    DecryptionInvalidHmacSizeError !Int
  | -- | Invalid @HMAC-SHA384@ message authentication code.
    DecryptionInvalidHmacError
      -- | Expected HMAC.
      !ByteString
      -- | Actual HMAC.
      !ByteString
  | -- | 'Crypto.CryptoError' that occurred during decryption.
    DecryptionCryptoError !Crypto.CryptoError
  | -- | Initialization vector is of an invalid size.
    DecryptionInvalidInitializationVectorSizeError
      -- | Invalid initialization vector.
      !ByteString
  | -- | Error deserializing a decrypted collection of claims as JSON.
    DecryptionClaimsDeserializationError !String
  deriving stock (Show, Eq)

-- | [PASETO version 3 decryption](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version3.md#decrypt).
decrypt
  :: SymmetricKey V3
  -- ^ Symmetric key.
  -> Token V3 Local
  -- ^ Token to decrypt.
  -> Maybe Footer
  -- ^ Optional footer to authenticate.
  -> Maybe ImplicitAssertion
  -- ^ Optional implicit assertion to authenticate.
  -> Either DecryptionError Claims
decrypt (SymmetricKeyV3 k) (TokenV3Local (Payload m) actualF) expectedF i = do
  let h :: ByteString
      h = v3LocalTokenHeader

  -- Check that the actual footer matches the provided expected footer.
  when (expectedF /= actualF) (Left $ DecryptionInvalidFooterError expectedF actualF)

  let n :: ByteString
      n = BS.take 32 m

      nLen :: Int
      nLen = BS.length n

      tBs :: ByteString
      tBs = BS.takeEnd 48 m

      mbT :: Maybe (Crypto.HMAC Crypto.SHA384)
      mbT = Crypto.HMAC <$> Crypto.digestFromByteString tBs

      c :: ByteString
      c = BS.dropEnd 48 (BS.drop 32 m)

  when (nLen /= 32) (Left $ DecryptionInvalidHkdfNonceSizeError nLen)

  t <-
    case mbT of
      Nothing -> Left (DecryptionInvalidHmacSizeError $ BS.length tBs)
      Just x -> Right x

  let prk :: Crypto.PRK Crypto.SHA384
      prk = Crypto.extract BS.empty k

      ek :: ByteString
      n2 :: ByteString
      (ek, n2) = BS.splitAt 32 $ Crypto.expand prk (encryptionKeyHkdfInfoPrefix <> n) 48

      ak :: ByteString
      ak = Crypto.expand prk (authenticationKeyHkdfInfoPrefix <> n) 48

      preAuth :: ByteString
      preAuth = PAE.encode [h, n, c, maybe BS.empty unFooter actualF, maybe BS.empty unImplicitAssertion i]

      t2 :: Crypto.HMAC Crypto.SHA384
      t2 = Crypto.hmac ak preAuth

  -- The 'Crypto.HMAC' 'Eq' instance performs a constant-time equality check.
  when (t2 /= t) (Left $ DecryptionInvalidHmacError (BA.convert t2) (BA.convert t))

  aes256 <- first DecryptionCryptoError (mkAes256Cipher ek)
  iv <- maybeToEither (DecryptionInvalidInitializationVectorSizeError n2) (Crypto.makeIV n2)
  let decrypted :: ByteString
      decrypted = Crypto.ctrCombine aes256 iv c

  -- Deserialize the raw decrypted bytes as a JSON object of claims.
  first DecryptionClaimsDeserializationError (Aeson.eitherDecodeStrict decrypted)

------------------------------------------------------------------------------
-- Public purpose
------------------------------------------------------------------------------

v3PublicTokenHeader :: ByteString
v3PublicTokenHeader = "v3.public."

-- | PASETO version 3 cryptographic signing error.
data SigningError
  = -- | Scalar multiple, @k@, is zero.
    SigningScalarMultipleIsZeroError
  deriving (Show, Eq)

-- | Pure variant of 'sign'.
--
-- For typical usage, please use 'sign'.
signPure
  :: Integer
  -- ^ Explicit @k@ scalar.
  -> SigningKey V3
  -- ^ Signing key.
  -> Claims
  -- ^ Claims to be signed.
  -> Maybe Footer
  -- ^ Optional footer to authenticate and encode within the resulting token.
  -> Maybe ImplicitAssertion
  -- ^ Optional implicit assertion to authenticate.
  -> Either SigningError (Token V3 Public)
signPure k signingKey@(SigningKeyV3 (PrivateKeyP384 sk)) cs f i = do
  let h :: ByteString
      h = v3PublicTokenHeader

      m :: ByteString
      m = BS.toStrict (Aeson.encode cs)

      vk :: VerificationKey V3
      vk = fromSigningKey signingKey

      m2 :: ByteString
      m2 = PAE.encode [verificationKeyToBytes vk, h, m, maybe BS.empty unFooter f, maybe BS.empty unImplicitAssertion i]

  sig <-
    maybeToEither
      SigningScalarMultipleIsZeroError
      (Crypto.signWith k sk Crypto.SHA384 m2)
  let r :: Integer
      r = Crypto.sign_r sig

      s :: Integer
      s = Crypto.sign_s sig

      sigBs :: ByteString
      sigBs =
        padTo 48 (BS.toStrict $ runPut (putIntegerbe r))
          <> padTo 48 (BS.toStrict $ runPut (putIntegerbe s))

      payload :: Payload
      payload = Payload (m <> sigBs)

  Right $ TokenV3Public payload f
    where
      padTo :: Int -> ByteString -> ByteString
      padTo n bs
        | n <= 0 = bs
        | BS.length bs >= n = bs
        | otherwise = BS.replicate (n - BS.length bs) 0 <> bs

-- | [PASETO version 3 cryptographic signing](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version3.md#sign).
--
-- This implementation produces a token which is signed using @ECDSA@ over
-- @P-384@ and @SHA-384@.
--
-- Note that this function essentially just calls 'signPure' with a
-- randomly-generated scalar multiple, @k@.
sign
  :: SigningKey V3
  -- ^ Signing key.
  -> Claims
  -- ^ Claims to be signed.
  -> Maybe Footer
  -- ^ Optional footer to authenticate and encode within the resulting token.
  -> Maybe ImplicitAssertion
  -- ^ Optional implicit assertion to authenticate.
  -> ExceptT SigningError IO (Token V3 Public)
sign sk cs f i = do
  k <- liftIO generateScalarP384
  hoistEither (signPure k sk cs f i)

-- | PASETO version 3 signature verification error.
data VerificationError
  = -- | Invalid token footer.
    VerificationInvalidFooterError
      -- | Expected footer.
      !(Maybe Footer)
      -- | Actual footer.
      !(Maybe Footer)
  | -- | Signature size is invalid.
    VerificationInvalidSignatureSizeError
  | -- | Signature verification failed.
    VerificationInvalidSignatureError
  | -- | Error deserializing a verified collection of claims as JSON.
    VerificationClaimsDeserializationError !String
  deriving (Show, Eq)

-- | [PASETO version 3 cryptographic signature verification](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version3.md#verify).
verify
  :: VerificationKey V3
  -- ^ Verification key.
  -> Token V3 Public
  -- ^ Token to verify.
  -> Maybe Footer
  -- ^ Optional footer to authenticate.
  -> Maybe ImplicitAssertion
  -- ^ Optional implicit assertion to authenticate.
  -> Either VerificationError Claims
verify verKey@(VerificationKeyV3 (PublicKeyP384 vk)) (TokenV3Public (Payload sm) actualF) expectedF i = do
  let h :: ByteString
      h = v3PublicTokenHeader

  -- Check that the actual footer matches the provided expected footer.
  when (expectedF /= actualF) (Left $ VerificationInvalidFooterError expectedF actualF)

  let sigBs :: ByteString
      sigBs = BS.takeEnd 96 sm

      rBs :: ByteString
      sBs :: ByteString
      (rBs, sBs) = BS.splitAt 48 sigBs

      r :: Integer
      r = bsToInteger rBs

      s :: Integer
      s = bsToInteger sBs

  sig <- sigFromIntegers (r, s)

  let m :: ByteString
      m = BS.dropEnd 96 sm

      m2 :: ByteString
      m2 = PAE.encode [verificationKeyToBytes verKey, h, m, maybe BS.empty unFooter actualF, maybe BS.empty unImplicitAssertion i]

  unless
    (Crypto.verify Crypto.SHA384 vk sig m2)
    (Left VerificationInvalidSignatureError)

  first VerificationClaimsDeserializationError (Aeson.eitherDecodeStrict m)
  where
    -- Decode a big endian 'Integer' from a 'ByteString'.
    --
    -- Ripped from @haskoin-core-1.1.0@.
    bsToInteger :: ByteString -> Integer
    bsToInteger = BS.foldr f 0 . BS.reverse
      where
        f w n = toInteger w .|. shiftL n 8

    mkValidScalar :: Integer -> Either VerificationError Integer
    mkValidScalar s
      | isScalarValidP384 s = Right s
      | otherwise = Left VerificationInvalidSignatureSizeError

    sigFromIntegers :: (Integer, Integer) -> Either VerificationError Crypto.Signature
    sigFromIntegers (r, s) =
      Crypto.Signature <$> mkValidScalar r <*> mkValidScalar s
