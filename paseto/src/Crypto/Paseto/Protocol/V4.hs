{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}

-- | Implementation of
-- [PASETO version 4](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version4.md)
-- (modern [Sodium](https://doc.libsodium.org/) cryptography).
--
-- Note that we're not actually using @libsodium@ itself in this module but,
-- instead, the equivalent algorithm implementations that are available in
-- @crypton@.
module Crypto.Paseto.Protocol.V4
  ( -- * Local purpose
    v4LocalTokenHeader
  , encrypt
  , encryptPure
  , DecryptionError (..)
  , renderDecryptionError
  , decrypt

    -- * Public purpose
  , v4PublicTokenHeader
  , sign
  , VerificationError (..)
  , renderVerificationError
  , verify
  ) where

import Control.Monad ( unless, when )
import qualified Crypto.Cipher.ChaCha as Crypto
import qualified Crypto.Error as Crypto
import qualified Crypto.Hash as Crypto
import qualified Crypto.MAC.KeyedBlake2 as Crypto
import Crypto.Paseto.Keys
  ( SigningKey (..), SymmetricKey (..), VerificationKey (..) )
import Crypto.Paseto.Mode ( Purpose (..), Version (..) )
import qualified Crypto.Paseto.PreAuthenticationEncoding as PAE
import Crypto.Paseto.Token
  ( Footer (..), ImplicitAssertion (..), Payload (..), Token (..) )
import Crypto.Paseto.Token.Claims ( Claims )
import qualified Crypto.PubKey.Ed25519 as Crypto
import qualified Crypto.Random as Crypto
import qualified Data.Aeson as Aeson
import Data.Bifunctor ( first )
import qualified Data.ByteArray as BA
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Text ( Text )
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Prelude

------------------------------------------------------------------------------
-- Local purpose
------------------------------------------------------------------------------

v4LocalTokenHeader :: ByteString
v4LocalTokenHeader = "v4.local."

encryptionKeyHkdfInfoPrefix :: ByteString
encryptionKeyHkdfInfoPrefix = "paseto-encryption-key"

authenticationKeyHkdfInfoPrefix :: ByteString
authenticationKeyHkdfInfoPrefix = "paseto-auth-key-for-aead"

-- | Pure variant of 'encrypt'.
--
-- For typical usage, please use 'encrypt'.
encryptPure
  :: ByteString
  -- ^ Random 32-byte nonce.
  --
  -- It is recommended to generate this from the operating system's CSPRNG.
  -> SymmetricKey V4
  -- ^ Symmetric key.
  -> Claims
  -- ^ Claims to be encrypted.
  -> Maybe Footer
  -- ^ Optional footer to authenticate and encode within the resulting token.
  -> Maybe ImplicitAssertion
  -- ^ Optional implicit assertion to authenticate.
  -> Token V4 Local
encryptPure n (SymmetricKeyV4 k) cs f i =
  let h :: ByteString
      h = v4LocalTokenHeader

      m :: ByteString
      m = BS.toStrict (Aeson.encode cs)

      tmp :: Crypto.KeyedBlake2 (Crypto.Blake2b 448)
      tmp = Crypto.keyedBlake2 k (encryptionKeyHkdfInfoPrefix <> n)

      ek :: ByteString
      n2 :: ByteString
      (ek, n2) = BS.splitAt 32 $ BA.convert tmp

      ak :: Crypto.KeyedBlake2 (Crypto.Blake2b 256)
      ak = Crypto.keyedBlake2 k (authenticationKeyHkdfInfoPrefix <> n)

      xChaCha20St :: Crypto.State
      xChaCha20St = Crypto.initializeX 20 ek n2

      c :: ByteString
      (c, _) = Crypto.combine xChaCha20St m

      preAuth :: ByteString
      preAuth = PAE.encode [h, n, c, maybe BS.empty unFooter f, maybe BS.empty unImplicitAssertion i]

      t :: Crypto.KeyedBlake2 (Crypto.Blake2b 256)
      t = Crypto.keyedBlake2 (BA.convert ak :: ByteString) preAuth

      payload :: Payload
      payload = Payload (n <> c <> BA.convert t)

  in TokenV4Local payload f

-- | [PASETO version 4 encryption](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version4.md#encrypt).
--
-- This is an authenticated encryption with associated data (AEAD)
-- algorithm which combines the @XChaCha20@ stream cipher with the @Blake2b@
-- message authentication code.
--
-- Note that this function essentially just calls 'encryptPure' with a random
-- 32-byte nonce generated from the operating system's CSPRNG.
encrypt
  :: SymmetricKey V4
  -- ^ Symmetric key.
  -> Claims
  -- ^ Claims to be encrypted.
  -> Maybe Footer
  -- ^ Optional footer to authenticate and encode within the resulting token.
  -> Maybe ImplicitAssertion
  -- ^ Optional implicit assertion to authenticate.
  -> IO (Token V4 Local)
encrypt k cs f i = do
  n <- Crypto.getRandomBytes 32
  pure (encryptPure n k cs f i)

-- | PASETO version 4 decryption error.
data DecryptionError
  = -- | Invalid token footer.
    DecryptionInvalidFooterError
      -- | Expected footer.
      !(Maybe Footer)
      -- | Actual footer.
      !(Maybe Footer)
  | -- | Invalid nonce size.
    DecryptionInvalidNonceSizeError !Int
  | -- | Invalid @Blake2b@ message authentication code size.
    DecryptionInvalidMacSizeError !Int
  | -- | Invalid @Blake2b@ message authenticartion code.
    DecryptionInvalidMacError
      -- | Expected MAC.
      !ByteString
      -- | Actual MAC.
      !ByteString
  | -- | Error deserializing a decrypted collection of claims as JSON.
    DecryptionClaimsDeserializationError !String
  deriving stock (Show, Eq)

-- | Render a 'DecryptionError' as 'Text'.
renderDecryptionError :: DecryptionError -> Text
renderDecryptionError err =
  case err of
    DecryptionInvalidFooterError _ _ ->
      -- Since a footer could potentially be very long or some kind of
      -- illegible structured data, we're not going to attempt to render those
      -- values here.
      "Token has an invalid footer."
    DecryptionInvalidNonceSizeError actual ->
      "Expected nonce with a size of 32, but it was "
        <> T.pack (show actual)
        <> "."
    DecryptionInvalidMacSizeError actual ->
      "Expected MAC with a size of 32, but it was "
        <> T.pack (show actual)
        <> "."
    DecryptionInvalidMacError expected actual ->
      "Expected MAC value of "
        <> TE.decodeUtf8 (B16.encode expected)
        <> ", but encountered "
        <> TE.decodeUtf8 (B16.encode actual)
        <> "."
    DecryptionClaimsDeserializationError e ->
      "Error deserializing claims from JSON: " <> T.pack (show e)

-- | [PASETO version 4 decryption](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version4.md#decrypt).
decrypt
  :: SymmetricKey V4
  -- ^ Symmetric key.
  -> Token V4 Local
  -- ^ Token to decrypt.
  -> Maybe Footer
  -- ^ Optional footer to authenticate.
  -> Maybe ImplicitAssertion
  -- ^ Optional implicit assertion to authenticate.
  -> Either DecryptionError Claims
decrypt (SymmetricKeyV4 k) (TokenV4Local (Payload m) actualF) expectedF i = do
  let h :: ByteString
      h = v4LocalTokenHeader

  -- Check that the actual footer matches the provided expected footer.
  when (expectedF /= actualF) (Left $ DecryptionInvalidFooterError expectedF actualF)

  let n :: ByteString
      n = BS.take 32 m

      nLen :: Int
      nLen = BS.length n

      tBs :: ByteString
      tBs = BS.takeEnd 32 m

      mbT :: Maybe (Crypto.KeyedBlake2 (Crypto.Blake2b 256))
      mbT = Crypto.KeyedBlake2 <$> Crypto.digestFromByteString tBs

      c :: ByteString
      c = BS.dropEnd 32 (BS.drop 32 m)

  when (nLen /= 32) (Left $ DecryptionInvalidNonceSizeError nLen)

  t <-
    case mbT of
      Nothing -> Left (DecryptionInvalidMacSizeError $ BS.length tBs)
      Just x -> Right x

  let tmp :: Crypto.KeyedBlake2 (Crypto.Blake2b 448)
      tmp = Crypto.keyedBlake2 k (encryptionKeyHkdfInfoPrefix <> n)

      ek :: ByteString
      n2 :: ByteString
      (ek, n2) = BS.splitAt 32 $ BA.convert tmp

      ak :: Crypto.KeyedBlake2 (Crypto.Blake2b 256)
      ak = Crypto.keyedBlake2 k (authenticationKeyHkdfInfoPrefix <> n)

      preAuth :: ByteString
      preAuth = PAE.encode [h, n, c, maybe BS.empty unFooter actualF, maybe BS.empty unImplicitAssertion i]

      t2 :: Crypto.KeyedBlake2 (Crypto.Blake2b 256)
      t2 = Crypto.keyedBlake2 (BA.convert ak :: ByteString) preAuth

  -- The 'Crypto.KeyedBlake2' 'Eq' instance performs a constant-time equality check.
  when (t2 /= t) (Left $ DecryptionInvalidMacError (BA.convert t2) (BA.convert t))

  let xChaCha20St :: Crypto.State
      xChaCha20St = Crypto.initializeX 20 ek n2

      decrypted :: ByteString
      (decrypted, _) = Crypto.combine xChaCha20St c

  -- Deserialize the raw decrypted bytes as a JSON object of claims.
  first DecryptionClaimsDeserializationError (Aeson.eitherDecodeStrict decrypted)

------------------------------------------------------------------------------
-- Public purpose
------------------------------------------------------------------------------

v4PublicTokenHeader :: ByteString
v4PublicTokenHeader = "v4.public."

-- | [PASETO version 4 cryptographic signing](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version4.md#sign).
--
-- This implementation produces a token which is signed using @Ed25519@.
sign
  :: SigningKey V4
  -- ^ Signing key.
  -> Claims
  -- ^ Claims to be signed.
  -> Maybe Footer
  -- ^ Optional footer to authenticate and encode within the resulting token.
  -> Maybe ImplicitAssertion
  -- ^ Optional implicit assertion to authenticate.
  -> Token V4 Public
sign (SigningKeyV4 sk) cs f i =
  let h :: ByteString
      h = v4PublicTokenHeader

      m :: ByteString
      m = BS.toStrict (Aeson.encode cs)

      m2 :: ByteString
      m2 = PAE.encode [h, m, maybe BS.empty unFooter f, maybe BS.empty unImplicitAssertion i]

      sig :: Crypto.Signature
      sig = Crypto.sign sk (Crypto.toPublic sk) m2

      payload :: Payload
      payload = Payload (m <> BA.convert sig)

  in TokenV4Public payload f

-- | PASETO version 4 signature verification error.
data VerificationError
  = -- | Invalid token footer.
    VerificationInvalidFooterError
      -- | Expected footer.
      !(Maybe Footer)
      -- | Actual footer.
      !(Maybe Footer)
  | -- | 'Crypto.CryptoError' that occurred during verification.
    VerificationCryptoError !Crypto.CryptoError
  | -- | Signature verification failed.
    VerificationInvalidSignatureError
  | -- | Error deserializing a verified collection of claims as JSON.
    VerificationClaimsDeserializationError !String
  deriving (Show, Eq)

-- | Render a 'VerificationError' as 'Text'.
renderVerificationError :: VerificationError -> Text
renderVerificationError err =
  case err of
    VerificationInvalidFooterError _ _ ->
      -- Since a footer could potentially be very long or some kind of
      -- illegible structured data, we're not going to attempt to render those
      -- values here.
      "Token has an invalid footer."
    VerificationCryptoError e ->
      "Encountered a cryptographic error: " <> T.pack (show e)
    VerificationInvalidSignatureError -> "Signature is invalid."
    VerificationClaimsDeserializationError e ->
      "Error deserializing claims from JSON: " <> T.pack (show e)

-- | [PASETO version 4 cryptographic signature verification](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version4.md#verify).
verify
  :: VerificationKey V4
  -- ^ Verification key.
  -> Token V4 Public
  -- ^ Token to verify.
  -> Maybe Footer
  -- ^ Optional footer to authenticate.
  -> Maybe ImplicitAssertion
  -- ^ Optional implicit assertion to authenticate.
  -> Either VerificationError Claims
verify (VerificationKeyV4 vk) (TokenV4Public (Payload sm) actualF) expectedF i = do
  let h :: ByteString
      h = v4PublicTokenHeader

  -- Check that the actual footer matches the provided expected footer.
  when (expectedF /= actualF) (Left $ VerificationInvalidFooterError expectedF actualF)

  s <-
    first VerificationCryptoError
      . Crypto.eitherCryptoError
      $ Crypto.signature (BS.takeEnd 64 sm)

  let m :: ByteString
      m = BS.dropEnd 64 sm

      m2 :: ByteString
      m2 = PAE.encode [h, m, maybe BS.empty unFooter actualF, maybe BS.empty unImplicitAssertion i]

  unless
    (Crypto.verify vk m2 s)
    (Left VerificationInvalidSignatureError)

  first VerificationClaimsDeserializationError (Aeson.eitherDecodeStrict m)
