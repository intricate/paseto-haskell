-- | PASETO
-- [Pre-Authentication Encoding (PAE)](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Common.md#authentication-padding).
module Crypto.Paseto.PreAuthenticationEncoding
  ( encode
  , DecodingError (..)
  , decode
  ) where

import Control.Monad ( replicateM )
import Data.Binary.Get
  ( ByteOffset, Get, getByteString, getWord64le, runGetOrFail )
import Data.Binary.Put ( putByteString, putWord64le, runPut )
import Data.Bits ( (.&.) )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Foldable ( for_ )
import Data.Word ( Word64 )
import Prelude

-- | Encode a multipart message using
-- [Pre-Authentication Encoding (PAE)](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Common.md#authentication-padding)
-- as defined in the PASETO spec.
encode :: [ByteString] -> ByteString
encode pieces = BS.toStrict . runPut $ do
  let numPieces :: Word64
      numPieces = fromIntegral $ length pieces
  putWord64le (clearMsb numPieces) -- Clear the MSB for interoperability
  for_ pieces $ \piece -> do
    let pieceLen :: Word64
        pieceLen = fromIntegral $ BS.length piece
    putWord64le (clearMsb pieceLen) -- Clear the MSB for interoperability
    putByteString piece
  where
    -- Clear the most significant bit of a 'Word64'.
    clearMsb :: Word64 -> Word64
    clearMsb w64 = w64 .&. (0x7FFFFFFFFFFFFFFF :: Word64)

-- | Error decoding a PAE-encoded message.
newtype DecodingError = DecodingError (LBS.ByteString, ByteOffset, String)
  deriving newtype (Show, Eq)

-- | Decode a multipart message which has been encoded using
-- [Pre-Authentication Encoding (PAE)](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Common.md#authentication-padding)
-- as defined in the PASETO spec.
decode :: ByteString -> Either DecodingError [ByteString]
decode bs =
  case runGetOrFail getPieces (LBS.fromStrict bs) of
    Left err -> Left (DecodingError err)
    Right (_, _, pieces) -> Right pieces
  where
    getPieces :: Get [ByteString]
    getPieces = do
      numPieces <- getWord64le
      replicateM (fromIntegral numPieces) $ do
        pieceLen <- getWord64le
        getByteString (fromIntegral pieceLen)
