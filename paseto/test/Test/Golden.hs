module Test.Golden
  ( goldenTestPae
  , goldenTestPaseto
  ) where

import Control.Monad.IO.Class ( liftIO )
import qualified Crypto.Paseto.PreAuthenticationEncoding as PAE
import Crypto.Paseto.Token ( Token (..), toSomeToken )
import Crypto.Paseto.Token.Encoding ( encode )
import Crypto.Paseto.Token.Parser ( parseSomeToken )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import qualified Data.Text.Encoding as TE
import GHC.Stack ( HasCallStack, withFrozenCallStack )
import Hedgehog ( Property, property, withTests, (===) )
import Hedgehog.Internal.Property ( failWith )
import Prelude

-- | Golden test for PASETO Pre-Authentication Encoding (PAE).
goldenTestPae
  :: HasCallStack
  => [ByteString]
  -> FilePath
  -> Property
goldenTestPae x path = withFrozenCallStack $ withTests 1 . property $ do
  bs <- liftIO (BS.readFile path)
  PAE.encode x === bs
  case PAE.decode bs of
    Left err -> failWith Nothing $ "could not decode: " <> show err
    Right x' -> x === x'

-- | Golden test for the
-- [PASETO message format](https://github.com/paseto-standard/paseto-spec/tree/af79f25908227555404e7462ccdd8ce106049469/docs#paseto-message-format).
goldenTestPaseto
  :: HasCallStack
  => Token v p
  -> FilePath
  -> Property
goldenTestPaseto x path = withFrozenCallStack $ withTests 1 . property $ do
  t <- TE.decodeUtf8 <$> liftIO (BS.readFile path)
  encode x === t
  case parseSomeToken t of
    Left err -> failWith Nothing $ "could not decode: " <> show err
    Right x' -> (toSomeToken x) === x'
