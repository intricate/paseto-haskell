module Test.Crypto.Paseto.TestVectorTest
  ( tests
  ) where

import Control.Monad.IO.Class ( MonadIO (..) )
import qualified Data.Aeson as Aeson
import Data.String ( fromString )
import Hedgehog ( Group (..), checkParallel, property, withTests )
import Prelude
import Test.Crypto.Paseto.TestVectors
  ( mkV3TestVectorProperties, mkV4TestVectorProperties )

tests :: IO Bool
tests =
  and <$> mapM (>>= checkParallel) [testVectorsV3, testVectorsV4]

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

testVectorsV3 :: MonadIO m => m Group
testVectorsV3 = do
  res <- liftIO (Aeson.eitherDecodeFileStrict "test/test-vectors/v3.json")
  case res of
    Left err -> error $ "failed to decode V3 test vectors: " <> show err
    Right tvs ->
      pure $ Group "Test Vectors V3" $
        flip map (mkV3TestVectorProperties tvs) $ \(propName, prop) ->
          (fromString propName, withTests 1 (property prop))

testVectorsV4 :: MonadIO m => m Group
testVectorsV4 = do
  res <- liftIO (Aeson.eitherDecodeFileStrict "test/test-vectors/v4.json")
  case res of
    Left err -> error $ "failed to decode V4 test vectors: " <> show err
    Right tvs ->
      pure $ Group "Test Vectors V4" $
        flip map (mkV4TestVectorProperties tvs) $ \(propName, prop) ->
          (fromString propName, withTests 1 (property prop))
