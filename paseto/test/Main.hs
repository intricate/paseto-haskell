module Main where

import Hedgehog.Main ( defaultMain )
import Prelude
import qualified Test.Crypto.Paseto.Keys.V3
import qualified Test.Crypto.Paseto.PreAuthenticationEncoding
import qualified Test.Crypto.Paseto.Protocol.V3
import qualified Test.Crypto.Paseto.Protocol.V4
import qualified Test.Crypto.Paseto.TestVectorTest
import qualified Test.Crypto.Paseto.Token.Claim
import qualified Test.Crypto.Paseto.Token.Claims
import qualified Test.Crypto.Paseto.Token.Encoding
import qualified Test.Crypto.Paseto.Token.Validation

main :: IO ()
main =
  defaultMain
    [ Test.Crypto.Paseto.Keys.V3.tests
    , Test.Crypto.Paseto.PreAuthenticationEncoding.tests
    , Test.Crypto.Paseto.Protocol.V3.tests
    , Test.Crypto.Paseto.Protocol.V4.tests
    , Test.Crypto.Paseto.TestVectorTest.tests
    , Test.Crypto.Paseto.Token.Claim.tests
    , Test.Crypto.Paseto.Token.Claims.tests
    , Test.Crypto.Paseto.Token.Encoding.tests
    , Test.Crypto.Paseto.Token.Validation.tests
    ]
