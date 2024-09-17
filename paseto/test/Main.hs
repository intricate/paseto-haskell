module Main where

import Hedgehog.Main ( defaultMain )
import Prelude
import qualified Test.Crypto.Paseto.Keys.V3
import qualified Test.Crypto.Paseto.PreAuthenticationEncoding
import qualified Test.Crypto.Paseto.Protocol.V3
import qualified Test.Crypto.Paseto.Protocol.V4
import qualified Test.Crypto.Paseto.TestVectorTest
import qualified Test.Crypto.Paseto.Token.Encoding

main :: IO ()
main =
  defaultMain
    [ Test.Crypto.Paseto.Keys.V3.tests
    , Test.Crypto.Paseto.PreAuthenticationEncoding.tests
    , Test.Crypto.Paseto.Protocol.V3.tests
    , Test.Crypto.Paseto.Protocol.V4.tests
    , Test.Crypto.Paseto.TestVectorTest.tests
    , Test.Crypto.Paseto.Token.Encoding.tests
    ]
