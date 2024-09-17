module Crypto.Paseto.Mode
  ( Version (..)
  , Purpose (..)
  ) where

import Prelude

-- | PASETO protocol version.
data Version
  = -- | Version 3. Modern NIST cryptography.
    V3
  | -- | Version 4. Modern [Sodium (@libsodium@)](https://doc.libsodium.org/)
    -- cryptography.
    V4
  deriving stock (Show, Eq)

-- | PASETO token purpose.
data Purpose
  = -- | Shared-key authenticated encryption.
    Local
  | -- | Public-key digital signatures (__not encrypted__).
    Public
  deriving stock (Show, Eq)
