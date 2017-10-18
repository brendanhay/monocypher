{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

module Monocypher.Internal where

import Data.ByteString (ByteString)
import Data.Monoid     ((<>))

import Foreign.ForeignPtr (ForeignPtr)

import qualified Data.Map                  as Map
import qualified Language.C.Inline.Context as C
import qualified Language.C.Types          as C

#include "monocypher.h"

context :: C.Context
context = mempty { C.ctxTypesTable = types } <> C.bsCtx <> C.baseCtx

types :: C.TypesTable
types = Map.fromList
    [ (C.TypeName "crypto_blake2b_ctx",  [t| Blake2b |])
    ]

newtype PublicKey = PublicKey { unsafePublicKey :: ByteString }
newtype SharedKey = SharedKey { unsafeSharedKey :: ByteString }
newtype SecretKey = SecretKey { unsafeSecretKey :: ByteString }

newtype MAC        = MAC        { getMAC        :: ByteString }
newtype Nonce      = Nonce      { getNonce      :: ByteString }
newtype Salt       = Salt       { getSalt       :: ByteString }
newtype AD         = AD         { getAD         :: ByteString }
newtype Digest     = Digest     { getDigest     :: ByteString }
newtype Signature  = Signature  { getSignature  :: ByteString }
newtype Hash       = Hash       { getHash       :: ByteString }
newtype Plaintext  = Plaintext  { getPlaintext  :: ByteString }
newtype Ciphertext = Ciphertext { getCiphertext :: ByteString }
newtype Password   = Password   { getPassword   :: ByteString }

newtype Blake2b = Blake2b (ForeignPtr Blake2b)

blake2bSize :: Int
blake2bSize = (#size crypto_blake2b_ctx)
