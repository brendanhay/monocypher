{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TemplateHaskell   #-}

module Monocypher.Types where

import Data.ByteString (ByteString)
import Data.Vector.Storable (Vector)
import Data.Word            (Word8)

import Foreign.C.Types
import Foreign.Ptr      (Ptr)
import Foreign.Storable (Storable(..))

#include "monocypher.h"

newtype MAC   = MAC   ByteString
newtype Key   = Key   ByteString
newtype Nonce = Nonce ByteString

newtype Plaintext  = Plaintext  ByteString
newtype Ciphertext = Ciphertext ByteString

data Chacha20 = Chacha20
    { chacha20_input    :: !(Ptr CUInt) -- ^ Current input, unencrypted.
    , chacha20_pool     :: !(Ptr CUInt) -- ^ Last enput, encrypted.
    , chacha20_pool_idx :: !CSize       -- ^ Pointer to @random_pool@.
    } deriving (Show)

instance Storable Chacha20 where
    sizeOf _ = (#size crypto_chacha_ctx)
    {-# INLINE sizeOf #-}

    alignment _ = (#alignment crypto_chacha_ctx)
    {-# INLINE alignment #-}

    peek ptr = do
        chacha20_input    <- (#peek crypto_chacha_ctx, input)    ptr
        chacha20_pool     <- (#peek crypto_chacha_ctx, pool)     ptr
        chacha20_pool_idx <- (#peek crypto_chacha_ctx, pool_idx) ptr
        pure Chacha20{..}
    {-# INLINE peek #-}

    poke ptr Chacha20{..} = do
        (#poke crypto_chacha_ctx, input)    ptr chacha20_input
        (#poke crypto_chacha_ctx, pool)     ptr chacha20_pool
        (#poke crypto_chacha_ctx, pool_idx) ptr chacha20_pool_idx
    {-# INLINE poke #-}

data Poly1305 = Poly1305
    { poly1305_r     :: !(Ptr CUInt) -- ^ Constant multiplier (from the secret key).
    , poly1305_h     :: !(Ptr CUInt) -- ^ Accumulated hash.
    , poly1305_c     :: !(Ptr CUInt) -- ^ Chunk of the message.
    , poly1305_pad   :: !(Ptr CUInt) -- ^ Random number added at the end (from the secret key).
    , poly1305_c_idx :: !CSize       -- ^ How many bytes are there in the chunk.
    } deriving (Show)

instance Storable Poly1305 where
    sizeOf _ = (#size crypto_poly1305_ctx)
    {-# INLINE sizeOf #-}

    alignment _ = (#alignment crypto_poly1305_ctx)
    {-# INLINE alignment #-}

    peek ptr = do
        poly1305_r     <- (#peek crypto_poly1305_ctx, r)     ptr
        poly1305_h     <- (#peek crypto_poly1305_ctx, h)     ptr
        poly1305_c     <- (#peek crypto_poly1305_ctx, c)     ptr
        poly1305_pad   <- (#peek crypto_poly1305_ctx, pad)   ptr
        poly1305_c_idx <- (#peek crypto_poly1305_ctx, c_idx) ptr
        pure Poly1305{..}
    {-# INLINE peek #-}

    poke ptr Poly1305{..} = do
        (#poke crypto_poly1305_ctx, r)     ptr poly1305_r
        (#poke crypto_poly1305_ctx, h)     ptr poly1305_h
        (#poke crypto_poly1305_ctx, c)     ptr poly1305_c
        (#poke crypto_poly1305_ctx, pad)   ptr poly1305_pad
        (#poke crypto_poly1305_ctx, c_idx) ptr poly1305_c_idx
    {-# INLINE poke #-}

data Blake2b = Blake2b
    { blake2b_hash         :: !(Ptr CULLong)
    , blake2b_input_offset :: !(Ptr CULLong)
    , blake2b_input        :: !(Ptr CULLong)
    , blake2b_input_idx    :: !CSize
    , blake2b_hash_size    :: !CSize
    } deriving (Show)

instance Storable Blake2b where
    sizeOf _ = (#size crypto_blake2b_ctx)
    {-# INLINE sizeOf #-}

    alignment _ = (#alignment crypto_blake2b_ctx)
    {-# INLINE alignment #-}

    peek ptr = do
        blake2b_hash         <- (#peek crypto_blake2b_ctx, hash)         ptr
        blake2b_input_offset <- (#peek crypto_blake2b_ctx, input_offset) ptr
        blake2b_input        <- (#peek crypto_blake2b_ctx, input)        ptr
        blake2b_input_idx    <- (#peek crypto_blake2b_ctx, input_idx)    ptr
        blake2b_hash_size    <- (#peek crypto_blake2b_ctx, hash_size)    ptr
        pure Blake2b{..}
    {-# INLINE peek #-}

    poke ptr Blake2b{..} = do
        (#poke crypto_blake2b_ctx, hash)         ptr blake2b_hash
        (#poke crypto_blake2b_ctx, input_offset) ptr blake2b_input_offset
        (#poke crypto_blake2b_ctx, input)        ptr blake2b_input
        (#poke crypto_blake2b_ctx, input_idx)    ptr blake2b_input_idx
        (#poke crypto_blake2b_ctx, hash_size)    ptr blake2b_hash_size
    {-# INLINE poke #-}
