{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE QuasiQuotes              #-}
{-# LANGUAGE ScopedTypeVariables      #-}
{-# LANGUAGE TemplateHaskell          #-}

module Monocypher
    (
    -- * Authenticated encryption (XChacha20 + Poly1305)
    -- $authenticated_encryption

      cryptoLock
    , cryptoUnlock

    -- -- * Types
    -- , Chacha20
    -- , Poly1305
    -- , Blake2b

    , Key
    , Nonce
    , Plaintext
    , Ciphertext
    , ErrorCode
    , MAC
    ) where

import Data.Word (Word8)

import Monocypher.Internal (Ciphertext (..), Key (..), MAC (..), Nonce (..),
                            Plaintext (..))

import Foreign.Marshal.Array (allocaArray)
import Foreign.Ptr           (Ptr, castPtr)

import qualified Data.ByteString        as BS
import qualified Data.ByteString.Unsafe as BS
import qualified Language.C.Inline      as C
import qualified Monocypher.Internal    as Cypher

-- FIXME: Recreate the Monocypher test suite

C.context Cypher.context

C.include "monocypher.h"

data ErrorCode

{- $authenticated_encryption

Authenticated encryption (XChacha20 + Poly1305)

Encryption makes your messages unreadable to eavesdroppers. Authentication
ascertain the origin and integrity of the messages you read.

Both are important. Without encryption, you give away all your secrets, and
without authentication, you can fall prey to forgeries (messages that look
legitimate, but actually come from the attacker). A clever attacker may even
leverage forgeries to steal your secrets.

/Always authenticate your messages./
-}

{- |
The inputs are:

__key__: a 32-byte session key, shared between you and the recipient. It must be
secret (unknown to the attacker) and random (unpredictable to the attacker). Of
course, one does not simply transmit this key over the network. There are less
suicidal ways to share session keys, such as meeting physically, or performing
a Diffie Hellman key exchange (described below).

__nonce__: a 24-byte a number, used only once with any given session key. It
doesn't have to be secret or random. But you must never reuse that number with
the same key. If you do, the attacker will have access to the XOR of 2
different messages, and the ability to forge messages in your stead.

The easiest (and recommended) way to generate this nonce is to use your OS's
random number generator (__\/dev\/urandom__ on UNIX systems). Don't worry about
accidental collisions, the nonce is big enough to make them virtually
impossible.

Don't use user space random number generators, they're error prone. You could
accidentally reuse the generator's internal state, duplicate the random stream,
and trigger a nonce reuse. Oops.

__plaintext__: the secret you want to send. Of course, it must be unknown to the
attacker. Keep in mind however that the length of the plaintext, unlike its
content, is not secret. Make sure your protocol doesn't leak secret information
with the length of messages. (It has happened before with variable-length voice
encoding software.) Solutions to mitigate this include constant-length
encodings and padding.

The outputs are:

__mac__: a 16-byte message authentication code (MAC), that only you could have
produced. (Of course, this guarantee goes out the window the nanosecond the
attacker somehow learns your session key, or sees 2 messages with the same
nonce. Seriously, don't reuse that nonce.)

Transmit this MAC over the network so the recipient can authenticate your
message.

__ciphertext__: the encrypted message (same length as the plaintext
message). Transmit it over the network so the recipient can decrypt and read
it.

/Note:/ ciphertext is allowed to have the same value as plaintext. If so,
encryption will happen in place.
-}
cryptoLock :: Key -> Nonce -> Plaintext -> IO (MAC, Ciphertext)
cryptoLock (Key key) (Nonce nonce) (Plaintext plain) =
    -- void crypto_lock(uint8_t        mac[16],
    --                  uint8_t       *ciphertext,
    --                  const uint8_t  key[32],
    --                  const uint8_t  nonce[24],
    --                  const uint8_t *plaintext, size_t text_size);

    let macLen    = 16
        cipherLen = BS.length plain
     in allocaArray macLen    $ \(macPtr    :: Ptr Word8) ->
        allocaArray cipherLen $ \(cipherPtr :: Ptr Word8) -> do
            [C.block|void {
                crypto_lock( $(uint8_t *macPtr)
                           , $(uint8_t *cipherPtr)
                           , $bs-ptr:key
                           , $bs-ptr:nonce
                           , $bs-ptr:plain
                           , $bs-len:plain
                           );
            }|]

            macBS    <- BS.unsafePackCStringLen (castPtr macPtr,    macLen)
            cipherBS <- BS.unsafePackCStringLen (castPtr cipherPtr, cipherLen)

            pure (MAC macBS, Ciphertext cipherBS)

{- |
The flip side of the coin. The inputs are:

__key__: the session key. It's the same as the one used for authenticated
encryption.

__nonce__: the nonce that was used to encrypt this particular message. No
decryption is possible without it.

__mac__: the message authentication code produced by the sender. Integrity cannot
be ensured without it.

__ciphertext__: the encrypted text produced by the sender.

There are 2 outputs:

__plaintext__: The decrypted message (same length as the ciphertext).

/Note:/ plaintext is allowed to be the same as ciphertext. If so, decryption will
happen in place.

__return code__: 0 if all went well, -1 if the message was corrupted (either
accidentally or intentionally).

/Tip:/ always check your return code.

Unlocking proceeds in two steps: first, we authenticate the additional data and
the ciphertext with the provided MAC. If any of those three has been corrupted,
crypto_aead_unlock() returns -1 immediately, without decrypting the message. If
the message is genuine, crypto_aead_unlock() decrypts the ciphertext, then
returns 0.

/(Again, if someone gave away the session key or reused a nonce, detecting forgeries becomes impossible. Don't reuse the nonce.)/
-}
cryptoUnlock :: Key -> Nonce -> MAC -> Ciphertext -> IO (Maybe Plaintext)
cryptoUnlock (Key key) (Nonce nonce) (MAC mac) (Ciphertext cipher) =
    -- int crypto_unlock(uint8_t       *plaintext,
    --                   const uint8_t  key[32],
    --                   const uint8_t  nonce[24],
    --                   const uint8_t  mac[16],
    --                   const uint8_t *ciphertext, size_t text_size);

    let plainLen = BS.length cipher
     in allocaArray plainLen $ \(plainPtr :: Ptr Word8) -> do
            code <- [C.block|int {
                crypto_unlock( $(uint8_t *plainPtr)
                             , $bs-ptr:key
                             , $bs-ptr:nonce
                             , $bs-ptr:mac
                             , $bs-ptr:cipher
                             , $bs-len:cipher
                             );
            }|]

            if code /= 0
                then pure Nothing
                else Just . Plaintext <$>
                    BS.unsafePackCStringLen (castPtr plainPtr, plainLen)
