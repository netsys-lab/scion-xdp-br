// Copyright (c) 2022 Lars-Christian Schulz
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

/// \file
/// \brief AES key expansion, encryption, and MAC computation.
///
/// This file can be included both in control plane programs and in data plane BPF programs.
/// For data plane applications, only the core AES cypher and certain MAC-sizes are implemented.
/// The key expansion and subkey derivation needed to use these functions must be performed in the
/// control plane.
/// Since global BPF functions (which are verified independently from one another and can be called
/// by other BPF functions) only support scalars or pointers to fixed-size memory locations as
/// inputs, pointers passed to all non-inline functions refer to fixed size structs aes_block,
/// aes_key, aes_key_schedule, and aes_cmac.

#ifndef AES_H_GUARD
#define AES_H_GUARD

#include <stddef.h>
#include <stdint.h>


#define AES_KEY_LENGTH 4
#define AES_BLOCK_SIZE 4
#define AES_ROUNDS 10
#define AES_SCHED_SIZE (AES_ROUNDS+1)*AES_BLOCK_SIZE
#define AES_CMAC_NO_LOOP_MAX_BYTES 4 * (4*AES_BLOCK_SIZE)


/// \brief A 16 byte / 128 bit block for AES.
struct aes_block
{
    union {
        uint8_t b[4*AES_BLOCK_SIZE];
        uint32_t w[AES_BLOCK_SIZE];
    };
};

/// \brief 128-bit AES key
struct aes_key
{
    union {
        uint8_t b[4*AES_KEY_LENGTH];
        uint32_t w[AES_KEY_LENGTH];
    };
};

/// \brief AES key schedule containing initialization data (the AES key) followed by 10 round keys.
struct aes_key_schedule
{
    union {
        uint8_t b[4*AES_SCHED_SIZE];
        uint32_t w[AES_SCHED_SIZE];
        struct aes_key k[AES_ROUNDS+1];
    };
};

/// \brief Holds a MAC computed by the AES-CMAC algorithm.
struct aes_cmac
{
    union {
        uint8_t b[4*AES_KEY_LENGTH];
        uint32_t w[AES_KEY_LENGTH];
    };
};


#ifndef __bpf__

/// \brief AES substitution table
extern const uint8_t AES_SBox[256];

void aes_key_expansion(
    const struct aes_key *key,
    struct aes_key_schedule *key_schedule);

#endif


int aes_cypher(
    const struct aes_block *input,
    const struct aes_key_schedule *key_schedule,
    struct aes_block *output);


#ifndef __bpf__

void aes_cmac_subkeys(
    const struct aes_key_schedule *key_schedule,
    struct aes_block subkeys[2]);

void aes_cmac(
    const uint8_t *data, size_t len,
    const struct aes_key_schedule *key_schedule,
    const struct aes_block subkeys[2],
    struct aes_cmac *mac);

void aes_cmac_no_loops(
    const uint8_t *data, size_t len,
    const struct aes_key_schedule *key_schedule,
    const struct aes_block subkeys[2],
    struct aes_cmac *mac);

#else // !defined __bpf__

/// \brief Calculate the AES-CMAC of a 16 byte block according to RFC4493.
/// \param[in] data Input data, must be exactly 16 bytes
/// \param[in] key_schedule AES round keys
/// \param[in] subkey First subkey derived from the main key by aes_cmac_subkeys()
/// \param[out] mac Computed MAC
__attribute__((__always_inline__)) // Linking will fail if this function is not inlined
inline void aes_cmac_16bytes(
    const struct aes_block *data,
    const struct aes_key_schedule *key_schedule,
    const struct aes_block *subkey,
    struct aes_cmac *mac)
{
    // XOR data and subkey
    for (size_t i = 0; i < 4*AES_BLOCK_SIZE; ++i)
        mac->b[i] = data->b[i] ^ subkey->b[i];

    // Invoke block cypher
    aes_cypher((struct aes_block*)mac, key_schedule, (struct aes_block*)mac);
}

#endif // !defined __bpf__
#endif // AES_H_GUARD
