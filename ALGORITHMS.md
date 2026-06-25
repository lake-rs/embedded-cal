<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
-->

Currently supported algorithms are:

# AEAD

| Algorithm | Implementation | Notes |
|-----------|----------------|-------|
| A128GCM (AES-GCM) | libcrux | alloc'ed AAD |
| A256GCM (AES-GCM) | libcrux | alloc'ed AAD |
| AES-CCM-16-64-128 | nrf54l15 | limited AAD and message size |
| AES-CCM-16-64-256 | nrf54l15 | limited AAD and message size |
| AES-CCM-16-64-128 | stm32wba55 | |
| AES-CCM-16-64-256 | stm32wba55 | |
| AES-CCM-16-64-128 | rustcrypto | limited or alloc'ed AAD |
| AES-CCM-16-64-256 | rustcrypto | limited or alloc'ed AAD |

Limitation in AAD streaming or message size are subject to ongoing work.

# ECDH

| Algorithm | Implementation | Notes |
|-----------|----------------|-------|
| ECDH on curve P-256 | rustcrypto | |
| ECDH on curve X25519 | rustcrypto | |
| ECDH on curve P-256 | stm32wba55 | |
| ECDH on curve P-256 | nrf54l15 | |
| ECDH on curve X25519 | nrf54l15 | |
| ECDH on curve X448 | nrf54l15 | |

# Hash

| Algorithm | Implementation | Notes |
|-----------|----------------|-------|
| SHA-256 | libcrux | |
| SHA-256 | rustcrypto | |
| SHA-256 | software-demo | using SHA2-short plumbing for acceleration |
| SHA2-short | nrf54l15 | providing plumbing |
| SHA2-short | stm32wba55 | providing plumbing |
| SHA3-224 | nrf54l15 | |
| SHA3-256 | nrf54l15 | |
| SHA3-384 | nrf54l15 | |
| SHA3-512 | nrf54l15 | |

# HMAC

| Algorithm | Implementation | Notes |
|-----------|----------------|-------|
| HMAC w/ SHA-256 | rustcrypto | |
| HMAC w/ SHA-256 | software-demo | |

# HKDF

| Algorithm | Implementation | Notes |
|-----------|----------------|-------|
| HKDF on HMAC w/ SHA-256 | blanket | to be moved into implementations |
