//! # Verifiable Random Function (VRF)
//!
//! This crate defines the generic contract that must be followed by VRF implementations ([`VRF`](trait.VRF.html) trait).
//!
//! ## Elliptic Curve VRF
//!
//! The [`openssl`](openssl/index.html) module provides an implementation of Elliptic Curve VRF ([`ECVRF`](openssl/struct.ECVRF.html)).
//!
//! It follows the algorithms described in:
//!
//! * [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
//! * [RFC6979](https://tools.ietf.org/html/rfc6979)
//!
//! Currently the supported cipher suites are:
//!
//! * `P256_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `NIST P-256` curve.
//! * `K163_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `NIST K-163` curve.
//! * `SECP256K1_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `secp256k1` curve.
pub mod vrf_sgx;