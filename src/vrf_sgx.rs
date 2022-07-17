//! This is a sgx version migration of [vrf-rs](https://github.com/witnet/vrf-rs) based on [incubator-teaclave-sgx-sdk](https://github.com/apache/incubator-teaclave-sgx-sdk).
//!
//! Module that uses the OpenSSL library to offer Elliptic Curve Verifiable Random Function (VRF) functionality.
//! This module follows the algorithms described in [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05) and [RFC6979](https://tools.ietf.org/html/rfc6979).
//!
//! In particular, it provides:
//!
//! * `ECVRF_hash_to_curve` as in the `ECVRF_hash_to_curve_try_and_increment` algorithm from [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
//! * `ECVRF_nonce_generation` as specified in Section 3.2 of [RFC6979](https://tools.ietf.org/html/rfc6979)
//!
//! Warning: if input data is private, information leaks in the form of timing side channels are possible.
//!
//! Currently the supported cipher suites are:
//! * _P256_SHA256_TAI_: the aforementioned algorithms with `SHA256` and the `NIST P-256` curve.
//! * _K163_SHA256_TAI_: the aforementioned algorithms with `SHA256` and the `NIST K-163` curve.
//! * _SECP256K1_SHA256_TAI_: the aforementioned algorithms with `SHA256` and the `secp256k1` curve.
//!
//! ## Documentation
//!
//! * [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
//! * [RFC6979](https://tools.ietf.org/html/rfc6979)
//! * [GitHub repository](https://github.com/witnet/vrf-rs)
//!
//!  ## Features
//!
//! * Compute VRF proof
//! * Verify VRF proof
#![warn(unused_extern_crates)]

use sgx_tcrypto as intel_crypto;
use sgx_tstd::{vec::Vec, iter};

use num_bigint::{BigInt, Sign};
use intel_crypto::*;
use sgx_types::*;

use rust_secp256k1::{ffi::types::AlignedType,
                     PublicKey as PubKey,
                     SecretKey as PrvKey,
                     Error as SECP256K1Error,
                     Secp256k1};

type EcPoint = PubKey;

/// Different errors that can be raised when proving/verifying VRFs
#[derive(Debug)]
pub enum Error {
    /// Error raised from `openssl::error::ErrorStack` with a specific code
    CodedError { code: c_ulong },
    /// The `hash_to_point()` function could not find a valid point
    HashToPointError,
    /// The proof length is invalid
    InvalidPiLength,
    /// The proof is invalid
    InvalidProof,
    /// The hash failed
    InvalidHash,
    /// Error from the SGX
    SGXError,
    /// Error from the SECP256k1
    Secp256k1Error,
    /// Unknown error
    Unknown,
}

impl core::convert::From<sgx_types::sgx_status_t> for Error {
    fn from(_: sgx_status_t) -> Self {
        Error::SGXError
    }
}

impl core::convert::From<SECP256K1Error> for Error{
    fn from(_: SECP256K1Error) -> Self {
        Error::Secp256k1Error
    }
}

/// A trait containing the common capabilities for all Verifiable Random Functions (VRF) implementations.
pub trait VRF<PublicKey, SecretKey> {
    type Error;

    /// Generates proof from a secret key and a message.
    ///
    /// # Arguments
    ///
    /// * `x`     - A secret key.
    /// * `alpha` - A slice representing the message in octets.
    ///
    /// # Returns
    ///
    /// * If successful, a vector of octets representing the proof of the VRF.
    fn prove(&mut self, x: SecretKey, alpha: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Verifies the provided VRF proof and computes the VRF hash output.
    ///
    /// # Arguments
    ///
    /// * `y`   - A public key.
    /// * `pi`  - A slice of octets representing the VRF proof.
    ///
    /// # Returns
    ///
    /// * If successful, a vector of octets with the VRF hash output.
    fn verify(&mut self, _y: PublicKey, _pi: &[u8], _alpha: &[u8]) -> Result<Vec<u8>, Self::Error> { Ok(Vec::new()) }
}

/// Appends leading zeros if provided slice is smaller than given length.
///
/// # Arguments
///
/// * `data`         - A slice of octets.
/// * `bits_length`  - An integer to specify the total length (in bits) after appending zeros.
///
/// # Returns
///
/// * A vector of octets with leading zeros (if necessary)
pub fn append_leading_zeros(data: &[u8], bits_length: usize) -> Vec<u8> {
    if data.len() * 8 > bits_length {
        return data.to_vec();
    }
    let leading_zeros = if bits_length % 8 > 0 {
        vec![0; bits_length / 8 - data.len() + 1]
    } else {
        vec![0; bits_length / 8 - data.len()]
    };

    [&leading_zeros[..], data].concat()
}

fn hash(data: &[u8]) -> sgx_sha256_hash_t {
    rsgx_sha256_slice(data).unwrap()
}

fn int2octets(v: BigInt, qlen: usize) -> Vec<u8> {
    let rolen = (qlen + 7) >> 3;
    let v_b = v.to_biguint().unwrap().to_bytes_be();
    let v_len = v_b.len();
    if rolen > v_len {
        // TODO: fix this std support
        let mut res: Vec<u8> = iter::repeat(0u8).take(rolen).collect();
        res[rolen - v_len..].copy_from_slice(v_b.clone().as_slice());

        res
    } else {
        v_b[v_len - rolen..].to_vec()
    }
}

/// Converts a slice of octets into a `BigInt` of length `qlen` as specified in [RFC6979](https://tools.ietf.org/html/rfc6979)
/// (section 2.3.2).
///
/// # Arguments
///
/// * `data` - A slice representing the number to be converted.
/// * `qlen` - The desired length for the output `BigInt`.
///
/// # Returns
///
/// * If successful, a `BigInt` representing the conversion.
pub fn bits2int(data: &[u8], qlen: usize) -> BigInt {
    let data_len_bits = data.len() * 8;
    let mut result = BigInt::from_bytes_be(Sign::Plus, data);
    if data_len_bits > qlen {
        result >>= (data_len_bits - qlen) as usize;
    }

    result
}

/// Transform an input to a sequence of `length` (in bits) and output this sequence representing a
/// number between 0 and `order` (non-inclusive), as specified in [RFC6979](https://tools.ietf.org/html/rfc6979) (section 2.3.4.).
///
/// # Arguments
///
/// * `data`         - A slice of octets.
/// * `bits_length`  - An integer to specify the total length (in bits) after appending zeros.
///
/// # Returns
///
/// * If successful, a vector of octets.
pub fn bits2octets(
    data: &[u8],
    qlen: usize,
    order: &BigInt,
) -> Vec<u8> {
    let z1 = bits2int(data, qlen);
    let z2 = &z1 % order;
    return if z2 < BigInt::from(0) {
        int2octets(z1, qlen)
    } else {
        int2octets(z2, qlen)
    };
}

/// Different cipher suites for different curves/algorithms
#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum CipherSuite {
    /// `NIST P-256` with `SHA256` and `ECVRF_hash_to_curve_try_and_increment`
    P256_SHA256_TAI,
    /// `Secp256k1` with `SHA256` and `ECVRF_hash_to_curve_try_and_increment`
    SECP256K1_SHA256_TAI,
    /// `NIST K-163` with `SHA256` and `ECVRF_hash_to_curve_try_and_increment`
    K163_SHA256_TAI,
}

impl CipherSuite {
    fn suite_string(&self) -> u8 {
        match *self {
            CipherSuite::P256_SHA256_TAI => 0x01,
            CipherSuite::SECP256K1_SHA256_TAI => 0xFE,
            CipherSuite::K163_SHA256_TAI => 0xFF,
        }
    }
}

/// An Elliptic Curve VRF
pub struct ECVRF {
    order: BigInt,
    cipher_suite: CipherSuite,
    qlen: usize,
    n: usize,
}

impl ECVRF {
    /// Factory method for creating a ECVRF structure with a context that is initialized for the provided cipher suite.
    ///
    /// # Arguments
    ///
    /// * `suite` - A ciphersuite identifying the curve/algorithms.
    ///
    /// # Returns
    ///
    /// * If successful, the ECVRF structure.
    pub fn from_suite(_suite: CipherSuite) -> Result<Self, Error> {
        // We only need secp256k1 curve, therefore, we hardcode it here
        let order = BigInt::parse_bytes(b"00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();
        Ok(ECVRF {
            order,
            cipher_suite:CipherSuite::SECP256K1_SHA256_TAI,
            n: 128,
            qlen: 256,
        })
    }

    /// Function for deriving a public key given a secret key point.
    /// Returns an `EcPoint` with the corresponding public key.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - A `BigInt` referencing the secret key.
    ///
    /// # Returns
    ///
    /// * If successful, an `EcPoint` representing the public key.
    fn derive_public_key_point(&mut self, secret_key: &BigInt) -> Result<EcPoint, Error> {
        let secp_size = Secp256k1::preallocate_size();
        let mut buf = vec![AlignedType::zeroed(); secp_size];
        let secp = Secp256k1::preallocated_new(&mut buf).unwrap();
        let prikey = PrvKey::from_slice(&secret_key.to_biguint().unwrap().to_bytes_be()).unwrap();
        Ok(PubKey::from_secret_key(&secp, &prikey))
    }

    /// Generates a nonce deterministically by following the algorithm described in the [RFC6979](https://tools.ietf.org/html/rfc6979)
    /// (section 3.2. __Generation of k__).
    ///
    /// # Arguments
    ///
    /// * `secret_key`  - A `BigInt` representing the secret key.
    /// * `data`        - A slice of octets (message).
    ///
    /// # Returns
    ///
    /// * If successful, the `BigInt` representing the nonce.
    fn generate_nonce(&mut self, secret_key: &BigInt, data: &[u8]) -> Result<BigInt, Error> {
        let data_hash = hash(data);

        let data_trunc = bits2octets(&data_hash, self.qlen, &self.order);
        let padded_data_trunc = append_leading_zeros(&data_trunc, self.qlen);

        let padded_secret_key_bytes: Vec<u8> =
            append_leading_zeros(&secret_key.to_bytes_be().1, self.qlen);

        // Init `V` & `K`
        // `K = HMAC_K(V || 0x00 || int2octects(secret_key) || bits2octects(data))`
        let mut v = [0x01; 32];
        let mut k = [0x00; 32];

        // First 2 rounds defined by specification
        for prefix in 0..2u8 {
            k = rsgx_hmac_sha256_slice(&k, [
                &v[..],
                &[prefix],
                &padded_secret_key_bytes[..],
                &padded_data_trunc[..],
            ].concat().as_slice())?;
            v = rsgx_hmac_sha256_slice(&k, &v)?;
        }

        // Loop until valid `BigInt` extracted from `V` is found
        loop {
            v = rsgx_hmac_sha256_slice(&k, &v)?;
            let ret_bn = bits2int(&v, self.qlen);

            if ret_bn > BigInt::from(0) && ret_bn < self.order {
                return Ok(ret_bn);
            }
            k = rsgx_hmac_sha256_slice(&k, [&v[..], &[0x00]].concat().as_slice())?;
            v = rsgx_hmac_sha256_slice(&k, &v)?;
        }
    }

    /// Function to convert a `Hash(PK|DATA)` to a point in the curve as stated in [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
    /// (section 5.4.1.1).
    ///
    /// # Arguments
    ///
    /// * `public_key` - An `EcPoint` referencing the public key.
    /// * `alpha` - A slice containing the input data.
    ///
    /// # Returns
    ///
    /// * If successful, an `EcPoint` representing the hashed point.
    fn hash_to_try_and_increment(
        &mut self,
        public_key: &PubKey,
        alpha: &[u8],
    ) -> Result<EcPoint, Error> {
        let mut c = 0..255;
        let pk_bytes = public_key.serialize();
        let cipher = [self.cipher_suite.suite_string(), 0x01];
        let mut v = [&cipher[..], &pk_bytes[..], alpha, &[0x00]].concat();
        let position = v.len() - 1;
        // `Hash(cipher||PK||data)`
        let point = c.find_map(|ctr| {
            v[position] = ctr;
            // Check validity of `H`
            match self.arbitrary_string_to_point(&hash(&v)) {
                Ok(v) => Some(v),
                Err(_) => None,
            }
        });
        // Return error if no valid point was found
        match point {
            Some(v) => Ok(v),
            None => Err(Error::InvalidHash)
        }
    }

    /// Function to convert an arbitrary string to a point in the curve as specified in VRF-draft-05
    /// (section 5.5).
    ///
    /// # Arguments
    ///
    /// * `data` - A slice representing the data to be converted to a point.
    ///
    /// # Returns
    ///
    /// * If successful, an `EcPoint` representing the converted point.
    fn arbitrary_string_to_point(&mut self, data: &[u8]) -> Result<EcPoint, Error> {
        let mut v = vec![0x02];
        v.extend(data);
        match EcPoint::from_slice(&v) {
            Ok(v) => Ok(v),
            Err(_) => Err(Error::Unknown),
        }
    }

    /// Function to hash a certain set of points as specified in [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
    /// (section 5.4.3).
    ///
    /// # Arguments
    ///
    /// * `points` - A reference to an array containing the points that need to be hashed.
    ///
    /// # Returns
    ///
    /// * If successful, a `BigInt` representing the hash of the points, truncated to length `n`.
    fn hash_points(&mut self, points: &[&EcPoint]) -> Result<BigInt, Error> {
        // point_bytes = [P1||P2||...||Pn]
        let mut point_bytes = Vec::new();
        point_bytes.extend(vec![self.cipher_suite.suite_string(), 0x02]);

        for point in points.into_iter() {
            point_bytes.extend(point.serialize().to_vec());
        }
        // H(point_bytes)
        let hash = hash(&point_bytes);
        let truncated_c_string = &hash[0..16];

        Ok(BigInt::from_bytes_be(Sign::Plus, &truncated_c_string))
    }

    /// Decodes a VRF proof by extracting the gamma (as `EcPoint`), and parameters `c` and `s`
    /// (as `BigInt`).
    ///
    /// # Arguments
    ///
    /// * `pi`  - A slice of octets representing the VRF proof.
    ///
    /// # Returns
    ///
    /// * A tuple containing the gamma `EcPoint`, and `BigInt` parameters `c` and `s`.
    fn decode_proof(&mut self, pi: &[u8]) -> Result<(EcPoint, BigInt, BigInt), Error> {
        let gamma_oct = if self.qlen % 8 > 0 {
            self.qlen / 8 + 2
        } else {
            self.qlen / 8 + 1
        };
        let c_oct = if self.n % 8 > 0 {
            self.n / 8 + 1
        } else {
            self.n / 8
        };

        // Expected size of proof: len(pi) == len(gamma) + len(c) + len(s)
        // len(s) == 2 * len(c), so len(pi) == len(gamma) + 3 * len(c)
        if pi.len() != gamma_oct + c_oct * 3 {
            return Err(Error::InvalidProof);
        }
        let gamma_point = PubKey::from_slice(&pi[0..gamma_oct]).unwrap();
        let c = BigInt::from_bytes_be(Sign::Plus, &pi[gamma_oct..gamma_oct + c_oct]);
        let s = BigInt::from_bytes_be(Sign::Plus, &pi[gamma_oct + c_oct..]);

        Ok((gamma_point, c, s))
    }

    /// Computes the VRF hash output as result of the digest of a ciphersuite-dependent prefix
    /// concatenated with the gamma point ([VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05), section 5.2).
    ///
    /// # Arguments
    ///
    /// * `gamma`  - An `EcPoint` representing the VRF gamma.
    ///
    /// # Returns
    ///
    /// * A vector of octets with the VRF hash output.
    fn gamma_to_hash(&mut self, gamma: &EcPoint) -> Result<Vec<u8>, Error> {
        let mut v = Vec::new();
        v.extend(&[self.cipher_suite.suite_string(), 0x03]);
        v.extend(gamma.serialize().to_vec());
        let hash = hash(v.as_slice());
        Ok(Vec::from(hash))
    }

    /// Computes the VRF hash output as result of the digest of a ciphersuite-dependent prefix
    /// concatenated with the gamma point ([VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05), section 5.2).
    ///
    /// # Arguments
    ///
    /// * `pi`  - A slice representing the VRF proof in octets.
    ///
    /// # Returns
    ///
    /// * If successful, a vector of octets with the VRF hash output.
    pub fn proof_to_hash(&mut self, pi: &[u8]) -> Result<Vec<u8>, Error> {
        let (gamma_point, _, _) = self.decode_proof(pi).unwrap();

        self.gamma_to_hash(&gamma_point)
    }
}

/// VRFs are objects capable of generating and verifying proofs.
impl VRF<&[u8], &[u8]> for ECVRF {
    type Error = Error;
    /// Generates proof from a secret key and message as specified in the
    /// [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05) (section 5.1).
    ///
    /// # Arguments
    ///
    /// * `x` - A slice representing the secret key in octets.
    /// * `alpha` - A slice representing the message in octets.
    ///
    /// # Returns
    ///
    /// * If successful, a vector of octets representing the proof of the VRF.
    fn prove(&mut self, x: &[u8], alpha: &[u8]) -> Result<Vec<u8>, Error> {
        // Step 1: derive public key from secret key
        // `Y = x * B`
        //TODO: validate secret key length?
        let x = PrvKey::from_slice(x).unwrap();
        let secret_key = BigInt::from_bytes_be(Sign::Plus, x.as_ref());
        let public_key_point = self.derive_public_key_point(&secret_key).unwrap();

        // Step 2: Hash to curve
        let h_point = self.hash_to_try_and_increment(&public_key_point, alpha).unwrap();

        // Step 3: point to string
        let h_string = h_point.serialize();

        let secp_size = Secp256k1::preallocate_size();
        let mut buf = vec![AlignedType::zeroed(); secp_size];
        let secp = Secp256k1::preallocated_new(&mut buf).unwrap();

        // Step 4: Gamma = x * H
        let mut gamma_point = h_point.clone();
        gamma_point.mul_assign(&secp, x.as_ref())?;

        // Step 5: nonce
        let k = self.generate_nonce(&secret_key, &h_string).unwrap();
        let k_bytes = k.to_biguint().unwrap().to_bytes_be();
        // Step 6: c = hash points(...)
        let u_point = self.derive_public_key_point(&k).unwrap();
        let mut v_point = h_point.clone();
        v_point.mul_assign(&secp, k_bytes.as_slice())?;
        let c = self.hash_points(&[&h_point, &gamma_point, &u_point, &v_point]).unwrap();

        // Step 7: s = (k + c*x) mod q
        let s = &(&k + &(&c * &secret_key)) % &self.order;

        // Step 8: encode (gamma, c, s)
        let gamma_string = gamma_point.serialize();
        // Fixed size; len(c) must be n and len(s)=2n
        let c_string = append_leading_zeros(&c.to_biguint().unwrap().to_bytes_be(), self.n);
        let s_string = append_leading_zeros(&s.to_biguint().unwrap().to_bytes_be(), self.qlen);
        // proof =  [Gamma_string||c_string||s_string]
        let proof = [&gamma_string[..], &c_string, &s_string].concat();
        Ok(proof)
    }

    // /// Verifies the provided VRF proof and computes the VRF hash output as specified in
    // /// [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05) (section 5.3).
    // ///
    // /// # Arguments
    // ///
    // /// * `y`   - A slice representing the public key in octets.
    // /// * `pi`  - A slice of octets representing the VRF proof.
    // ///
    // /// # Returns
    // ///
    // /// * If successful, a vector of octets with the VRF hash output.
    // fn verify(&mut self, y: &[u8], pi: &[u8], alpha: &[u8]) -> Result<Vec<u8>, Error> {
    //     // Step 1: decode proof
    //     let (gamma_point, c, s) = self.decode_proof(pi).unwrap();
    //
    //     // Step 2: hash to curve
    //     // TODO: unwrap is not good here, need update
    //     let public_key_point = EcPoint::from_slice(y).unwrap();
    //     let h_point = self.hash_to_try_and_increment(&public_key_point, alpha).unwrap();
    //
    //     // Fixed size; len(c) must be n and len(s)=2n
    //     let c_string = append_leading_zeros(&c.to_biguint().unwrap().to_bytes_be(), self.qlen);
    //     let s_string = append_leading_zeros(&s.to_biguint().unwrap().to_bytes_be(), self.qlen);
    //     let pubkey = PubKey::from_slice(&y).unwrap();
    //
    //     let secp_size = Secp256k1::preallocate_size();
    //     let mut buf = vec![AlignedType::zeroed(); secp_size];
    //     let secp = Secp256k1::preallocated_new(&mut buf).unwrap();
    //
    //     // Step 3: U = s*B - c*Y
    //     let s_b = PubKey::from_slice(&s_string).unwrap();
    //     let mut c_y = pubkey.clone();
    //     c_y.mul_assign(&secp, &c_string);
    //     let u_point = s_b.min(c_y);
    //
    //     // Step 4: V = sH -cGamma
    //     let mut s_h = h_point.clone();
    //     s_h.mul_assign(&secp, &s_string);
    //     let mut c_gamma = gamma_point.clone();
    //     c_gamma.mul_assign(&secp,&c_string);
    //     let v_point = s_h.min(c_gamma);
    //
    //
    //     // Step 5: hash points(...)
    //     let derived_c = self.hash_points(&[&h_point, &gamma_point, &u_point, &v_point]).unwrap();
    //
    //     // Step 6: Check validity
    //     if !derived_c.eq(&c) {
    //         return Err(Error::InvalidProof);
    //     }
    //     let beta = self.gamma_to_hash(&gamma_point).unwrap();
    //
    //     Ok(beta)
    // }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_bits2int() {
        let data1 = vec![0x01; 32];
        let expected_result_1 = BigInt::from_bytes_be(Sign::Plus, &data1);
        let result1 = bits2int(&data1, 256);
        assert_eq!(result1, expected_result_1);

        let data2 = vec![0x01; 33];
        let data2_bn = BigInt::from_bytes_be(Sign::Plus, &data2);
        let result2 = bits2int(&data2, 256);
        let expected_result_2 = data2_bn >> 8 as usize;
        // expected_result_2.rshift(&data2_bn, 8).unwrap();

        assert_eq!(result2.to_signed_bytes_be(), expected_result_2.to_signed_bytes_be());
    }

    /// Test vector taken from [RFC6979](https://tools.ietf.org/html/rfc6979)
    /// Input: `sha256("sample")`
    /// `qlen=163`
    #[test]
    fn test_bits2octets() {
        let data = hex::decode("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF")
            .unwrap();
        let order = BigInt::parse_bytes(b"00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();

        let order_hex = hex::decode("04000000000000000000020108A2E0CC0D99F8A5EF").unwrap();
        let order = BigInt::from_bytes_be(Sign::Plus, order_hex.as_slice());

        let b = order.to_bytes_be();

        let result = bits2octets(
            &data.as_slice(),
            order.bits() as usize,
            &order,
        );

        let expected_result = hex::decode("01795EDF0D54DB760F156D0DAC04C0322B3A204224").unwrap();
        assert_eq!(result, expected_result);
    }

    /// Test for `SECP256K1-SHA256-TAI` cipher suite
    /// ASCII: "sample"
    #[test]
    fn test_prove_secp256k1_sha256_tai() {
        let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
        // Secret Key (labelled as x)
        let x = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
            .unwrap();
        // Data: ASCII "sample"
        let alpha = hex::decode("73616d706c65").unwrap();

        let pi = vrf.prove(&x, &alpha).unwrap();
        let expected_pi = hex::decode("031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d08748c9fbe6b95d17359707bfb8e8ab0c93ba0c515333adcb8b64f372c535e115ccf66ebf5abe6fadb01b5efb37c0a0ec9").unwrap();
        assert_eq!(pi, expected_pi);
    }

    // /// Test for `SECP256K1-SHA256-TAI` cipher suite
    // /// ASCII: "sample"
    // #[test]
    // fn test_verify_secp256k1_sha256_tai() {
    //     let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    //     // Public Key (labelled as y)
    //     let y = hex::decode("032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645")
    //         .unwrap();
    //     // Data: ASCII "sample"
    //     let alpha = hex::decode("73616d706c65").unwrap();
    //     // VRF proof
    //     let pi = hex::decode("031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d0814faa89697b482daa377fb6b4a8b0191a65d34a6d90a8a2461e5db9205d4cf0bb4b2c31b5ef6997a585a9f1a72517b6f").unwrap();
    //
    //     let beta = vrf.verify(&y, &pi, &alpha).unwrap();
    //     let expected_beta =
    //         hex::decode("612065e309e937ef46c2ef04d5886b9c6efd2991ac484ec64a9b014366fc5d81")
    //             .unwrap();
    //     assert_eq!(beta, expected_beta);
    // }
}