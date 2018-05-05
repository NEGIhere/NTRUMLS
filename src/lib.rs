#![crate_type = "lib"]
#![crate_type = "rlib"]
#![crate_type = "dylib"]
#![crate_name = "ntrumls"]

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
//#![warn(missing_docs)]

#![cfg_attr(all(test, feature = "unstable"), feature(test))]

extern crate libc;
extern crate rustc_serialize;

//use std::ops::{Deref, DerefMut};
use rustc_serialize::{
    hex::{ToHex, FromHex},
    Encodable, Decodable, Encoder, Decoder,
};

pub mod ffi;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicKey(pub Vec<u8>);

impl Encodable for PublicKey {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_str(&format!("{}", self.0.to_hex()))
    }
}

impl Decodable for PublicKey {
    fn decode<D: Decoder>(d: &mut D) -> Result<Self, D::Error> {
        Ok(PublicKey(d.read_str()?.from_hex().map_err(|e| d.error(&e.to_string()))?))
    }
}

//impl Deref for PublicKey {
//    type Target = [u8];
//
//    fn deref(&self) -> &[u8] {
//        &self.0
//    }
//}
//impl DerefMut for PublicKey {
//    fn deref_mut(&mut self) -> &mut [u8] {
//        &mut self.0
//    }
//}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PrivateKey(pub Vec<u8>);

impl Encodable for PrivateKey {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_str(&format!("{}", self.0.to_hex()))
    }
}

impl Decodable for PrivateKey {
    fn decode<D: Decoder>(d: &mut D) -> Result<Self, D::Error> {
        Ok(PrivateKey(d.read_str()?.from_hex().map_err(|e| d.error(&e.to_string()))?))
    }
}

//impl Deref for PrivateKey {
//    type Target = [u8];
//
//    fn deref(&self) -> &[u8] {
//        &self.0
//    }
//}
//impl DerefMut for PrivateKey {
//    fn deref_mut(&mut self) -> &mut [u8] {
//        &mut self.0
//    }
//}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Signature(pub Vec<u8>);

impl Encodable for Signature {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_str(&format!("{}", self.0.to_hex()))
    }
}

impl Decodable for Signature {
    fn decode<D: Decoder>(d: &mut D) -> Result<Self, D::Error> {
        Ok(Signature(d.read_str()?.from_hex().map_err(|e| d.error(&e.to_string()))?))
    }
}

//impl Deref for Signature {
//    type Target = [u8];
//
//    fn deref(&self) -> &[u8] {
//        &self.0
//    }
//}
//impl DerefMut for Signature {
//    fn deref_mut(&mut self) -> &mut [u8] {
//        &mut self.0
//    }
//}

pub enum PQParamSetID {
   Security82Bit, // XXX_20151024_401
   Security88Bit, // XXX_20151024_443
   Security126Bit, // XXX_20151024_563
   Security179Bit, // XXX_20151024_743
   Security269Bit, // XXX_20151024_907
}

pub type PQParamSet = ffi::PQParamSet;

pub struct NTRUMLS {
    p: PQParamSet,
    pubkey_packed_bytes_len: usize,
    privkey_packed_bytes_len: usize,
}

impl NTRUMLS {
    pub fn with_param_set(param_set: PQParamSetID) -> Self {
        unsafe {
            let p = match param_set {
                PQParamSetID::Security82Bit => ffi::PQParamSetID::Xxx20151024n401,
                PQParamSetID::Security88Bit => ffi::PQParamSetID::Xxx20151024n443,
                PQParamSetID::Security126Bit => ffi::PQParamSetID::Xxx20151024n563,
                PQParamSetID::Security179Bit => ffi::PQParamSetID::Xxx20151024n743,
                PQParamSetID::Security269Bit => ffi::PQParamSetID::Xxx20151024n907,
            };

            let p = ffi::pq_get_param_set_by_id(p);
            if p.is_null() {
                panic!("Invalid PQParamSetID");
            }

            let p = (*p).clone();

            let oid_bytes_len = std::mem::size_of::<[u8; 3]>();
            let packed_product_from_bytes_len = ((2 * (p.d1 + p.d2 + p.d3) as usize * p.n_bits as usize + 7) / 8) as usize;
            let packed_mod3_poly_bytes_len = (p.n + 4)/5;
            let packed_mod_q_poly_bytes_len = (p.n * p.q_bits as u16 + 7)/8;
            let hash_bytes_len = 64;

            let pubkey_packed_bytes_len = 2 + oid_bytes_len + packed_mod_q_poly_bytes_len as usize + hash_bytes_len;
            let privkey_packed_bytes_len = 2 + oid_bytes_len + 2 * packed_product_from_bytes_len as usize + packed_mod3_poly_bytes_len as usize;

            NTRUMLS {
                p,
                pubkey_packed_bytes_len,
                privkey_packed_bytes_len,
            }
        }
    }

    pub fn generate_keypair(&self) -> Option<(PrivateKey, PublicKey)> {
        unsafe {
            let p = &self.p;

            let privkey_blob_len = &mut (self.privkey_packed_bytes_len as isize) as *mut isize;
            let pubkey_blob_len = &mut (self.pubkey_packed_bytes_len as isize) as *mut isize;

            let mut privkey_blob = vec![0u8; *privkey_blob_len as usize];
            let mut pubkey_blob = vec![0u8; *pubkey_blob_len as usize];

            let rc = ffi::pq_gen_key(p as *const PQParamSet,
                                       privkey_blob_len, privkey_blob.as_mut_ptr(),
                                       pubkey_blob_len, pubkey_blob.as_mut_ptr());
            if rc != 0 {
                return None;
            }

            return Some((PrivateKey(privkey_blob), PublicKey(pubkey_blob)));
        }
    }

    pub fn unpack_fg_from_private_key(&self, sk: &PrivateKey) -> Option<Vec<u16>> {
        let p = &self.p;

        let product_form_bytes_len = 2*(p.d1 + p.d2 + p.d3) as usize;

        let mut f_blob = vec![0u16; product_form_bytes_len as usize];
        let mut g_blob = vec![0u16; product_form_bytes_len as usize];

        unsafe {
            let rc = ffi::unpack_private_key(p as *const PQParamSet, f_blob.as_mut_ptr(), g_blob.as_mut_ptr(),
                                             std::ptr::null_mut(), self.privkey_packed_bytes_len as isize, sk.0.as_ptr());

            if rc == 0 {
                let mut vec = Vec::<u16>::new();
                vec.splice(.., f_blob.iter().cloned());
                let offset = vec.len();
                vec.splice(offset.., g_blob.iter().cloned());
                return Some(vec);
            }
            None
        }
    }

    /**
    * Calculates keypair from 'fg' (concatenated ring elements 'f' and 'g')
    */
    pub fn generate_keypair_from_fg(&self, fg: &[u16]) -> Option<(PrivateKey, PublicKey)> {
        unsafe {
            let p = &self.p;
            let d = ((p.d1 + p.d2 + p.d3) * 4) as usize;
            assert_eq!(d, fg.len());

            let privkey_blob_len = &mut (self.privkey_packed_bytes_len as isize) as *mut isize;
            let pubkey_blob_len = &mut (self.pubkey_packed_bytes_len as isize) as *mut isize;

            let mut privkey_blob = vec![0u8; *privkey_blob_len as usize];
            let mut pubkey_blob = vec![0u8; *pubkey_blob_len as usize];

            let rc = ffi::pq_gen_key_fg(p as *const PQParamSet, fg.as_ptr(),
                                       privkey_blob_len, privkey_blob.as_mut_ptr(),
                                       pubkey_blob_len, pubkey_blob.as_mut_ptr());
            if rc != 0 {
                return None;
            }

            return Some((PrivateKey(privkey_blob), PublicKey(pubkey_blob)));
        }
    }

    pub fn sign(&self, msg: &[u8], sk: &PrivateKey, pk: &PublicKey) -> Option<Signature> {
        unsafe {
            let p = &self.p;

            let mut sig_len = (((p.n * (p.q_bits-1) as u16) + 7)/8) as usize;
            let mut sig = vec![0u8; sig_len];

            let rc = ffi::pq_sign(&mut sig_len as *mut usize, (&mut sig).as_mut_ptr(), sk.0.len(), sk.0.as_ptr(), pk.0.len(), pk.0.as_ptr(), msg.len(), msg.as_ptr());
            if rc != 0 {
                return None;
            }

            return Some(Signature(sig));
        }
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature, pk: &PublicKey) -> bool {
        unsafe {
            0 == ffi::pq_verify(sig.0.len(), sig.0.as_ptr(), pk.0.len(), pk.0.as_ptr(), msg.len(), msg.as_ptr())
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::NTRUMLS;

    #[test]
    fn capabilities() {
        let ntrumls = NTRUMLS::with_param_set(super::PQParamSetID::Security269Bit);
        let (sk, pk) = ntrumls.generate_keypair().expect("failed to generate keypair");
        let fg = ntrumls.unpack_fg_from_private_key(&sk).expect("failed to get Fg");
        let (sk2, pk2) = ntrumls.generate_keypair_from_fg(&fg).expect("failed to generate keypair \
        from Fg");

        assert_eq!(sk, sk2);
        assert_eq!(pk, pk2);

        let msg = "TEST MESSAGE";
        let sig = ntrumls.sign(msg.as_bytes(), &sk, &pk).expect("failed to generate signature");
        assert!(ntrumls.verify(msg.as_bytes(), &sig, &pk));
    }
}