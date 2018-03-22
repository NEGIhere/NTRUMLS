#![crate_type = "lib"]
#![crate_type = "rlib"]
#![crate_type = "dylib"]
#![crate_name = "ntrumls"]

// Coding conventions
//#![deny(non_upper_case_globals)]
//#![deny(non_camel_case_types)]
//#![deny(non_snake_case)]
//#![deny(unused_mut)]
//#![warn(missing_docs)]

#![cfg_attr(all(test, feature = "unstable"), feature(test))]
#[cfg(any(test, feature = "rand"))] extern crate rand;

extern crate libc;
//
use std::{error, fmt, ops, ptr};
#[cfg(any(test, feature = "rand"))] use rand::Rng;
#[cfg(any(test, feature = "rand"))] use rand::thread_rng;

use std::cell::RefCell;
use std::boxed::Box;

pub mod ffi;

#[derive(Debug)]
pub struct PublicKey(pub Vec<u8>);
#[derive(Debug)]
pub struct PrivateKey(pub Vec<u8>);
#[derive(Debug)]
pub struct Signature(pub Vec<u8>);

pub struct NTRUMLS {

}

impl NTRUMLS {
    pub fn generate_keypair() -> Option<(PrivateKey, PublicKey)> {
        unsafe {
            let p = ffi::pq_get_param_set_by_id(ffi::PQParamSetID::XXX_20151024_907);
            let d = (((*p).d1 + (*p).d2 + (*p).d3) * 4) as usize;
            let OID_BYTES = std::mem::size_of::<[u8; 3]>();
            let PACKED_PRODUCT_FORM_BYTES = ((2 * ((*p).d1 + (*p).d2 + (*p).d3) as usize * (*p).N_bits as usize + 7) / 8) as usize;
            let PACKED_MOD3_POLY_BYTES = ((*p).N + 4)/5;
            let PACKED_MODQ_POLY_BYTES = ((*p).N * (*p).q_bits as u16 + 7)/8;
            let HASH_BYTES = 64;

            let PUBKEY_PACKED_BYTES = 2 + OID_BYTES + PACKED_MODQ_POLY_BYTES as usize + HASH_BYTES;
            let PRIVKEY_PACKED_BYTES = 2 + OID_BYTES + 2 * PACKED_PRODUCT_FORM_BYTES as usize + PACKED_MOD3_POLY_BYTES as usize;

            let privkey_blob_len = &mut (PRIVKEY_PACKED_BYTES as isize) as *mut isize;
            let pubkey_blob_len = &mut (PUBKEY_PACKED_BYTES as isize) as *mut isize;

            let mut privkey_blob = vec![0u8; *privkey_blob_len as usize];
            let mut pubkey_blob = vec![0u8; *pubkey_blob_len as usize];

            let rc = ffi::pq_gen_key(p,
                                       privkey_blob_len, privkey_blob.as_mut_ptr(),
                                       pubkey_blob_len, pubkey_blob.as_mut_ptr());
            if rc != 0 {
                return None;
            }

            return Some((PrivateKey(privkey_blob), PublicKey(pubkey_blob)));
        }
        None
    }

    pub fn generate_keypair_from_fg(fg: &[u16]) -> Option<(PrivateKey, PublicKey)> {
        unsafe {
            let p = ffi::pq_get_param_set_by_id(ffi::PQParamSetID::XXX_20151024_907);
            let d = (((*p).d1 + (*p).d2 + (*p).d3) * 4) as usize;
            assert_eq!(d, fg.len());

            let OID_BYTES = std::mem::size_of::<[u8; 3]>();
            let PACKED_PRODUCT_FORM_BYTES = ((2 * ((*p).d1 + (*p).d2 + (*p).d3) as usize * (*p).N_bits as usize + 7) / 8) as usize;
            let PACKED_MOD3_POLY_BYTES = ((*p).N + 4)/5;
            let PACKED_MODQ_POLY_BYTES = ((*p).N * (*p).q_bits as u16 + 7)/8;
            let HASH_BYTES = 64;

            let PUBKEY_PACKED_BYTES = 2 + OID_BYTES + PACKED_MODQ_POLY_BYTES as usize + HASH_BYTES;
            let PRIVKEY_PACKED_BYTES = 2 + OID_BYTES + 2 * PACKED_PRODUCT_FORM_BYTES as usize + PACKED_MOD3_POLY_BYTES as usize;

            let privkey_blob_len = &mut (PRIVKEY_PACKED_BYTES as isize) as *mut isize;
            let pubkey_blob_len = &mut (PUBKEY_PACKED_BYTES as isize) as *mut isize;

            let mut privkey_blob = vec![0u8; *privkey_blob_len as usize];
            let mut pubkey_blob = vec![0u8; *pubkey_blob_len as usize];

            let rc = ffi::pq_gen_key_fg(p, fg.as_ptr(),
                                       privkey_blob_len, privkey_blob.as_mut_ptr(),
                                       pubkey_blob_len, pubkey_blob.as_mut_ptr());
            if rc != 0 {
                return None;
            }

            return Some((PrivateKey(privkey_blob), PublicKey(pubkey_blob)));
        }
        None
    }

    pub fn sign(msg: &[u8], sk: &PrivateKey, pk: &PublicKey) -> Option<Signature> {
        unsafe {
            let p = ffi::pq_get_param_set_by_id(ffi::PQParamSetID::XXX_20151024_907);

            let mut sig_len = ((((*p).N * ((*p).q_bits-1) as u16) + 7)/8) as usize;
            let mut sig = vec![0u8; sig_len];

            let rc = ffi::pq_sign(&mut sig_len as *mut usize, (&mut sig).as_mut_ptr(), sk.0.len(), sk.0.as_ptr(), pk.0.len(), pk.0.as_ptr(), msg.len(), msg.as_ptr());
            if rc != 0 {
                return None;
            }

            return Some(Signature(sig));
        }
        None
    }

    pub fn verify(msg: &[u8], sig: &Signature, pk: &PublicKey) -> bool {
        unsafe {
            0 == ffi::pq_verify(sig.0.len(), sig.0.as_ptr(), pk.0.len(), pk.0.as_ptr(), msg.len(), msg.as_ptr())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NTRUMLS;

    #[test]
    fn capabilities() {
        let fg = [100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100];
        let (sk, pk) = NTRUMLS::generate_keypair_from_fg(&fg).expect("failed to generate keypair");
        println!("{:?}", sk);
        println!("{:?}", pk);

        let msg = "TEST_MESSAGE";
        let sig = NTRUMLS::sign(msg.as_bytes(), &sk, &pk).expect("failed to generate signature");
        println!("{:?}", sig);
        assert!(NTRUMLS::verify(msg.as_bytes(), &sig, &pk));
    }
}