#![crate_type = "lib"]
#![crate_type = "rlib"]
#![crate_type = "dylib"]
#![crate_name = "ntrumls"]

// Coding conventions
#![deny(non_upper_case_globals)]
//#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

#![cfg_attr(all(test, feature = "unstable"), feature(test))]
#[cfg(all(test, feature = "unstable"))] extern crate test;
#[cfg(any(test, feature = "serde"))] extern crate serde;
#[cfg(test)] extern crate serde_json as json;
#[cfg(any(test, feature = "rand"))] extern crate rand;
#[cfg(any(test, feature = "rustc-serialize"))] extern crate rustc_serialize as serialize;

extern crate libc;

use libc::size_t;
use std::{error, fmt, ops, ptr};
#[cfg(any(test, feature = "rand"))] use rand::Rng;

pub mod ffi;

pub struct NTRUMLS {

}

impl NTRUMLS {
    pub fn generate_keypair() {
        unsafe {
//            ffi::bench_param_set(ffi::PQParamSetID::XXX_20140508_401);
//            ffi::call_this_func_plz();

//            let p = ffi::pq_get_param_set_by_id(ffi::PQParamSetID::XXX_20140508_401);
//            println!("p={:?}", *p);
//            let privkey_blob_len = 0 as *mut usize;
//            let pubkey_blob_len = 0 as *mut usize;
//            let r = ffi::pq_gen_key(p,
//                                    privkey_blob_len, ptr::null_mut(),
//                                    pubkey_blob_len, ptr::null_mut());
//            println!("privkey_blob_len={} pubkey_blob_len={}", *privkey_blob_len, *pubkey_blob_len)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NTRUMLS;

    #[test]
    fn capabilities() {
        NTRUMLS::generate_keypair();
    }
}