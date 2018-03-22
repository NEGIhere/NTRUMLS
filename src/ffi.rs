use std::mem;
use std::hash;

use libc::{c_int, c_uchar, c_char, c_uint, c_void, size_t, uint8_t, int8_t, uint16_t, int16_t, int64_t};

#[derive(Clone, Debug)]
#[repr(i32)]
pub enum PQParamSetID {
    XXX_20140508_401,
    XXX_20140508_439,
    XXX_20140508_593,
    XXX_20140508_743,

    XXX_20151024_401,
    XXX_20151024_443,
    XXX_20151024_563,
    //XXX_20151024_509,
    XXX_20151024_743,
    XXX_20151024_907,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct PQParamSet {
    pub id: PQParamSetID,
    pub name: *mut c_char,
    pub OID: [uint8_t; 3],
    pub N_bits: uint8_t,
    pub q_bits: uint8_t,
    pub N: uint16_t,
    pub p: int8_t,
    pub q: int64_t,
    pub B_s: int64_t,
    pub B_t: int64_t,
    pub norm_bound_s: int64_t,
    pub norm_bound_t: int64_t,
    pub d1: uint8_t,
    pub d2: uint8_t,
    pub d3: uint8_t,
    pub padded_N: uint16_t,
}

extern "C" {
    pub fn pq_gen_key(params: *mut PQParamSet,
                      privkey_blob_len: *mut isize,
                      privkey_blob: *mut c_uchar,
                      pubkey_blob_len: *mut isize,
                      pubkey_blob: *mut c_uchar) -> c_int;

    pub fn pq_gen_key_fg(params: *mut PQParamSet,
                         fg: *const u16,
                         privkey_blob_len: *mut isize,
                         privkey_blob: *mut c_uchar,
                         pubkey_blob_len: *mut isize,
                         pubkey_blob: *mut c_uchar) -> c_int;

    pub fn pq_get_param_set_by_id(id: PQParamSetID) -> *mut PQParamSet;
    pub fn bench_param_set(id: PQParamSetID) -> c_int;
    pub fn pq_sign(packed_sig_len: *mut usize, packed_sig: *mut c_uchar, private_key_len: usize, private_key_blob: *const c_uchar, public_key_len: usize, public_key_blob: *const c_uchar, msg_len: usize, msg: *const c_uchar) -> c_int;
    pub fn pq_verify(packed_sig_len: usize, packed_sig: *const c_uchar, public_key_len: usize, public_key_blob: *const c_uchar, msg_len: usize, msg: *const c_uchar) -> c_int;
}