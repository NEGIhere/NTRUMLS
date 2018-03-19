use std::mem;
use std::hash;

use libc::{c_int, c_uchar, c_char, c_uint, c_void, size_t, uint8_t, int8_t, uint16_t, int16_t, int64_t};

#[derive(Clone, Debug)]
#[repr(C)] pub enum PQParamSetID {
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
#[repr(C)] pub struct PQParamSet(
    PQParamSetID,
    *mut c_char,
    [uint8_t; 3],
    uint8_t,
    uint8_t,
    uint16_t,
    int8_t,
    int64_t,
    int64_t,
    int64_t,
    int64_t,
    int64_t,
    uint8_t,
    uint8_t,
    uint8_t,
    uint16_t,
);

extern "C" {
//    pub fn pq_gen_key(params: *mut PQParamSet,
//                                    privkey_blob_len: *mut size_t,
//                                    privkey_blob: *mut c_uchar,
//                                    pubkey_blob_len: *mut size_t,
//                                    pubkey_blob: *mut c_uchar) -> c_int;
//
//
    pub fn pq_get_param_set_by_id(id: PQParamSetID) -> *mut PQParamSet;
    pub fn bench_param_set(id: PQParamSetID) -> c_int;
    pub fn call_this_func_plz() -> c_int;
}