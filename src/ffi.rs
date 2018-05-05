use libc::{c_int, c_uchar, c_char, uint8_t, int8_t, uint16_t, int64_t};

#[derive(Clone, Debug)]
#[repr(i32)]
pub enum PQParamSetID {
    Xxx20140508n401,
    Xxx20140508n439,
    Xxx20140508n593,
    Xxx20140508n743,

    Xxx20151024n401,
    Xxx20151024n443,
    Xxx20151024n563,
    Xxx20151024n743,
    Xxx20151024n907,
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct PQParamSet {
    pub id: PQParamSetID,
    pub name: *mut c_char,
    pub oid: [uint8_t; 3],
    pub n_bits: uint8_t,
    pub q_bits: uint8_t,
    pub n: uint16_t,
    pub p: int8_t,
    pub q: int64_t,
    pub b_s: int64_t,
    pub b_t: int64_t,
    pub norm_bound_s: int64_t,
    pub norm_bound_t: int64_t,
    pub d1: uint8_t,
    pub d2: uint8_t,
    pub d3: uint8_t,
    pub padded_n: uint16_t,
}

extern "C" {
    pub fn pq_gen_key(params: *const PQParamSet,
                      privkey_blob_len: *mut isize,
                      privkey_blob: *mut c_uchar,
                      pubkey_blob_len: *mut isize,
                      pubkey_blob: *mut c_uchar) -> c_int;

    pub fn pq_gen_key_fg(params: *const PQParamSet,
                         fg: *const u16,
                         privkey_blob_len: *mut isize,
                         privkey_blob: *mut c_uchar,
                         pubkey_blob_len: *mut isize,
                         pubkey_blob: *mut c_uchar) -> c_int;

    pub fn unpack_private_key(params: *const PQParamSet,
                         f: *mut u16,
                         g: *mut u16,
                         ginv: *mut i64,
                         blob_len: isize,
                         blob: *const c_uchar) -> c_int;

    pub fn pq_get_param_set_by_id(id: PQParamSetID) -> *mut PQParamSet;
    pub fn bench_param_set(id: PQParamSetID) -> c_int;
    pub fn pq_sign(packed_sig_len: *mut usize, packed_sig: *mut c_uchar, private_key_len: usize, private_key_blob: *const c_uchar, public_key_len: usize, public_key_blob: *const c_uchar, msg_len: usize, msg: *const c_uchar) -> c_int;
    pub fn pq_verify(packed_sig_len: usize, packed_sig: *const c_uchar, public_key_len: usize, public_key_blob: *const c_uchar, msg_len: usize, msg: *const c_uchar) -> c_int;
}