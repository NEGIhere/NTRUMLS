// NTRUMLS bindings
// Written in 2018 by
//   Vladislav Markushin
//
//! # Build script

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

extern crate gcc;

fn main() {
	let mut base_config = gcc::Build::new();

    base_config.include("depend/NTRUMLS/src").include("depend/NTRUMLS/").flag("-g");
	base_config
		.file("depend/NTRUMLS/src/crypto_hash_sha512.c")
		.file("depend/NTRUMLS/src/crypto_stream.c")
		.file("depend/NTRUMLS/src/fastrandombytes.c")
		.file("depend/NTRUMLS/src/shred.c")
		.file("depend/NTRUMLS/src/convert.c")
		.file("depend/NTRUMLS/src/pack.c")
		.file("depend/NTRUMLS/src/pol.c")
		.file("depend/NTRUMLS/src/params.c")
		.file("depend/NTRUMLS/src/pqntrusign.c");

	if cfg!(target_os = "windows") {
		base_config.file("depend/NTRUMLS/src/randombytes-vs.c");
	} else {
		base_config.file("depend/NTRUMLS/src/randombytes.c");
	}

    if let Err(e) = base_config.try_compile("libntrumls.a") {
		panic!("Compiler error: {:?}", e);
    }

}