// This file is part of mbedtls. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT. No part of mbedtls, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2016 The developers of mbedtls. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT.


use ::std::slice::from_raw_parts;
use ::std::mem::transmute;
use ::std::ffi::CStr;
use ::std::ffi::CString;
use ::std::str::FromStr;
use ::std::fmt::Display;
use ::std::fmt::Formatter;
extern crate libc;
use self::libc::c_int;
extern crate num;
use self::num::FromPrimitive;
extern crate mbedtls_sys;
use ::CipherSuiteParseError;


enum_from_primitive!
{
	#[allow(non_camel_case_types)]
	#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
	#[repr(i32)]
	pub enum CipherSuite
	{
		TLS_RSA_WITH_NULL_MD5 = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_NULL_MD5,
		TLS_RSA_WITH_NULL_SHA = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_NULL_SHA,
		TLS_RSA_WITH_RC4_128_MD5 = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_RC4_128_MD5,
		TLS_RSA_WITH_RC4_128_SHA = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_RC4_128_SHA,
		TLS_RSA_WITH_DES_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_DES_CBC_SHA,
		TLS_RSA_WITH_3DES_EDE_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		TLS_DHE_RSA_WITH_DES_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_DES_CBC_SHA,
		TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
		TLS_PSK_WITH_NULL_SHA = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_NULL_SHA,
		TLS_DHE_PSK_WITH_NULL_SHA = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA,
		TLS_RSA_PSK_WITH_NULL_SHA = mbedtls_sys::MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA,
		TLS_RSA_WITH_AES_128_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
		TLS_DHE_RSA_WITH_AES_128_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_AES_256_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA,
		TLS_DHE_RSA_WITH_AES_256_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_NULL_SHA256 = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_NULL_SHA256,
		TLS_RSA_WITH_AES_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
		TLS_RSA_WITH_AES_256_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
		TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
		TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
		TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
		TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
		TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
		TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
		TLS_PSK_WITH_RC4_128_SHA = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_RC4_128_SHA,
		TLS_PSK_WITH_3DES_EDE_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_3DES_EDE_CBC_SHA,
		TLS_PSK_WITH_AES_128_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA,
		TLS_PSK_WITH_AES_256_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA,
		TLS_DHE_PSK_WITH_RC4_128_SHA = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_RC4_128_SHA,
		TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
		TLS_DHE_PSK_WITH_AES_128_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
		TLS_DHE_PSK_WITH_AES_256_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
		TLS_RSA_PSK_WITH_RC4_128_SHA = mbedtls_sys::MBEDTLS_TLS_RSA_PSK_WITH_RC4_128_SHA,
		TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
		TLS_RSA_PSK_WITH_AES_128_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
		TLS_RSA_PSK_WITH_AES_256_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_AES_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_RSA_WITH_AES_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_PSK_WITH_AES_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
		TLS_PSK_WITH_AES_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384,
		TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
		TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
		TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
		TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
		TLS_PSK_WITH_AES_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256,
		TLS_PSK_WITH_AES_256_CBC_SHA384 = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384,
		TLS_PSK_WITH_NULL_SHA256 = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_NULL_SHA256,
		TLS_PSK_WITH_NULL_SHA384 = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_NULL_SHA384,
		TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
		TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
		TLS_DHE_PSK_WITH_NULL_SHA256 = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA256,
		TLS_DHE_PSK_WITH_NULL_SHA384 = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA384,
		TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
		TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = mbedtls_sys::MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
		TLS_RSA_PSK_WITH_NULL_SHA256 = mbedtls_sys::MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA256,
		TLS_RSA_PSK_WITH_NULL_SHA384 = mbedtls_sys::MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA384,
		TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
		TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
		TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
		TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
		TLS_ECDH_ECDSA_WITH_NULL_SHA = mbedtls_sys::MBEDTLS_TLS_ECDH_ECDSA_WITH_NULL_SHA,
		TLS_ECDH_ECDSA_WITH_RC4_128_SHA = mbedtls_sys::MBEDTLS_TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
		TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
		TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
		TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_NULL_SHA = mbedtls_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_NULL_SHA,
		TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = mbedtls_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		TLS_ECDH_RSA_WITH_NULL_SHA = mbedtls_sys::MBEDTLS_TLS_ECDH_RSA_WITH_NULL_SHA,
		TLS_ECDH_RSA_WITH_RC4_128_SHA = mbedtls_sys::MBEDTLS_TLS_ECDH_RSA_WITH_RC4_128_SHA,
		TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
		TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
		TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_RSA_WITH_NULL_SHA = mbedtls_sys::MBEDTLS_TLS_ECDHE_RSA_WITH_NULL_SHA,
		TLS_ECDHE_RSA_WITH_RC4_128_SHA = mbedtls_sys::MBEDTLS_TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
		TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
		TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_PSK_WITH_RC4_128_SHA = mbedtls_sys::MBEDTLS_TLS_ECDHE_PSK_WITH_RC4_128_SHA,
		TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
		TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = mbedtls_sys::MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
		TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
		TLS_ECDHE_PSK_WITH_NULL_SHA = mbedtls_sys::MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA,
		TLS_ECDHE_PSK_WITH_NULL_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA256,
		TLS_ECDHE_PSK_WITH_NULL_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA384,
		TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
		TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
		TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
		TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
		TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
		TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
		TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
		TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
		TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
		TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
		TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
		TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
		TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
		TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
		TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
		TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
		TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256,
		TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384,
		TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256,
		TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384,
		TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = mbedtls_sys::MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
		TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = mbedtls_sys::MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
		TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,
		TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,
		TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
		TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
		TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
		TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = mbedtls_sys::MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
		TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = mbedtls_sys::MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
		TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = mbedtls_sys::MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
		TLS_RSA_WITH_AES_128_CCM = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_AES_128_CCM,
		TLS_RSA_WITH_AES_256_CCM = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_AES_256_CCM,
		TLS_DHE_RSA_WITH_AES_128_CCM = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM,
		TLS_DHE_RSA_WITH_AES_256_CCM = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM,
		TLS_RSA_WITH_AES_128_CCM_8 = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_AES_128_CCM_8,
		TLS_RSA_WITH_AES_256_CCM_8 = mbedtls_sys::MBEDTLS_TLS_RSA_WITH_AES_256_CCM_8,
		TLS_DHE_RSA_WITH_AES_128_CCM_8 = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM_8,
		TLS_DHE_RSA_WITH_AES_256_CCM_8 = mbedtls_sys::MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM_8,
		TLS_PSK_WITH_AES_128_CCM = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_AES_128_CCM,
		TLS_PSK_WITH_AES_256_CCM = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_AES_256_CCM,
		TLS_DHE_PSK_WITH_AES_128_CCM = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM,
		TLS_DHE_PSK_WITH_AES_256_CCM = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM,
		TLS_PSK_WITH_AES_128_CCM_8 = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8,
		TLS_PSK_WITH_AES_256_CCM_8 = mbedtls_sys::MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8,
		TLS_DHE_PSK_WITH_AES_128_CCM_8 = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM_8,
		TLS_DHE_PSK_WITH_AES_256_CCM_8 = mbedtls_sys::MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM_8,
		TLS_ECDHE_ECDSA_WITH_AES_128_CCM = mbedtls_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		TLS_ECDHE_ECDSA_WITH_AES_256_CCM = mbedtls_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
		TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = mbedtls_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = mbedtls_sys::MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
		TLS_ECJPAKE_WITH_AES_128_CCM_8 = mbedtls_sys::MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8,
	}
}

impl Display for CipherSuite
{
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result
	{
        write!(f, "{}", self.name().to_string_lossy())
    }
}

// TODO: Consider quick-error (https://github.com/tailhook/quick-error)
impl FromStr for CipherSuite
{
	type Err = CipherSuiteParseError;
	
	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		match CString::new(s)
		{
			Err(_) => Err(CipherSuiteParseError::ContainsNul(s.to_owned())),
			Ok(cipherSuiteName) =>
			{
				match Self::from(&cipherSuiteName)
				{
					Some(cipherSuite) => Ok(cipherSuite),
					None => Err(CipherSuiteParseError::Unknown(s.to_owned())),
				}
			},
		}
	}
}

impl CipherSuite
{
	const NoCipherSuiteId: c_int = 0;

	pub fn allSupportedCipherSuites() -> &'static [Self]
	{
		const increment: usize = 1;
		unsafe
		{
			let list: *const c_int = mbedtls_sys::mbedtls_ssl_list_ciphersuites();
			
			let mut element = list;
			let mut listSize = 0;
			while *element != Self::NoCipherSuiteId
			{
				listSize = listSize + increment;
				element = element.offset(increment as isize);
			}
			
			from_raw_parts(transmute::<_, *const Self>(list), listSize)
		}
	}
	
	pub fn from(name: &CStr) -> Option<Self>
	{
		match unsafe { mbedtls_sys::mbedtls_ssl_get_ciphersuite_id(name.as_ptr()) }
		{
			Self::NoCipherSuiteId => None,
			value @ _ => CipherSuite::from_i32(value),
		}
	}
	
	pub fn name(&self) -> &'static CStr
	{
		let cipherSuiteId: c_int = *self as c_int;
		unsafe
		{
			let name = mbedtls_sys::mbedtls_ssl_get_ciphersuite_name(cipherSuiteId);
			debug_assert!(!name.is_null(), "mbedtls_ssl_get_ciphersuite_name() returned NULL - probably an API vs linked library incompatibility");
			CStr::from_ptr(name)
		}
	}
}

#[cfg(test)]
mod tests
{
	use super::*;
	use ::std::ffi::CStr;
	use ::std::ffi::CString;
	use ::CipherSuiteParseError;
	
	#[test]
	fn fmt()
	{
		const expected: CipherSuite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
		let name = expected.name();
		let expectedDisplay = name.to_string_lossy();
		let actual = format!("{}", expected);
		assert_eq!(expectedDisplay, actual);
	}
	
	#[test]
	fn from_str()
	{
		const invalid: &'static str = "\0";
		let expectedError = CipherSuiteParseError::ContainsNul(invalid.to_owned());
		let actual: Result<CipherSuite, CipherSuiteParseError> = invalid.parse();
		assert_eq!(expectedError, actual.err().unwrap());
		
		const knownIncorrectName: &'static str = "Known Incorrect Name";
		let expectedError = CipherSuiteParseError::Unknown(knownIncorrectName.to_owned());
		let actual: Result<CipherSuite, CipherSuiteParseError> = knownIncorrectName.parse();
		assert_eq!(expectedError, actual.err().unwrap());
		
		const expectedOk: CipherSuite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
		let knownGoodName = expectedOk.name().to_str().unwrap();
		let actual = knownGoodName.parse().unwrap();
		assert_eq!(expectedOk, actual);
	}
	
	#[test]
	fn ciphersuites()
	{
		let suites = CipherSuite::allSupportedCipherSuites();
		assert!(suites.len() > 0);
	}
	
	#[test]
	fn from()
	{
		const expected: CipherSuite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
		let name = expected.name();
		let actual = CipherSuite::from(name).unwrap();
		assert_eq!(expected, actual);
	}
	
	#[test]
	fn name()
	{
		let expected: &CStr = &CString::new("TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384").unwrap();
		let actual = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.name();
		assert_eq!(expected, actual);
	}
}
