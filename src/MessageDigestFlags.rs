// This file is part of mbedtls. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT. No part of mbedtls, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2016 The developers of mbedtls. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT.


use ::std::default::Default;
extern crate libc;
use self::libc::uint32_t;
extern crate mbedtls_sys;
use self::mbedtls_sys::mbedtls_md_type_t;
use self::mbedtls_sys::mbedtls_md_type_t::*;
use ::MBEDTLS_X509_ID_FLAG;


bitflags!
{
	pub flags MessageDigestFlags: uint32_t
	{
		//const None = MBEDTLS_MD_NONE as uint32_t,
		const MD2 = MBEDTLS_X509_ID_FLAG_messageDigest(MBEDTLS_MD_MD2),
		const MD4 = MBEDTLS_X509_ID_FLAG_messageDigest(MBEDTLS_MD_MD4),
		const MD5 = MBEDTLS_X509_ID_FLAG_messageDigest(MBEDTLS_MD_MD5),
		const SHA1 = MBEDTLS_X509_ID_FLAG_messageDigest(MBEDTLS_MD_SHA1),
		const SHA224 = MBEDTLS_X509_ID_FLAG_messageDigest(MBEDTLS_MD_SHA224),
		const SHA256 = MBEDTLS_X509_ID_FLAG_messageDigest(MBEDTLS_MD_SHA256),
		const SHA384 = MBEDTLS_X509_ID_FLAG_messageDigest(MBEDTLS_MD_SHA384),
		const SHA512 = MBEDTLS_X509_ID_FLAG_messageDigest(MBEDTLS_MD_SHA512),
		const RIPEMD160 = MBEDTLS_X509_ID_FLAG_messageDigest(MBEDTLS_MD_RIPEMD160),
	}
}

impl Default for MessageDigestFlags
{
	fn default() -> Self
	{
		Self::empty()
	}
}

bitflags_combine!(MessageDigestFlags);

const fn MBEDTLS_X509_ID_FLAG_messageDigest(id: mbedtls_md_type_t) -> uint32_t
{
	MBEDTLS_X509_ID_FLAG(id as uint32_t)
}
