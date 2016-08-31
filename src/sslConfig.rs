// This file is part of mbedtls. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT. No part of mbedtls, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2016 The developers of mbedtls. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT.


extern crate libc;
use self::libc::c_int;
extern crate mbedtls_sys;
use self::mbedtls_sys::mbedtls_ssl_config;
use self::mbedtls_sys::mbedtls_ssl_conf_endpoint;
use self::mbedtls_sys::mbedtls_ssl_conf_transport;
use self::mbedtls_sys::mbedtls_ssl_conf_authmode;
//use self::mbedtls_sys::mbedtls_ssl_conf_verify;
//use self::mbedtls_sys::mbedtls_ssl_conf_rng;
//use self::mbedtls_sys::mbedtls_ssl_conf_dbg;


#[derive(Copy, Clone, Debug)]
pub struct SslConfig(mbedtls_ssl_config);

impl SslConfig
{
	#[inline(always)]
	pub fn new(endpoint: Endpoint, transport: Transport, authenticationMode: Verify) -> SslConfig
	{
		let mut value = mbedtls_ssl_config::default();
		
		unsafe
		{
			let reference = &mut value;
			mbedtls_ssl_conf_endpoint(reference, endpoint as c_int);
			mbedtls_ssl_conf_transport(reference, transport as c_int);
			mbedtls_ssl_conf_authmode(reference, authenticationMode as c_int);
			//mbedtls_ssl_conf_verify(reference, verificationCallback, verificationCallbackContext);
			//mbedtls_ssl_conf_rng(reference, randomNumberGeneratorCallback, randomNumberGeneratorCallbackContext);
			//mbedtls_ssl_conf_dbg(reference, debugCallback, debugCallbackContext);
		}
		
		SslConfig(value)
	}
}

use self::mbedtls_sys::MBEDTLS_SSL_IS_CLIENT;
use self::mbedtls_sys::MBEDTLS_SSL_IS_SERVER;
#[derive(Clone, Copy, Debug)]
#[repr(i32)]
pub enum Endpoint
{
	Client = MBEDTLS_SSL_IS_CLIENT as c_int,
	Server = MBEDTLS_SSL_IS_SERVER as c_int,
}

use self::mbedtls_sys::MBEDTLS_SSL_TRANSPORT_STREAM;
use self::mbedtls_sys::MBEDTLS_SSL_TRANSPORT_DATAGRAM;
#[derive(Clone, Copy, Debug)]
#[repr(i32)]
pub enum Transport
{
	Stream = MBEDTLS_SSL_TRANSPORT_STREAM as c_int,
	Datagram = MBEDTLS_SSL_TRANSPORT_DATAGRAM as c_int,
}

use self::mbedtls_sys::MBEDTLS_SSL_VERIFY_NONE;
use self::mbedtls_sys::MBEDTLS_SSL_VERIFY_OPTIONAL;
use self::mbedtls_sys::MBEDTLS_SSL_VERIFY_REQUIRED;
#[derive(Clone, Copy, Debug)]
#[repr(i32)]
pub enum Verify
{
	None = MBEDTLS_SSL_VERIFY_NONE as c_int,
	Optional = MBEDTLS_SSL_VERIFY_OPTIONAL as c_int,
	Required = MBEDTLS_SSL_VERIFY_REQUIRED as c_int,
}
