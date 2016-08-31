// This file is part of mbedtls. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT. No part of mbedtls, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2016 The developers of mbedtls. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT.


use std::os::raw::c_void;
//extern crate libc;
//use self::libc::c_int;
extern crate mbedtls_sys;
use self::mbedtls_sys::mbedtls_ssl_send_t;
use self::mbedtls_sys::mbedtls_ssl_recv_t;
use self::mbedtls_sys::mbedtls_ssl_recv_timeout_t;
use self::mbedtls_sys::mbedtls_ssl_context;
use self::mbedtls_sys::mbedtls_ssl_set_bio;


const readWithTimeoutCallback: mbedtls_ssl_recv_timeout_t = None;

#[derive(Copy, Clone, Debug)]
pub struct SslContext(mbedtls_ssl_context);

impl SslContext
{
	#[inline(always)]
	pub fn new(bioContext: *mut c_void, sendCallback: mbedtls_ssl_send_t, receiveCallback: mbedtls_ssl_recv_t) -> SslContext
	{
		let mut value = mbedtls_ssl_context::default();
		
		unsafe
		{
			let reference = &mut value;
			mbedtls_ssl_set_bio(reference, bioContext, sendCallback, receiveCallback, readWithTimeoutCallback);
		}
		
		SslContext(value)
	}
}
