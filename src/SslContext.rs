// This file is part of mbedtls. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT. No part of mbedtls, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2016 The developers of mbedtls. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT.


use ::std::ops::Drop;
use ::std::marker::PhantomData;
use ::std::os::raw::c_int;
//use ::std::os::raw::c_void;
extern crate mbedtls_sys;
// use self::mbedtls_sys::mbedtls_ssl_send_t;
// use self::mbedtls_sys::mbedtls_ssl_recv_t;
// use self::mbedtls_sys::mbedtls_ssl_recv_timeout_t;
use self::mbedtls_sys::mbedtls_ssl_context;
use self::mbedtls_sys::MBEDTLS_ERR_SSL_ALLOC_FAILED;
use self::mbedtls_sys::MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
use self::mbedtls_sys::MBEDTLS_ERR_SSL_COMPRESSION_FAILED;
use ::SslConfig;


#[derive(Clone, Debug)]
pub struct SslContext<'a>(mbedtls_ssl_context, PhantomData<&'a SslConfig>);

impl<'a> Drop for SslContext<'a>
{
	fn drop(&mut self)
	{
		unsafe
		{
			mbedtls_sys::mbedtls_ssl_free(&mut self.0);
		}
	}
}

impl<'a> SslContext<'a>
{
	const NoError: c_int = 0;
	
	// TODO: If we panic after mbedtls_ssl_setup but before returning, we need to free 'value' to prevent a memory leak
	// , bioContext: *mut c_void, sendCallback: mbedtls_ssl_send_t, receiveCallback: mbedtls_ssl_recv_t
	#[inline(always)]
	pub fn new(sslConfig: &'a SslConfig) -> Option<SslContext<'a>>
	{
		//const readWithTimeoutCallback: mbedtls_ssl_recv_timeout_t = None;
		
		let mut value = mbedtls_ssl_context::default();
		
		unsafe
		{
			let reference = &mut value;
			mbedtls_sys::mbedtls_ssl_init(reference);
			match mbedtls_sys::mbedtls_ssl_setup(reference, &sslConfig.0)
			{
				Self::NoError => {},
				MBEDTLS_ERR_SSL_ALLOC_FAILED => return None,
				undocumented @ _ => panic!("Received undocumented error code '{}' from mbedtls_ssl_setup()", undocumented),
			}
			//mbedtls_sys::mbedtls_ssl_set_bio(reference, bioContext, sendCallback, receiveCallback, readWithTimeoutCallback);
			//mbedtls_sys::mbedtls_ssl_set_timer_cb;
			//mbedtls_sys::mbedtls_ssl_set_client_transport_id(reference, info, length);
		}
		
		Some(SslContext(value, PhantomData))
	}
	
	#[inline(always)]
	pub fn reset(&mut self) -> Option<()>
	{
		match unsafe { mbedtls_sys::mbedtls_ssl_session_reset(&mut self.0) }
		{
			Self::NoError => Some(()),
			MBEDTLS_ERR_SSL_ALLOC_FAILED => None,
			MBEDTLS_ERR_SSL_HW_ACCEL_FAILED => panic!("mbedtls_ssl_session_reset() failed due to hardware acceleration failure"),
			MBEDTLS_ERR_SSL_COMPRESSION_FAILED => panic!("mbedtls_ssl_session_reset() failed due to compression failure"),
			undocumented @ _ => panic!("Received undocumented error code '{}' from mbedtls_ssl_session_reset()", undocumented),
		}
	}
}
