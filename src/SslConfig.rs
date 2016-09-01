// This file is part of mbedtls. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT. No part of mbedtls, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2016 The developers of mbedtls. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT.


use ::std::ops::Deref;
use ::std::ops::DerefMut;
use ::std::os::raw::c_char;
use ::std::os::raw::c_int;
extern crate libc;
use self::libc::uint32_t;
extern crate mbedtls_sys;
use self::mbedtls_sys::mbedtls_ssl_config;
use ::SslContext;
use ::Endpoint;
use ::Transport;
use ::Verify;
use ::DtlsAntiReplayMode;


#[derive(Copy, Clone, Debug)]
pub struct SslConfig(pub mbedtls_ssl_config);

impl Deref for SslConfig
{
	type Target = mbedtls_ssl_config;

	fn deref(&self) -> &mbedtls_ssl_config
	{
		&self.0
	}
}

impl DerefMut for SslConfig
{
	fn deref_mut(&mut self) -> &mut mbedtls_ssl_config
	{
		&mut self.0
	}
}

impl SslConfig
{
	#[inline(always)]
	pub fn new(endpoint: Endpoint, transport: Transport, authenticationMode: Verify) -> SslConfig
	{
		const NoReadTimeout: uint32_t = 0;
		const dtlsAntiReplayMode: DtlsAntiReplayMode = DtlsAntiReplayMode::Enabled;
		
		let mut value = mbedtls_ssl_config::default();
		
		unsafe
		{
			let reference = &mut value;
			mbedtls_sys::mbedtls_ssl_conf_endpoint(reference, endpoint as c_int);
			mbedtls_sys::mbedtls_ssl_conf_transport(reference, transport as c_int);
			mbedtls_sys::mbedtls_ssl_conf_authmode(reference, authenticationMode as c_int);
			//mbedtls_sys::mbedtls_ssl_conf_verify(reference, verificationCallback, verificationCallbackContext);
			//mbedtls_sys::mbedtls_ssl_conf_rng(reference, randomNumberGeneratorCallback, randomNumberGeneratorCallbackContext);
			//mbedtls_sys::mbedtls_ssl_conf_dbg(reference, debugCallback, debugCallbackContext);
			mbedtls_sys::mbedtls_ssl_conf_read_timeout(reference, NoReadTimeout);
			//mbedtls_sys::mbedtls_ssl_conf_session_tickets_cb(reference, ticketWriteCallback, ticketParseCallback, ticketCallbackContext);
			//mbedtls_ssl_conf_export_keys_cb
			//mbedtls_ssl_conf_dtls_cookies
			mbedtls_sys::mbedtls_ssl_conf_dtls_anti_replay(reference, dtlsAntiReplayMode as c_char);
		}
		
		SslConfig(value)
	}
	
	// The SslConfig MUST outlive the SslContext
	#[inline(always)]
	pub fn newSslContext<'a>(&'a self) -> Option<SslContext<'a>>
	{
		SslContext::new(self)
	}
}
