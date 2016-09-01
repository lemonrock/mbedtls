// This file is part of mbedtls. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT. No part of mbedtls, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2016 The developers of mbedtls. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT.


use ::std::ops::Deref;
use ::std::ops::DerefMut;
use ::std::mem::transmute;
use ::std::ptr::copy_nonoverlapping;
use ::std::os::raw::c_char;
use ::std::os::raw::c_int;
use ::std::os::raw::c_uint;
extern crate libc;
use self::libc::uint32_t;
extern crate mbedtls_sys;
use self::mbedtls_sys::mbedtls_ssl_config;
use ::SslContext;
use ::Endpoint;
use ::Transport;
use ::Verify;
use ::DtlsAntiReplayMode;
use ::CipherSuite;
use ::MaximumSizeOfNulTerminatedCipherSuiteList;


type NulTerminatedListOfCipherSuites = Vec<i32>;

#[derive(Clone, Debug)]
pub struct SslConfig(pub mbedtls_ssl_config, NulTerminatedListOfCipherSuites);

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
		const dtlsBadMacLimit: c_uint = 0; // 0 is no limit
		const dtlsHandshakeTimeoutMillisecondsMinimum: uint32_t = 0;
		const dtlsHandshakeTimeoutMillisecondsMaximum: uint32_t = 60000;
		
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
			mbedtls_sys::mbedtls_ssl_conf_dtls_badmac_limit(reference, dtlsBadMacLimit);
			mbedtls_sys::mbedtls_ssl_conf_handshake_timeout(reference, dtlsHandshakeTimeoutMillisecondsMinimum, dtlsHandshakeTimeoutMillisecondsMaximum);
			
			//mbedtls_ssl_conf_session_cache
			
			
		}
		
		let mut sslConfig = SslConfig(value, Vec::with_capacity(*MaximumSizeOfNulTerminatedCipherSuiteList));
		let cipherSuites = vec![CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384];
		sslConfig.setCipherSuites(&cipherSuites);
		sslConfig
	}
	
	// The ciphersuites array is not copied, and must remain valid for the lifetime of the ssl_config.
	fn setCipherSuites(&mut self, cipherSuites: &[CipherSuite])
	{
		const EndOfList: i32 = 0;
		
		let length = cipherSuites.len();
		let ref mut nulTerminatedList = self.1;
		//nulTerminatedList.clear();  Causes all existing elements to be dropped in place; we can avoid this because we known CipherSuite is just an enum of i32
		unsafe
		{
			copy_nonoverlapping(transmute::<_, *const c_int>(cipherSuites.as_ptr()), nulTerminatedList.as_mut_ptr(), length);
			nulTerminatedList.set_len(length);
		}
		nulTerminatedList.push(EndOfList);
		
		let reference = &mut self.0;
		unsafe
		{
			mbedtls_sys::mbedtls_ssl_conf_ciphersuites(reference, nulTerminatedList.as_ptr());
		}
	}
	
	// The SslConfig MUST outlive the SslContext
	#[inline(always)]
	pub fn newSslContext<'a>(&'a self) -> Option<SslContext>
	{
		SslContext::new(self)
	}
}
