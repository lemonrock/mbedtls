// This file is part of mbedtls. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT. No part of mbedtls, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2016 The developers of mbedtls. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT.


use ::std::ops::Deref;
use ::std::ops::DerefMut;
use ::std::ops::Drop;
use ::std::mem::transmute;
use ::std::mem::drop;
use ::std::ptr::copy_nonoverlapping;
use ::std::ptr::write;
use ::std::ptr::null_mut;
use ::std::os::raw::c_char;
use ::std::os::raw::c_int;
use ::std::os::raw::c_uint;
use ::std::ffi::CString;
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
use ::TlsVersion;


type NulTerminatedListOfCipherSuites = Vec<i32>;


type NulTerminatedListOfApplicationProtocols = Vec<*mut c_char>;


#[derive(Clone, Debug)]
pub struct SslConfig(pub mbedtls_ssl_config, NulTerminatedListOfCipherSuites, NulTerminatedListOfApplicationProtocols);

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

impl Drop for SslConfig
{
	fn drop(&mut self)
	{
		self.dropListOfApplicationProtocols();
	}
}

impl SslConfig
{
	#[inline(always)]
	pub fn new(endpoint: Endpoint, transport: Transport, authenticationMode: Verify, cipherSuites: &[CipherSuite], applicationLayerProtocols: &[&str]) -> SslConfig
	{
		const LikelyNumberOfApplicationLayerProtocolsPlusOne: usize = 4;
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
			
			// Deprecated: mbedtls_ssl_conf_arc4_support
			// Deprecated: mbedtls_ssl_conf_cbc_record_splitting
			
			//mbedtls_sys::mbedtls_ssl_conf_ca_chain(reference, certificateAuthorityChain, certificateAuthorityReovicationList);
		}
		
		let mut sslConfig = SslConfig
		(
			value,
			Vec::with_capacity(*MaximumSizeOfNulTerminatedCipherSuiteList),
			Vec::with_capacity(LikelyNumberOfApplicationLayerProtocolsPlusOne),
		);
		sslConfig.setCipherSuites(cipherSuites);
		sslConfig.setApplicationLayerProtocols(applicationLayerProtocols);
		sslConfig
	}
	
	pub fn setCipherSuitesForVersion(&mut self, cipherSuites: &[CipherSuite], tlsVersion: TlsVersion)
	{
		unsafe
		{
			self.copyCipherSuitesIntoVecWithoutIncreasingCapacity(cipherSuites);
			let reference = &mut self.0;
			mbedtls_sys::mbedtls_ssl_conf_ciphersuites_for_version(reference, self.1.as_ptr(), tlsVersion.major() as c_int, tlsVersion.minor() as c_int);
		}
	}
	
	// The SslConfig MUST outlive the SslContext
	#[inline(always)]
	pub fn newSslContext<'a>(&'a self) -> Option<SslContext>
	{
		SslContext::new(self)
	}
	
	// WARN: Assumes Vec has correct capacity
	unsafe fn copyCipherSuitesIntoVecWithoutIncreasingCapacity(&mut self, cipherSuites: &[CipherSuite])
	{
		const EndOfList: i32 = 0;

		let ref mut nulTerminatedList = self.1;
		let length = cipherSuites.len();
		debug_assert!(nulTerminatedList.capacity() >= length + 1, "nulTerminatedList does not have sufficient capacity; are you passing a cipherSuites bigger than the maximum?");

		//nulTerminatedList.clear();  Causes all existing elements to be dropped in place; we can avoid this because we know nulTerminatedList is just i32
		let nulTerminatedListPointer = nulTerminatedList.as_mut_ptr();
		copy_nonoverlapping(transmute::<_, *const c_int>(cipherSuites.as_ptr()), nulTerminatedListPointer, length);
		write(nulTerminatedListPointer.offset(length as isize), EndOfList);
		nulTerminatedList.set_len(length + 1);
	}
	
	// The ciphersuites array is not copied, and must remain valid for the lifetime of the ssl_config.
	fn setCipherSuites(&mut self, cipherSuites: &[CipherSuite])
	{
		unsafe
		{
			self.copyCipherSuitesIntoVecWithoutIncreasingCapacity(cipherSuites);
			let reference = &mut self.0;
			mbedtls_sys::mbedtls_ssl_conf_ciphersuites(reference, self.1.as_ptr());
		}
	}
	
	fn setApplicationLayerProtocols(&mut self, applicationLayerProtocols: &[&str])
	{
		self.dropListOfApplicationProtocols();
		
		let ref mut nulTerminatedList = self.2;
		let length = applicationLayerProtocols.len();
		
		nulTerminatedList.reserve(length + 1);
		for applicationLayerProtocol in applicationLayerProtocols
		{
			// Annoyingly, this does a capacity check for every push
			nulTerminatedList.push(CString::new(*applicationLayerProtocol).unwrap().into_raw());
		}
		nulTerminatedList.push(null_mut());
	}
	
	fn dropListOfApplicationProtocols(&mut self)
	{
		let actualLength = self.2.len() - 1;
		for index in 0..actualLength
		{
			unsafe { drop(CString::from_raw(self.2[index])) };
		}
		unsafe { self.2.set_len(0) };
	}
}
