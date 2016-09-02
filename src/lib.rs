// This file is part of mbedtls. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT. No part of mbedtls, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2016 The developers of mbedtls. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT.


#![feature(associated_consts)]
#![feature(const_fn)]
#![feature(custom_derive)]
#![feature(plugin)]
#![plugin(num_macros)]

#[allow(unused_extern_crates)] #[macro_use] extern crate quick_error;
#[allow(unused_extern_crates)] #[macro_use] extern crate lazy_static;
#[allow(unused_extern_crates)] #[macro_use] extern crate bitflags;
extern crate num;

macro_rules! bitflags_combine
{
	( $bitflagsTypeName:ident ) =>
	{
		impl $bitflagsTypeName
		{
			// We'd like to use  MessageDigestFlags::from_iter(allowedMessageDigests); in regular code
			// but the Iterator from a slice returns &element, not element and so can not be used!
			pub fn combine(flags: &[Self]) -> Self
			{
				match flags.len()
				{
					0 => Self::empty(),
					1 => flags[0],
					2 => flags[0] | flags[1],
					3 => $bitflagsTypeName {bits: flags[0].bits | flags[1].bits | flags[2].bits}, // Doing it this way rather than flags[0] | flags[1] | flags[2] reduces allocations, although they're all stack-based in any event
					4 => $bitflagsTypeName {bits: flags[0].bits | flags[1].bits | flags[2].bits | flags[3].bits},
					_ =>
					{
						let mut bits: uint32_t = 0;
						for flag in flags
						{
							bits |= (*flag).bits;
						}
						$bitflagsTypeName {bits: bits}
					}
				}
			}
		}
	}
}

#[path="SslConfig.rs"] mod _SslConfig; pub use _SslConfig::*;
#[path="SslContext.rs"] mod _SslContext; pub use _SslContext::*;
#[path="SslSession.rs"] mod _SslSession; pub use _SslSession::*;
#[path="X509Certificate.rs"] mod _X509Certificate; pub use _X509Certificate::*;
#[path="X509CertificateProfile.rs"] mod _X509CertificateProfile; pub use _X509CertificateProfile::*;
#[path="X509CertificateRevocationList.rs"] mod _X509CertificateRevocationList; pub use _X509CertificateRevocationList::*;
#[path="CipherSuite.rs"] mod _CipherSuite; pub use _CipherSuite::*;
#[path="CipherSuiteParseError.rs"] mod _CipherSuiteParseError; pub use _CipherSuiteParseError::*;
#[path="TlsVersion.rs"] mod _TlsVersion; pub use _TlsVersion::*;
#[path="TlsMajorVersion.rs"] mod _TlsMajorVersion; pub use _TlsMajorVersion::*;
#[path="TlsMinorVersion.rs"] mod _TlsMinorVersion; pub use _TlsMinorVersion::*;
#[path="Endpoint.rs"] mod _Endpoint; pub use _Endpoint::*;
#[path="Transport.rs"] mod _Transport; pub use _Transport::*;
#[path="Verify.rs"] mod _Verify; pub use _Verify::*;
#[path="DtlsAntiReplayMode.rs"] mod _DtlsAntiReplayMode; pub use _DtlsAntiReplayMode::*;
#[path="MessageDigestFlags.rs"] mod _MessageDigestFlags; pub use _MessageDigestFlags::*;
