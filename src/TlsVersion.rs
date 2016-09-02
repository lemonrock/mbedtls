// This file is part of mbedtls. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT. No part of mbedtls, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2016 The developers of mbedtls. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT.


use ::std::default::Default;
use ::TlsMajorVersion;
use ::TlsMinorVersion;


#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsVersion
{
	major: TlsMajorVersion,
	minor: TlsMinorVersion,
}

impl Default for TlsVersion
{
	fn default() -> Self
	{
		Self::Tls_1_2
	}
}

impl TlsVersion
{
	pub const Ssl_3: TlsVersion = TlsVersion { major: TlsMajorVersion::Version3, minor: TlsMinorVersion::Version0 };
	pub const Tls_1_0: TlsVersion = TlsVersion { major: TlsMajorVersion::Version3, minor: TlsMinorVersion::Version1 };
	pub const Tls_1_1: TlsVersion = TlsVersion { major: TlsMajorVersion::Version3, minor: TlsMinorVersion::Version2 };
	pub const Tls_1_2: TlsVersion = TlsVersion { major: TlsMajorVersion::Version3, minor: TlsMinorVersion::Version3 };
	pub const Dtls_1_0: TlsVersion = TlsVersion::Tls_1_1;
	pub const Dtls_1_2: TlsVersion = TlsVersion::Tls_1_2;
	
	#[inline(always)]
	pub fn major(&self) -> TlsMajorVersion
	{
		self.major
	}
	
	#[inline(always)]
	pub fn minor(&self) -> TlsMinorVersion
	{
		self.minor
	}
}
