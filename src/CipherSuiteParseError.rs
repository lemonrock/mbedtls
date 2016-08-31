// This file is part of mbedtls. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT. No part of mbedtls, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2016 The developers of mbedtls. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT.


quick_error!
{
	#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
	pub enum CipherSuiteParseError
	{
		ContainsNul(cipherSuiteName: String)
		{
			description("Cipher Suite name contains NUL")
			display("Cipher Suite name '{}' contains NUL", cipherSuiteName)
		}
		
		Unknown(cipherSuiteName: String)
		{
			description("Cipher Suite name is unknown")
			display("Cipher Suite name '{}' is unknown", cipherSuiteName)
		}
	}
}
