// This file is part of mbedtls. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT. No part of mbedtls, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2016 The developers of mbedtls. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT.


extern crate mbedtls_sys;


#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, NumFromPrimitive)]
#[repr(i8)]
pub enum DtlsAntiReplayMode
{
	Enabled = mbedtls_sys::MBEDTLS_SSL_ANTI_REPLAY_ENABLED,
	Disabled = mbedtls_sys::MBEDTLS_SSL_ANTI_REPLAY_DISABLED,
}


