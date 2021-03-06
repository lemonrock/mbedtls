// This file is part of mbedtls. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT. No part of mbedtls, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2016 The developers of mbedtls. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls/master/COPYRIGHT.


extern crate mbedtls_sys;
use self::mbedtls_sys::mbedtls_ssl_session;


#[allow(missing_debug_implementations)]
#[derive(Clone, Copy)]
pub struct SslSession(pub mbedtls_ssl_session);

impl SslSession
{
}
