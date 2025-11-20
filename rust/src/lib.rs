// Copyright (c) 2022 Spruce Systems, Inc.
// Portions Copyright (c) 2025 Indicio
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// This software may be modified and distributed under the terms
// of either the Apache License, Version 2.0 or the MIT license.
// See the LICENSE-APACHE and LICENSE-MIT files for details.
//
// This project contains code from Spruce Systems, Inc.
// https://github.com/spruceid/sprucekit-mobile

use uuid::Uuid;

uniffi::setup_scaffolding!();

pub mod mdl;

uniffi::custom_type!(Uuid, String);

impl UniffiCustomTypeConverter for Uuid {
    type Builtin = String;
    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self>
    where
        Self: ::std::marker::Sized,
    {
        Ok(val.parse()?)
    }
    fn from_custom(obj: Self) -> Self::Builtin {
        obj.to_string()
    }
}
