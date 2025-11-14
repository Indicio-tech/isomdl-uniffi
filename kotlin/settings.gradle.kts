/*
 * Copyright (c) 2025 Indicio
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * This software may be modified and distributed under the terms
 * of either the Apache License, Version 2.0 or the MIT license.
 * See the LICENSE-APACHE and LICENSE-MIT files for details.
 */

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")
pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "isomdl-uniffi"
