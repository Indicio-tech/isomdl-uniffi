/*
 * Copyright (c) 2025 Indicio
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * This software may be modified and distributed under the terms
 * of either the Apache License, Version 2.0 or the MIT license.
 * See the LICENSE-APACHE and LICENSE-MIT files for details.
 */

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

import gobley.gradle.cargo.dsl.jvm
import gobley.gradle.cargo.dsl.android
import gobley.gradle.GobleyHost
import gobley.gradle.Variant
import gobley.gradle.cargo.dsl.linux
import gobley.gradle.rust.targets.RustPosixTarget
import gobley.gradle.rust.targets.RustWindowsTarget
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSetTree
import java.util.Properties

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    id("dev.gobley.cargo") version "0.3.7"
    id("dev.gobley.uniffi") version "0.3.7"
    kotlin("plugin.atomicfu") version libs.versions.kotlin
    kotlin("plugin.serialization") version "2.1.20"
    id("maven-publish")
}

group = "tech.indicio"
version = "0.0.3"

val localProperties = Properties().apply {
    val file = rootProject.file("local.properties")
    if (file.exists()) {
        load(file.inputStream())
    }
}

publishing {
    repositories{
        mavenLocal()
        maven {
            name = "github"
            setUrl("https://maven.pkg.github.com/indicio-tech/isomdl-uniffi")
            credentials{
                username = localProperties.getProperty("githubUsername") ?: System.getenv("GITHUB_ACTOR")
                password = localProperties.getProperty("githubToken") ?: System.getenv("GITHUB_TOKEN")
            }
        }
    }
}

cargo {
    jvmVariant = Variant.Release
    nativeVariant = Variant.Release
    packageDirectory = layout.projectDirectory.dir("src/commonMain/rust/")

    builds{
        jvm{
            if(GobleyHost.Platform.MacOS.isCurrent){
                embedRustLibrary = when (rustTarget){
                    RustWindowsTarget.X64 -> false
                    RustWindowsTarget.Arm64 -> false
                    else -> true
                }
                if (rustTarget == RustPosixTarget.MinGWX64) {
                    variants {
                        dynamicLibraries.set(listOf("isomdl_uniffi.dll"))
                    }
                }
            }
        }

        android{
            variants{
                buildTaskProvider.configure {
                    additionalEnvironment.put("RUSTFLAGS", "-C link-args=-Wl,-z,max-page-size=16384")
                }
            }
        }
    }
}

uniffi{
    generateFromLibrary()
}

kotlin {
    jvmToolchain(17)
    applyDefaultHierarchyTemplate()

    androidTarget {
        publishLibraryVariants("release")
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_11)
        }
        instrumentedTestVariant.sourceSetTree.set(KotlinSourceSetTree.test)
        unitTestVariant.sourceSetTree.set(KotlinSourceSetTree.unitTest)
    }

    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
            freeCompilerArgs.add("-Xdebug")
        }

        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
        }
    }

    macosX64()
    macosArm64()
    iosX64()
    iosSimulatorArm64()
    iosArm64()


    sourceSets {
        commonMain.dependencies {
            //put your multiplatform dependencies here
            implementation(libs.kotlinx.serialization.json)
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
            implementation(libs.kotlinx.coroutines.test)
        }
        nativeTest.dependencies {
        }
        jvmTest.dependencies {
        }
        androidUnitTest.dependencies{
        }
    }
}

android {
    namespace = "tech.indicio.isomdl_uniffi"
    compileSdk = 35

    // Use the specific NDK version recommended for this project
    // This version will be automatically installed in CI environments
    ndkVersion = "28.2.13676358"

    defaultConfig {
        minSdk = 24
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}
