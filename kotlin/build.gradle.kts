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
                username = localProperties.getProperty("githubUsername")
                password = localProperties.getProperty("githubToken")
            }
        }
    }
}

cargo {
    jvmVariant = Variant.Release
    nativeVariant = Variant.Release
    packageDirectory = layout.projectDirectory.dir("src/commonMain/rust/")

    builds{
        if (GobleyHost.Platform.MacOS.isCurrent) {
            val home = System.getProperty("user.home")
            val crossFile = File("$home/.cargo/bin/cross")
            linux {
                variants {
                    buildTaskProvider.configure {
                        this@configure.cargo = crossFile
                    }
                }
            }
        }

        jvm{
            // Linux-host build for holdr-sdk CLI: emit a per-target classifier jar
            // (embedRustLibrary=false) instead of embedding the .so in the main jar,
            // so it matches the `:linux-x86-64` coordinate holdr-sdk consumes.
            embedRustLibrary = false
        }
    }
}

uniffi{
    generateFromLibrary{
        // Pin bindings generation to the Linux JVM target; default picked iosArm64
        // which cannot link on a Linux host.
        build.set(RustPosixTarget.LinuxX64)
    }
}

kotlin {
    jvmToolchain(17)
    applyDefaultHierarchyTemplate()

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
    }
}
