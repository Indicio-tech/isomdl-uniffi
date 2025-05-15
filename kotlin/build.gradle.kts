import org.jetbrains.kotlin.gradle.dsl.JvmTarget

import gobley.gradle.cargo.dsl.jvm
import gobley.gradle.GobleyHost
import gobley.gradle.Variant
import gobley.gradle.cargo.dsl.linux
import gobley.gradle.rust.targets.RustWindowsTarget
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSetTree

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    id("dev.gobley.cargo") version "0.2.0"
    id("dev.gobley.uniffi") version "0.2.0"
    kotlin("plugin.atomicfu") version libs.versions.kotlin
    kotlin("plugin.serialization") version "2.1.20"
}

cargo {
    jvmVariant = Variant.Release
    nativeVariant = Variant.Release
    packageDirectory = layout.projectDirectory.dir("src/commonMain/rust/")

    if(GobleyHost.Platform.MacOS.isCurrent){
        val home = System.getProperty("user.home")
        val crossFile = File("$home/.cargo/bin/cross")
        builds{
            linux{
                variants{
                    buildTaskProvider.configure {
                        cargo = crossFile
                    }
                }
            }
        }
    }

    builds.jvm{
        if(GobleyHost.Platform.MacOS.isCurrent){
            embedRustLibrary = when (rustTarget){
                RustWindowsTarget.X64 -> false
                RustWindowsTarget.Arm64 -> false
                else -> true
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
    ndkVersion = "26.1.10909125"
    defaultConfig {
        minSdk = 24
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}
