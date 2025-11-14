/*
 * Copyright (c) 2025 Indicio
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * This software may be modified and distributed under the terms
 * of either the Apache License, Version 2.0 or the MIT license.
 * See the LICENSE-APACHE and LICENSE-MIT files for details.
 */

package tech.indicio.isomdl_uniffi

import uniffi.isomdl_uniffi.Disposable

class UniffiStack internal constructor(){
    private val stack = mutableListOf<Disposable>()

    /**
     * Helper function to add disposable objects to stack
     */
    fun <T: Disposable>T.toStack(): T {
        stack.add(this)
        return this
    }

    /**
     * Remove all disposable objects from stack
     */
    fun close(){
        stack.forEach{
            it.destroy()
        }
    }
}

/**
 * Function that keeps track of disposable objects and disposes them for you.
 * Add them to stack by calling `Disposable.toStack()` while inside the scope.
 */
suspend fun <T> uniffiStack(init: suspend UniffiStack.() -> T):T{
    val stack = UniffiStack()
    val ret = stack.init()
    stack.close()
    return ret
}
