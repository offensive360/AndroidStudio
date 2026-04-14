package com.offensive360.sast.settings

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage

@State(name = "O360SASTSettings", storages = [Storage("o360sast.xml")])
class O360Settings : PersistentStateComponent<O360Settings.State> {

    data class State(
        var endpoint: String = "",
        var accessToken: String = "",
        var allowSelfSignedCerts: Boolean = false
    )

    private var state = State()

    override fun getState(): State = state

    override fun loadState(state: State) {
        this.state = state
    }

    var endpoint: String
        get() = state.endpoint
        set(value) { state.endpoint = value }

    var accessToken: String
        get() = state.accessToken
        set(value) { state.accessToken = value }

    var allowSelfSignedCerts: Boolean
        get() = state.allowSelfSignedCerts
        set(value) { state.allowSelfSignedCerts = value }

    val isConfigured: Boolean
        get() = endpoint.isNotBlank() && accessToken.isNotBlank()

    companion object {
        fun getInstance(): O360Settings =
            ApplicationManager.getApplication().getService(O360Settings::class.java)
    }
}
