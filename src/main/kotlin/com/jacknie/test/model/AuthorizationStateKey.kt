package com.jacknie.test.model

open class AuthorizationStateKey(
    val responseType: String,
    val clientId: String,
    val code: String,
    val redirectUri: String,
) {

    override fun equals(other: Any?) = other is AuthorizationStateKey &&
        responseType == other.responseType &&
        clientId == other.clientId &&
        redirectUri == other.redirectUri &&
        code == other.code

}
