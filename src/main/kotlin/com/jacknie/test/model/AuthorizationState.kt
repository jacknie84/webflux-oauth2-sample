package com.jacknie.test.model

import java.time.Instant
import org.springframework.security.core.userdetails.UserDetails

class AuthorizationState(

    responseType: String,
    clientId: String,
    val scopes: Set<String>,
    redirectUri: String,
    val state: String? = null,
    code: String,
    val userDetails: UserDetails,

) : AuthorizationStateKey(responseType, clientId, code, redirectUri) {

    val expiresAt: Instant = Instant.now().plusSeconds(360)

}
