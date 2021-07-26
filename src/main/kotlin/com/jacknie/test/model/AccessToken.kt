package com.jacknie.test.model

import com.fasterxml.jackson.annotation.JsonProperty

data class AccessToken(

    @get: JsonProperty("token_type")
    val tokenType: String,

    @get: JsonProperty("expires_in")
    val expiresIn: Long,

    @get: JsonProperty("access_token")
    val accessToken: String,

    @get: JsonProperty("scope")
    val scope: String,

    @get: JsonProperty("refresh_token")
    val refreshToken: String,

)
