package com.jacknie.test.model

import java.time.Instant
import org.springframework.security.core.userdetails.UserDetails

data class RefreshToken(

    val value: String,
    val userDetails: UserDetails,
    val client: MemberClient,
    val expiresAt: Instant,
    val scopes: Set<String>,

)
