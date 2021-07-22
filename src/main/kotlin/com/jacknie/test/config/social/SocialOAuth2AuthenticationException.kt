package com.jacknie.test.config.social

import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error

class SocialOAuth2AuthenticationException(
    error: OAuth2Error,
    val user: SocialUnregisteredUser
) : OAuth2AuthenticationException(error)
