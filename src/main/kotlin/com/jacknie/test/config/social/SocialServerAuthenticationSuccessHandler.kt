package com.jacknie.test.config.social

import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver.DEFAULT_AUTHORIZATION_REQUEST_PATTERN
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono

class SocialServerAuthenticationSuccessHandler(
    private val userRepository: SocialUnregisteredUserRepository,
) : ServerAuthenticationSuccessHandler {

    private val redirectStrategy = DefaultServerRedirectStrategy()

    override fun onAuthenticationSuccess(webFilterExchange: WebFilterExchange, authentication: Authentication): Mono<Void> {
        val exchange = webFilterExchange.exchange
        return userRepository.loadAndRemove(exchange)
            .map {
                UriComponentsBuilder.fromPath(DEFAULT_AUTHORIZATION_REQUEST_PATTERN)
                    .buildAndExpand(it.clientRegistration.registrationId)
                    .toUri()
            }
            .flatMap { redirectStrategy.sendRedirect(exchange, it) }
    }

}
