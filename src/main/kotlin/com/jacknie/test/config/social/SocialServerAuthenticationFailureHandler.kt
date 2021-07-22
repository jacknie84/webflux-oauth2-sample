package com.jacknie.test.config.social

import java.net.URI
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler
import reactor.core.publisher.Mono

class SocialServerAuthenticationFailureHandler(
    caseFailedLocation: String,
    caseUnregisteredLocation: String,
    private val userRepository: SocialUnregisteredUserRepository,
) : ServerAuthenticationFailureHandler {

    private val caseFailedLocation = URI.create(caseFailedLocation)
    private val caseUnregisteredLocation = URI.create(caseUnregisteredLocation)
    private val redirectStrategy = DefaultServerRedirectStrategy()

    override fun onAuthenticationFailure(webFilterExchange: WebFilterExchange, exception: AuthenticationException): Mono<Void> {
        return isUnregisteredSocialError(exception)
            .flatMap {
                val exchange = webFilterExchange.exchange
                if (it) {
                    val user = (exception as SocialOAuth2AuthenticationException).user
                    userRepository.save(exchange, user)
                        .then(redirectStrategy.sendRedirect(exchange, caseUnregisteredLocation))
                } else {
                    redirectStrategy.sendRedirect(exchange, caseFailedLocation)
                }
            }
    }

    private fun isUnregisteredSocialError(exception: AuthenticationException): Mono<Boolean> {
        return if (exception is OAuth2AuthenticationException) {
            Mono.just(exception.error.errorCode == UNREGISTERED_SOCIAL_ERROR_CODE)
        } else {
            Mono.just(false)
        }
    }

    companion object {
        const val UNREGISTERED_SOCIAL_ERROR_CODE = "unregistered_social"
    }

}
