package com.jacknie.test.config.social

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

class SocialServerAuthenticationConverter(
    private val userRepository: SocialUnregisteredUserRepository,
    private val exchangeMatcher: PathPatternParserServerWebExchangeMatcher,
    private val extractSocialId: (ServerWebExchangeMatcher.MatchResult) -> String,
) : ServerAuthenticationConverter {

    override fun convert(exchange: ServerWebExchange): Mono<Authentication> {
        return userRepository.load(exchange)
            .flatMap { validateSocialId(exchange, it) }
            .map { UsernamePasswordAuthenticationToken(it.oauth2User.name, "") }
    }

    private fun validateSocialId(exchange: ServerWebExchange, user: SocialUnregisteredUser): Mono<SocialUnregisteredUser> {
        return exchangeMatcher.matches(exchange)
            .filter { extractSocialId(it) == user.oauth2User.name }
            .switchIfEmpty(
                Mono.error {
                    val path = exchange.request.path.pathWithinApplication()
                    IllegalStateException("illegal social id login(path: $path, socialId: ${user.oauth2User.name})")
                }
            )
            .thenReturn(user)
    }

}
