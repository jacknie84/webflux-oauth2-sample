package com.jacknie.test.config.oauth2

import com.jacknie.test.model.RefreshToken
import org.springframework.stereotype.Repository
import reactor.core.publisher.Mono

@Repository
class RefreshTokenRepository {

    private val tokens = mutableMapOf<String, RefreshToken>()

    fun existsByRefreshToken(refreshToken: String): Mono<Boolean> {
        return Mono.just(tokens.containsKey(refreshToken))
    }

    fun save(refreshToken: RefreshToken): Mono<RefreshToken> {
        tokens[refreshToken.value] = refreshToken
        return Mono.just(refreshToken)
    }

}
