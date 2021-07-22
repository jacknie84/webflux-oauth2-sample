package com.jacknie.test.handler

import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import reactor.core.publisher.Mono

@Component
class IndexHandler(
    private val authorizedClientService: ReactiveOAuth2AuthorizedClientService,
) {

    fun getIndex(request: ServerRequest): Mono<ServerResponse> {
        return ReactiveSecurityContextHolder.getContext()
            .flatMap { ServerResponse.ok().bodyValue(it.authentication) }
            .switchIfEmpty(ServerResponse.ok().bodyValue(emptyMap<String, Any>()))
    }

}
