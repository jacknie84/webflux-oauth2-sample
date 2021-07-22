package com.jacknie.test.config.social

import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

class SocialUnregisteredUserRepository {

    fun save(exchange: ServerWebExchange, user: SocialUnregisteredUser): Mono<Void> {
        return exchange.session.doOnNext { it.attributes[SESSION_ATTR_NAME] = user }.then()
    }

    fun load(exchange: ServerWebExchange): Mono<SocialUnregisteredUser> {
        return exchange.session.flatMap { Mono.justOrEmpty(it.getAttribute<SocialUnregisteredUser>(SESSION_ATTR_NAME)) }
    }

    fun loadAndRemove(exchange: ServerWebExchange): Mono<SocialUnregisteredUser> {
        return exchange.session.flatMap {
            it.attributes.remove(SESSION_ATTR_NAME)?.let { value -> Mono.just(value as SocialUnregisteredUser) }?: Mono.empty()
        }
    }

    companion object {
        private const val SESSION_ATTR_NAME = "SOCIAL_UNREGISTERED_USER"
    }

}
