package com.jacknie.test.config.oauth2

import com.jacknie.test.model.AuthorizationState
import com.jacknie.test.model.AuthorizationStateKey
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import org.springframework.stereotype.Repository
import reactor.core.publisher.Mono

@Repository
class AuthorizationStateRepository {

    private val map = ConcurrentHashMap<String, Set<AuthorizationState>>()

    fun save(state: AuthorizationState): Mono<AuthorizationState> {
        val clientStates = map.getOrDefault(state.clientId, mutableSetOf())
        val filtered = (clientStates + state).filter { it.expiresAt.isAfter(Instant.now()) }
        map[state.clientId] = filtered.toSet()
        return Mono.just(state)
    }

    fun loadAndRemove(key: AuthorizationStateKey): Mono<AuthorizationState> {
        val clientStates = map.getOrDefault(key.clientId, mutableSetOf())
        val filtered = clientStates.filter { it.expiresAt.isAfter(Instant.now()) }
        val found = filtered.first { it == key }
        map[key.clientId] = (filtered - found).toSet()
        return Mono.just(found)
    }

}
