package com.jacknie.test.repository

import com.jacknie.test.model.MemberClient
import org.springframework.data.r2dbc.repository.R2dbcRepository
import reactor.core.publisher.Mono

interface MemberClientRepository : R2dbcRepository<MemberClient, Long> {

    fun existsByClientId(clientId: String): Mono<Boolean>

    fun existsByRedirectUrisContaining(redirectUri: String): Mono<Boolean>

    fun findByClientId(clientId: String): Mono<MemberClient>

}
