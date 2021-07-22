package com.jacknie.test.repository

import com.jacknie.test.model.MemberAccount
import org.springframework.data.r2dbc.repository.R2dbcRepository
import reactor.core.publisher.Mono

interface MemberAccountRepository : R2dbcRepository<MemberAccount, Long> {

    fun findByUsername(username: String): Mono<MemberAccount>

}
