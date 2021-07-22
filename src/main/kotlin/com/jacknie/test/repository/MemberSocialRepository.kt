package com.jacknie.test.repository

import com.jacknie.test.model.MemberSocial
import org.springframework.data.r2dbc.repository.R2dbcRepository
import reactor.core.publisher.Mono

interface MemberSocialRepository : R2dbcRepository<MemberSocial, String> {

    fun existsBySocialId(socialId: String): Mono<Boolean>

    fun findBySocialId(socialId: String): Mono<MemberSocial>

}
