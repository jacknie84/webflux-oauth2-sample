package com.jacknie.test.config.social

import com.jacknie.test.config.ReactiveUserDetailsServiceImpl
import com.jacknie.test.repository.MemberSocialRepository
import org.springframework.security.core.userdetails.ReactiveUserDetailsPasswordService
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException
import reactor.core.publisher.Mono

class SocialReactiveUserDetailsService(
    private val socialRepository: MemberSocialRepository,
    private val delegate: ReactiveUserDetailsServiceImpl,
) : ReactiveUserDetailsService, ReactiveUserDetailsPasswordService by delegate {

    override fun findByUsername(username: String): Mono<UserDetails> {
        return socialRepository.findBySocialId(username)
            .switchIfEmpty(Mono.error { UsernameNotFoundException(username) })
            .then(delegate.findByUsername(username))
    }

}
