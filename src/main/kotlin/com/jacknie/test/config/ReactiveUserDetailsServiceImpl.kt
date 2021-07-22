package com.jacknie.test.config

import com.jacknie.test.repository.MemberAccountRepository
import org.springframework.security.core.userdetails.ReactiveUserDetailsPasswordService
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import reactor.core.publisher.Mono

class ReactiveUserDetailsServiceImpl(
    private val accountRepository: MemberAccountRepository,
) : ReactiveUserDetailsService, ReactiveUserDetailsPasswordService {

    override fun findByUsername(username: String): Mono<UserDetails> {
        return accountRepository.findByUsername(username)
            .map {
                User
                    .withUsername(it.username)
                    .password(it.password)
                    .passwordEncoder { password -> password }
                    .authorities("ROLE_USER")
                    .build()
            }
    }

    override fun updatePassword(user: UserDetails, newPassword: String): Mono<UserDetails> {
        return accountRepository.findByUsername(user.username)
            .doOnNext { it.password = newPassword }
            .doOnNext { accountRepository.save(it) }
            .thenReturn(user)
    }
}
