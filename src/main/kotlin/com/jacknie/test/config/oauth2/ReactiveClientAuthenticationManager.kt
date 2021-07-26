package com.jacknie.test.config.oauth2

import com.jacknie.test.model.MemberClient
import com.jacknie.test.repository.MemberClientRepository
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.crypto.password.PasswordEncoder
import reactor.core.publisher.Mono

class ReactiveClientAuthenticationManager(
    private val clientRepository: MemberClientRepository,
    private val passwordEncoder: PasswordEncoder,
) : ReactiveAuthenticationManager {

    override fun authenticate(authentication: Authentication): Mono<Authentication> {
        val presentedPassword = authentication.credentials.toString()
        return clientRepository.findByClientId(authentication.name)
            .filter { passwordEncoder.matches(presentedPassword, it.clientSecret) }
            .switchIfEmpty(Mono.error { BadCredentialsException("Invalid Credentials") })
            .flatMap { upgradeEncodingIfNecessary(it, presentedPassword) }
            .map {
                val authorities = it.scopes.split(",")
                    .map { scope -> SimpleGrantedAuthority("SCOPE_${scope.trim()}") }
                UsernamePasswordAuthenticationToken(it, it.clientSecret, authorities)
            }
    }

    private fun upgradeEncodingIfNecessary(client: MemberClient, presentedPassword: String): Mono<MemberClient> {
        return Mono.just(client.clientSecret)
            .filter { passwordEncoder.upgradeEncoding(it) }
            .map { passwordEncoder.encode(presentedPassword) }
            .flatMap { clientRepository.save(client.apply { clientSecret = it }) }
            .switchIfEmpty(Mono.just(client))
    }

}
