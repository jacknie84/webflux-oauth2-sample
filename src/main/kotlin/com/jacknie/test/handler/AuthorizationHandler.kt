package com.jacknie.test.handler

import com.jacknie.test.config.oauth2.AuthorizationStateRepository
import com.jacknie.test.model.AuthorizationState
import com.jacknie.test.repository.MemberClientRepository
import com.nimbusds.oauth2.sdk.AuthorizationCode
import java.net.URI
import kotlin.reflect.jvm.jvmName
import org.springframework.http.HttpStatus
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Component
import org.springframework.util.MultiValueMap
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono

@Component
class AuthorizationHandler(
    private val clientRepository: MemberClientRepository,
    private val authStateRepository: AuthorizationStateRepository,
) {

    fun getAuthorizationCode(request: ServerRequest): Mono<ServerResponse> {
        val params = request.queryParams()
        return ReactiveSecurityContextHolder.getContext()
            .flatMap { getAuthorizationState(it.authentication, params) }
            .map { getClientRedirectUri(it) }
            .flatMap { ServerResponse.temporaryRedirect(it).build() }
            .onErrorResume(HttpStatusException::class.java) {
                ServerResponse.status(it.httpStatus).bodyValue(it.message?: "no message")
            }
    }

    private fun getAuthorizationState(
        authentication: Authentication,
        params: MultiValueMap<String, String>
    ): Mono<AuthorizationState> {
        return Mono.zip(getClientId(params), getScopes(params), getRedirectUri(params), generateAuthorizationCode())
            .flatMap {
                authStateRepository.save(
                    AuthorizationState(
                        responseType = params["response_type"]!![0]!!,
                        clientId = it.t1,
                        scopes = it.t2,
                        redirectUri = it.t3,
                        state = params["state"]?.get(0),
                        code = it.t4,
                        userDetails = toUserDetails(authentication.principal)
                    )
                )
            }
    }

    private fun getClientId(params: MultiValueMap<String, String>): Mono<String> {
        val clientId = params["client_id"]?.get(0)
        return Mono.just(clientId?: "")
            .filter { !it.isNullOrBlank() }
            .switchIfEmpty(Mono.error { HttpStatusException(HttpStatus.BAD_REQUEST, "client_id parameter is required") })
            .filterWhen { clientRepository.existsByClientId(it) }
            .switchIfEmpty(Mono.error { HttpStatusException(HttpStatus.UNAUTHORIZED, "could not found client($clientId)") })
    }

    private fun getScopes(params: MultiValueMap<String, String>): Mono<Set<String>> {
        return Mono.just(
            params["scope"]?.get(0)?.split(" ")
                ?.filter { it.isNotBlank() }
                ?.toSet()
                ?: emptySet()
        )
    }

    private fun getRedirectUri(params: MultiValueMap<String, String>): Mono<String> {
        val redirectUri = params["redirect_uri"]?.get(0)
        return Mono.just(redirectUri?: "")
            .filter { !it.isNullOrBlank() }
            .switchIfEmpty(Mono.error { HttpStatusException(HttpStatus.BAD_REQUEST, "redirect_uri parameter is required") })
            .flatMap {
                try {
                    UriComponentsBuilder.fromHttpUrl(it)
                    Mono.just(it)
                } catch (e: IllegalArgumentException) {
                    Mono.error(HttpStatusException(HttpStatus.BAD_REQUEST, e.message))
                }
            }
            .filterWhen { clientRepository.existsByRedirectUrisContaining(it) }
            .switchIfEmpty(Mono.error { HttpStatusException(HttpStatus.UNAUTHORIZED, "could not found client($redirectUri)") })
    }

    private fun generateAuthorizationCode(): Mono<String> {
        return Mono.just(AuthorizationCode().value)
    }

    private fun getClientRedirectUri(authState: AuthorizationState): URI {
        val builder = UriComponentsBuilder.fromHttpUrl(authState.redirectUri).queryParam("code", authState.code)
        authState.state?.also { builder.queryParam("state", it) }
        return builder.build().toUri()
    }

    private fun toUserDetails(principal: Any): UserDetails {
        return when (principal) {
            is UserDetails -> principal
            is OAuth2User -> User.builder()
                .username(principal.name)
                .password("[PROTECTED]")
                .passwordEncoder { it }
                .authorities(principal.authorities)
                .build()
            else -> error("unsupported authentication principal type: ${principal::class.jvmName}")
        }
    }

}
