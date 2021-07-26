package com.jacknie.test.handler

import com.jacknie.test.config.oauth2.AuthorizationStateRepository
import com.jacknie.test.config.oauth2.RefreshTokenRepository
import com.jacknie.test.model.*
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.time.Instant
import java.util.*
import org.springframework.http.HttpStatus
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.stereotype.Component
import org.springframework.util.MultiValueMap
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import reactor.core.publisher.Mono

@Component
class TokenHandler(
    private val authStateRepository: AuthorizationStateRepository,
    private val refreshTokenRepository: RefreshTokenRepository,
    private val rsa: RSAKey
) {

    fun postToken(request: ServerRequest): Mono<ServerResponse> {
        return request.formData()
            .flatMap {
                when (val grantType = it["grant_type"]?.get(0)) {
                    null -> Mono.error { HttpStatusException(HttpStatus.BAD_REQUEST, "grant_type parameter is required") }
                    "authorization_code" -> handleAuthorizationCodeFlow(it)
                    "refresh_token" -> handleRefreshTokenFlow(it)
                    else -> Mono.error { HttpStatusException(HttpStatus.BAD_REQUEST, "unsupported grant_type($grantType)") }
                }
            }
            .flatMap { ServerResponse.ok().bodyValue(it) }
            .onErrorResume(HttpStatusException::class.java) {
                ServerResponse.status(it.httpStatus).bodyValue(it.message?: "no message")
            }
    }

    private fun handleAuthorizationCodeFlow(params: MultiValueMap<String, String>): Mono<AccessToken> {
        return ReactiveSecurityContextHolder.getContext()
            .map { it.authentication.principal as MemberClient }
            .zipWhen {
                Mono.just(
                    AuthorizationStateKey(
                        responseType = "code",
                        clientId = it.clientId,
                        code = getCode(params),
                        redirectUri = getRedirectUri(params)
                    )
                )
            }
            .flatMap { Mono.just(it.t1).zipWith(authStateRepository.loadAndRemove(it.t2)) }
            .switchIfEmpty(Mono.error { HttpStatusException(HttpStatus.UNAUTHORIZED, "failed authorization code flow") })
            .flatMap { getAccessToken(it.t1, it.t2) }
    }

    private fun handleRefreshTokenFlow(params: MultiValueMap<String, String>): Mono<AccessToken> {
        return ReactiveSecurityContextHolder.getContext()
            .map { it.authentication.principal as MemberClient }
            .zipWhen {
                Mono.just(
                    AuthorizationStateKey(
                        responseType = "code",
                        clientId = it.clientId,
                        code = getCode(params),
                        redirectUri = getRedirectUri(params)
                    )
                )
            }
            .flatMap { Mono.just(it.t1).zipWith(authStateRepository.loadAndRemove(it.t2)) }
            .switchIfEmpty(Mono.error { HttpStatusException(HttpStatus.UNAUTHORIZED, "failed authorization code flow") })
            .flatMap { getAccessToken(it.t1, it.t2) }
    }

    private fun getCode(params: MultiValueMap<String, String>): String {
        val code = params["code"]?.get(0)
        if (code.isNullOrBlank()) {
            throw HttpStatusException(HttpStatus.BAD_REQUEST, "code parameter is required")
        }
        return code
    }

    private fun getRedirectUri(params: MultiValueMap<String, String>): String {
        val redirectUri = params["redirect_uri"]?.get(0)
        if (redirectUri.isNullOrBlank()) {
            throw HttpStatusException(HttpStatus.BAD_REQUEST, "redirect_uri parameter is required")
        }
        return redirectUri
    }

    private fun getAccessToken(client: MemberClient, state: AuthorizationState): Mono<AccessToken> {
        if (!client.redirectUris.contains(state.redirectUri)) {
            throw HttpStatusException(HttpStatus.UNAUTHORIZED, "invalid redirect uri: ${state.redirectUri}")
        }
        if (!state.scopes.all { client.scopes.contains(it) }) {
            throw HttpStatusException(HttpStatus.UNAUTHORIZED, "insufficient scope: ${state.scopes}")
        }
        val tokenType = OAuth2AccessToken.TokenType.BEARER.value
        val expiresIn = client.accessTokenValiditySeconds
        val accessToken = getJwtToken(client, state)
        val scope = state.scopes.joinToString(" ")
        return getRefreshToken(client, state)
            .map { AccessToken(tokenType, expiresIn, accessToken, scope, it) }
    }

    private fun getJwtToken(client: MemberClient, state: AuthorizationState): String {
        val signer = RSASSASigner(rsa)
        val issuerTime = Instant.now()
        val expirationTime = issuerTime.plusSeconds(client.accessTokenValiditySeconds)
        val claimsSet = JWTClaimsSet.Builder()
            .issuer("http://localhost:8080/v1")
            .subject(state.userDetails.username)
            .audience(client.clientId)
            .expirationTime(Date.from(expirationTime))
            .issueTime(Date.from(issuerTime))
            .claim("scope", state.scopes.map { it })
            .build()
        val header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsa.keyID).build()
        val signed = SignedJWT(header, claimsSet)
        signed.sign(signer)
        return signed.serialize()
    }

    private fun getRefreshToken(client: MemberClient, state: AuthorizationState): Mono<String> {
        return generateRefreshToken()
            .doOnNext {
                refreshTokenRepository.save(
                    RefreshToken(
                        value = it,
                        userDetails = state.userDetails,
                        client = client,
                        expiresAt = Instant.now().plusSeconds(client.refreshTokenValiditySeconds),
                        scopes = state.scopes,
                    )
                )
            }
    }

    private fun generateRefreshToken(): Mono<String> {
        val refreshToken = UUID.randomUUID().toString()
        return refreshTokenRepository.existsByRefreshToken(refreshToken)
            .flatMap {
                if (!it) {
                    Mono.just(refreshToken)
                } else {
                    generateRefreshToken()
                }
            }
    }

}
