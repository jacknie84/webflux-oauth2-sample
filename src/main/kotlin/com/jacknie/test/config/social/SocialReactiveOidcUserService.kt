package com.jacknie.test.config.social

import com.jacknie.test.repository.MemberSocialRepository
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import reactor.core.publisher.Mono

class SocialReactiveOidcUserService(
    override val socialRepository: MemberSocialRepository
) : ReactiveOAuth2UserService<OidcUserRequest, OidcUser>, SocialUserValidationSupport() {

    private val delegate = OidcReactiveOAuth2UserService()

    override fun loadUser(userRequest: OidcUserRequest): Mono<OidcUser> {
        return delegate.loadUser(userRequest)
            .flatMap { validateOAuth2User(it, userRequest.clientRegistration) }
    }
}
