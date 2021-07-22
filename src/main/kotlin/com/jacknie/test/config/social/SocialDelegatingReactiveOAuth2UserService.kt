package com.jacknie.test.config.social

import com.jacknie.test.repository.MemberSocialRepository
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService
import org.springframework.security.oauth2.core.user.OAuth2User
import reactor.core.publisher.Mono

class SocialDelegatingReactiveOAuth2UserService(
    override val socialRepository: MemberSocialRepository,
    private val delegates: Map<String, ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User>>,
) : ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User>, SocialUserValidationSupport() {

    private val defaultDelegate = DefaultReactiveOAuth2UserService()

    override fun loadUser(userRequest: OAuth2UserRequest): Mono<OAuth2User> {
        val clientRegistration = userRequest.clientRegistration
        val oauth2UserService = delegates[clientRegistration.registrationId]?: defaultDelegate
        return oauth2UserService.loadUser(userRequest).flatMap { validateOAuth2User(it, clientRegistration) }
    }

}
