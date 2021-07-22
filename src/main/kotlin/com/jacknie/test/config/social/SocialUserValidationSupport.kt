package com.jacknie.test.config.social

import com.jacknie.test.config.social.SocialServerAuthenticationFailureHandler.Companion.UNREGISTERED_SOCIAL_ERROR_CODE
import com.jacknie.test.repository.MemberSocialRepository
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.user.OAuth2User
import reactor.core.publisher.Mono

abstract class SocialUserValidationSupport {

    protected abstract val socialRepository: MemberSocialRepository

    protected fun <U : OAuth2User> validateOAuth2User(user: U, clientRegistration: ClientRegistration): Mono<U> {
        return Mono.just(user)
            .filterWhen { socialRepository.existsBySocialId(it.name) }
            .switchIfEmpty(
                Mono.error {
                    val description = "Unregistered social account."
                    val oauth2Error = OAuth2Error(UNREGISTERED_SOCIAL_ERROR_CODE, description, null)
                    SocialOAuth2AuthenticationException(oauth2Error, SocialUnregisteredUser(user, clientRegistration))
                }
            )
    }

}
