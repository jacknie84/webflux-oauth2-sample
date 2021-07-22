package com.jacknie.test.config.social

import com.jacknie.test.model.MemberSocialType
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.core.user.OAuth2User

class SocialUnregisteredUser(
    val oauth2User: OAuth2User,
    val clientRegistration: ClientRegistration,
) {

    val type: MemberSocialType get() = MemberSocialType.values()
        .firstOrNull { it.clientRegistrationId == clientRegistration.registrationId }
        ?: error("could not found MemberSocialType(clientRegistrationId: ${clientRegistration.registrationId})")

}
