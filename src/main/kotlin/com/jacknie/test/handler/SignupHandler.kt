package com.jacknie.test.handler

import com.jacknie.test.config.social.SocialUnregisteredUserRepository
import com.jacknie.test.model.MemberAccount
import com.jacknie.test.model.MemberSocial
import com.jacknie.test.repository.MemberAccountRepository
import com.jacknie.test.repository.MemberSocialRepository
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.web.reactive.result.view.CsrfRequestDataValueProcessor.DEFAULT_CSRF_ATTR_NAME
import org.springframework.security.web.server.csrf.CsrfToken
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.attributeOrNull
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono

@Component
class SignupHandler(
    private val accountRepository: MemberAccountRepository,
    private val socialRepository: MemberSocialRepository,
    private val userRepository: SocialUnregisteredUserRepository,
    @Value("\${app.login.social.pattern}") private val loginSocialPattern: String,
) {

    fun getSignupForm(request: ServerRequest): Mono<ServerResponse> {
        return userRepository.load(request.exchange())
            .flatMap {
                val model = mapOf(
                    "socialUser" to it,
                    DEFAULT_CSRF_ATTR_NAME to request.attributeOrNull(CsrfToken::class.java.name)
                )
                ServerResponse.ok().render("signup-form", model)
            }
    }

    fun postSignupProcess(request: ServerRequest): Mono<ServerResponse> {
        val contextPath = request.requestPath().contextPath().value()
        return userRepository.load(request.exchange())
            .zipWhen {
                accountRepository.save(MemberAccount(username = it.oauth2User.name, password = "{noop}"))
            }
            .flatMap {
                socialRepository.save(
                    MemberSocial(
                        socialId = it.t1.oauth2User.name,
                        type = it.t1.type,
                        accountId = it.t2.id!!,
                    )
                )
            }
            .flatMap {
                val location = UriComponentsBuilder.fromPath(contextPath).path(loginSocialPattern).build(it.socialId)
                ServerResponse.temporaryRedirect(location).build()
            }
    }

}
