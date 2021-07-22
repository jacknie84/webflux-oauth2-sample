package com.jacknie.test.config.social

import com.nimbusds.oauth2.sdk.ErrorObject
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse
import net.minidev.json.JSONObject
import org.springframework.core.ParameterizedTypeReference
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpHeaders.*
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE
import org.springframework.http.MediaType.APPLICATION_JSON_VALUE
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails.UserInfoEndpoint
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService
import org.springframework.security.oauth2.core.AuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.user.DefaultOAuth2User
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority
import org.springframework.util.StringUtils
import org.springframework.web.reactive.function.UnsupportedMediaTypeException
import org.springframework.web.reactive.function.client.ClientResponse
import org.springframework.web.reactive.function.client.WebClient
import reactor.core.publisher.Mono

class SocialReactiveOAuth2UserService : ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private val webClient = WebClient.create()

    var userAttributeAccessSpec: (Map<String, Any>) -> Map<String, Any> = { it }
    var accessTokenHeaderSpec: (String, HttpHeaders) -> Unit = { token, headers -> headers.setBearerAuth(token) }

    override fun loadUser(userRequest: OAuth2UserRequest): Mono<OAuth2User> {
        val registrationId = userRequest.clientRegistration.registrationId
        val userInfoEndpoint = userRequest.clientRegistration.providerDetails.userInfoEndpoint
        val userInfoUri = getUserInfoUri(userInfoEndpoint, registrationId)
        val userNameAttributeName = getUserNameAttributeName(userInfoEndpoint, registrationId)
        return getUserAttributes(userRequest, userInfoUri)
            .map<OAuth2User> {
                val role = OAuth2UserAuthority(it)
                val scope = userRequest.accessToken.scopes.map { s -> SimpleGrantedAuthority("SCOPE_$s") }
                val attributes = userAttributeAccessSpec.invoke(it)
                DefaultOAuth2User(scope + role, attributes, userNameAttributeName)
            }
            .onErrorMap(
                UnsupportedMediaTypeException::class.java,
                mapUnsupportedMediaTypeException(userInfoUri, registrationId),
            )
            .onErrorMap(
                { e -> e.cause is UnsupportedMediaTypeException },
                mapCauseUnsupportedMediaTypeException(userInfoUri, registrationId),
            )
            .onErrorMap {
                val description = "An error occurred reading the UserInfo response: ${it.message}"
                val error = OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE, description, null)
                OAuth2AuthenticationException(error, error.toString(), it)
            }
    }

    private fun getUserInfoUri(userInfoEndpoint: UserInfoEndpoint, registrationId: String): String {
        val userInfoUri = userInfoEndpoint.uri
        if (!StringUtils.hasText(userInfoUri)) {
            val description = "Missing required UserInfo Uri in UserInfoEndpoint for Client Registration: $registrationId"
            val error = OAuth2Error(MISSING_USER_INFO_URI_ERROR_CODE, description, null)
            throw OAuth2AuthenticationException(error, error.toString())
        }
        return userInfoUri
    }

    private fun getUserNameAttributeName(userInfoEndpoint: UserInfoEndpoint, registrationId: String): String {
        val userNameAttributeName = userInfoEndpoint.userNameAttributeName
        if (!StringUtils.hasText(userNameAttributeName)) {
            val description = "Missing required \"user name\" attribute name in UserInfoEndpoint for Client Registration: $registrationId"
            val error = OAuth2Error(MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE, description, null)
            throw OAuth2AuthenticationException(error, error.toString())
        }
        return userNameAttributeName
    }

    private fun getUserAttributes(userRequest: OAuth2UserRequest, userInfoUri: String): Mono<Map<String, Any>> {
        val requestHeadersSpec = getRequestHeadersSpec(userRequest, userInfoUri)
        return requestHeadersSpec.retrieve()
            .onStatus(HttpStatus::isError) {
                parseError(it).map { userInfoErrorResponse ->
                    val description = userInfoErrorResponse.errorObject.description
                    val error = OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE, description, null)
                    OAuth2AuthenticationException(error, error.toString())
                }
            }
            .bodyToMono(STRING_OBJECT_MAP)
    }

    private fun getRequestHeadersSpec(userRequest: OAuth2UserRequest, userInfoUri: String) = when(userRequest.clientRegistration.providerDetails.userInfoEndpoint.authenticationMethod) {
        AuthenticationMethod.FORM -> webClient.post()
            .uri(userInfoUri)
            .header(ACCEPT, APPLICATION_JSON_VALUE)
            .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE)
            .bodyValue("access_token=${userRequest.accessToken.tokenValue}")
        else -> webClient.get()
            .uri(userInfoUri)
            .header(ACCEPT, APPLICATION_JSON_VALUE)
            .headers { accessTokenHeaderSpec.invoke(userRequest.accessToken.tokenValue, it) }
    }

    private fun parseError(response: ClientResponse): Mono<UserInfoErrorResponse> {
        val wwwAuth = response.headers().asHttpHeaders().getFirst(WWW_AUTHENTICATE)
        return if (wwwAuth.isNullOrBlank()) {
            Mono.just(UserInfoErrorResponse.parse(wwwAuth))
        } else {
            response.bodyToMono(STRING_STRING_MAP).map { UserInfoErrorResponse(ErrorObject.parse(JSONObject(it))) }
        }
    }

    private fun mapUnsupportedMediaTypeException(
        userInfoUri: String,
        registrationId: String,
    ): (UnsupportedMediaTypeException) -> Throwable {
        return {
            val description = """
                An error occurred while attempting to retrieve the UserInfo Resource from
                '$userInfoUri': response contains invalid content type '${it.contentType}'.
                The UserInfo Response should return a JSON object (content type 'application/json')
                that contains a collection of name and value pairs of the claims about the authenticated End-User.
                Please ensure the UserInfo Uri in UserInfoEndpoint for Client Registration
                '$registrationId' conforms to the UserInfo Endpoint, as defined in OpenID Connect 1.0:
                'https://openid.net/specs/openid-connect-core-1_0.html#UserInfo'
            """.trimIndent()
            val error = OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE, description, null)
            OAuth2AuthenticationException(error, error.toString(), it)
        }
    }

    private fun mapCauseUnsupportedMediaTypeException(
        userInfoUri: String,
        registrationId: String,
    ): (Throwable) -> Throwable {
        return {
            val e = it.cause as UnsupportedMediaTypeException
            mapUnsupportedMediaTypeException(userInfoUri, registrationId).invoke(e)
        }
    }

    companion object {
        private const val INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response"
        private const val MISSING_USER_INFO_URI_ERROR_CODE = "missing_user_info_uri"
        private const val MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE = "missing_user_name_attribute"
        private val STRING_OBJECT_MAP = object : ParameterizedTypeReference<Map<String, Any>>() {}
        private val STRING_STRING_MAP = object : ParameterizedTypeReference<Map<String, String>>() {}
    }

}
