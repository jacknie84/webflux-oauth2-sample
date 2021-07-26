package com.jacknie.test.model

import com.jacknie.test.model.TablePrefix.memberSubject
import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Table

@Table("${memberSubject}client")
data class MemberClient(

    @Id
    var id: Long? = null,

    var clientId: String,

    var clientSecret: String,

    var scopes: String,

    var redirectUris: String,

    var accessTokenValiditySeconds: Long,

    var refreshTokenValiditySeconds: Long,

)
