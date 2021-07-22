package com.jacknie.test.model

import com.jacknie.test.model.TablePrefix.memberSubject
import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Table

@Table("${memberSubject}social")
data class MemberSocial(

    @Id
    var id: Long? = null,

    var socialId: String,

    var type: MemberSocialType,

    var accountId: Long,

)
