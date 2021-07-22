package com.jacknie.test.model

import com.jacknie.test.model.TablePrefix.memberSubject
import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table

@Table("${memberSubject}account")
data class MemberAccount(

    @Id
    var id: Long? = null,

    var username: String,

    var password: String,

)
