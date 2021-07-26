package com.jacknie.test.handler

import org.springframework.http.HttpStatus

class HttpStatusException(
    val httpStatus: HttpStatus,
    message: String?,
): RuntimeException(message)
