package com.jacknie.test.config

import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.support.GenericApplicationContext

class GenericApplicationContextInitializer : ApplicationContextInitializer<GenericApplicationContext> {

    override fun initialize(applicationContext: GenericApplicationContext) {
        beans().initialize(applicationContext)
    }

}