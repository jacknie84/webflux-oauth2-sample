package com.jacknie.test.config

import org.springframework.context.annotation.Configuration
import org.springframework.web.reactive.config.PathMatchConfigurer
import org.springframework.web.reactive.config.WebFluxConfigurer

@Configuration
class WebFluxConfiguration : WebFluxConfigurer {

    override fun configurePathMatching(configurer: PathMatchConfigurer) {
        configurer
            .setUseCaseSensitiveMatch(true)
            .setUseTrailingSlashMatch(true)
    }

}
