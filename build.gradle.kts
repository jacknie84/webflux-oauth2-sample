plugins {
    kotlin("jvm") version "1.5.20"
    kotlin("plugin.spring") version "1.5.20"
    id("org.springframework.boot") version "2.5.2"
    id("io.spring.dependency-management") version "1.0.10.RELEASE"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("reflect"))
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.boot:spring-boot-starter-data-r2dbc")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-client")
    implementation("org.springframework.boot:spring-boot-starter-rsocket")
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
    runtimeOnly("io.r2dbc:r2dbc-h2")
}

tasks.compileKotlin.configure {
    kotlinOptions {
        freeCompilerArgs = freeCompilerArgs + "-Xjsr305=strict"
        jvmTarget = "11"
    }
}
