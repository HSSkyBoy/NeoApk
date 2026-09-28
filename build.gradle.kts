plugins {
    `java-library`
    kotlin("jvm") version "2.1.10"
    `maven-publish`
}

group = "com.github.HSSkyBoy"
version = "1.0.0"

repositories {
    mavenCentral()
    google()
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
    withSourcesJar()
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    api("org.bouncycastle:bcprov-jdk18on:1.78.1")

    testImplementation("junit:junit:4.13.2")
    testImplementation("com.android.tools.build:apksig:8.0.2")
    testImplementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            groupId = "com.github.HSSkyBoy"
            artifactId = "NeoApk"
            version = project.version.toString()
        }
    }
}

tasks.test {
    useJUnit()
}
