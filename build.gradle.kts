plugins {
    java
}

group = "com.squidsec"
version = "2.0.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
}

dependencies {
    // Provided by Burp at runtime
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.8")

    // Standalone mock harness (no Burp)
    testImplementation("net.portswigger.burp.extensions:montoya-api:2025.8")
    testImplementation("org.mockito:mockito-core:5.14.2")
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
}

tasks.test {
    useJUnitPlatform()
}

tasks.jar {
    archiveBaseName.set("burp-ai-bridge")
    archiveVersion.set(project.version.toString())
    manifest {
        attributes(
            "Implementation-Title" to "SquidSec Burp AI Bridge",
            "Implementation-Version" to project.version,
            "Implementation-Vendor" to "SquidSec"
        )
    }
}

tasks.register<Copy>("copyJarToDist") {
    dependsOn(tasks.jar)
    from(tasks.jar.get().archiveFile)
    into(layout.projectDirectory.dir("dist"))
}

tasks.build {
    finalizedBy("copyJarToDist")
}

// Run bridge against MockMontoyaApi (no Burp required)
tasks.register<JavaExec>("testMain") {
    group = "application"
    description = "Run AI Bridge HTTP server with mock Burp API"
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("com.squidsec.burp.bridge.TestMain")
    standardInput = System.`in`
}
