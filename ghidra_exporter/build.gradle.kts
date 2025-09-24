plugins {
    id("java")
}

group = "com.rldecompile"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

tasks {
    register<Jar>("libJar") {
        dependsOn.addAll(listOf("compileJava")) // We need this for Gradle optimization to work
        archiveClassifier.set("libs") // Naming the jar
        duplicatesStrategy = DuplicatesStrategy.EXCLUDE
        val contents = configurations.runtimeClasspath.get()
            .filter { !it.path.contains("ghidra") }
            .map { if (it.isDirectory) it else zipTree(it) } // + sourceSets.main.get()
        from(contents)
    }
}


dependencies {
    implementation (fileTree("/opt/ghidra") {
        include("**/*.jar")
    })
    implementation(platform("org.mongodb:mongodb-driver-bom:5.4.0"))
    implementation("org.mongodb:mongodb-driver-sync")
}
