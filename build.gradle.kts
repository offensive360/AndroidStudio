plugins {
    id("java")
    id("org.jetbrains.intellij") version "1.13.3"
}

group = "com.offensive360"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.google.code.gson:gson:2.10.1")
    implementation("com.squareup.okhttp3:okhttp:4.10.0")
}

intellij {
    version.set("2022.1")
    type.set("IC")
    plugins.set(listOf())
}

tasks {
    buildSearchableOptions {
        enabled = false
    }

    withType<JavaCompile> {
        sourceCompatibility = "11"
        targetCompatibility = "11"
    }

    patchPluginXml {
        sinceBuild.set("221.0")
        untilBuild.set("251.*")
        changeNotes.set("""
            <h2>1.0.0</h2>
            <ul>
                <li>Initial release of Offensive360 SAST plugin for IntelliJ IDEA and Android Studio</li>
                <li>Token-based authentication</li>
                <li>Direct source code scanning</li>
                <li>Git repository scanning support</li>
                <li>Real-time vulnerability display in IDE</li>
            </ul>
        """.trimIndent())
    }
}
