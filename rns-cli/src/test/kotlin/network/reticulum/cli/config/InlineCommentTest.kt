package network.reticulum.cli.config

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.writeText

/**
 * ConfigObj keeps a `#` that sits inside a quoted value; only an unquoted `#` opens a
 * comment. A passphrase such as `"pass#word"` was cut to `"pass` before this, which
 * derived an IFAC key the python peers on the same network did not share.
 */
class InlineCommentTest {
    @TempDir
    lateinit var tempDir: Path

    @Test
    fun `an unquoted hash opens a comment`() {
        assertEquals("passphrase = secret ", ConfigParser.stripInlineComment("passphrase = secret # the comment"))
        assertEquals("", ConfigParser.stripInlineComment("# whole line"))
    }

    @Test
    fun `a hash inside quotes is part of the value`() {
        assertEquals("passphrase = \"pass#word\"", ConfigParser.stripInlineComment("passphrase = \"pass#word\""))
        assertEquals("passphrase = 'pass#word' ", ConfigParser.stripInlineComment("passphrase = 'pass#word' # trailing"))
        assertEquals("name = \"it's # here\"", ConfigParser.stripInlineComment("name = \"it's # here\""))
    }

    @Test
    fun `the config file parser keeps a quoted hash in the value`() {
        val configFile = tempDir.resolve("config")
        configFile.writeText(
            """
            [interfaces]
              [[Client]]
                type = TCPClientInterface
                target_host = 127.0.0.1
                target_port = 4242
                passphrase = "pass#word" # not part of the value
                network_name = 'net#1'
            """.trimIndent(),
        )

        val config = ConfigParser.parse(configFile.toFile()).interfaces.getValue("Client")
        assertEquals("pass#word", config.options["passphrase"])
        assertEquals("net#1", config.options["network_name"])
        assertEquals("pass#word", config.ifacNetkey)
        assertEquals("net#1", config.ifacNetname)
        assertEquals("TCPClientInterface", config.type)
    }
}
