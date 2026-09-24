package network.reticulum.config

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * ConfigObj keeps a `#` that sits inside a quoted value; only an unquoted `#` opens a
 * comment. A passphrase such as `"pass#word"` was cut to `"pass` before this, on both
 * config parsers.
 */
class InlineCommentTest {
    @Test
    fun `an unquoted hash opens a comment`() {
        assertEquals("passphrase = secret ", InterfaceConfig.stripInlineComment("passphrase = secret # the comment"))
        assertEquals("", InterfaceConfig.stripInlineComment("# whole line"))
    }

    @Test
    fun `a hash inside quotes is part of the value`() {
        assertEquals("passphrase = \"pass#word\"", InterfaceConfig.stripInlineComment("passphrase = \"pass#word\""))
        assertEquals("passphrase = 'pass#word' ", InterfaceConfig.stripInlineComment("passphrase = 'pass#word' # trailing"))
        assertEquals("name = \"it's # here\"", InterfaceConfig.stripInlineComment("name = \"it's # here\""))
    }

    @Test
    fun `parseIni keeps a quoted hash in the value`() {
        val parsed =
            InterfaceConfig.parseIni(
                """
                [interfaces]
                  [[Backbone]]
                    type = BackboneInterface
                    passphrase = "pass#word" # not part of the value
                    network_name = "net#1"
                """.trimIndent(),
            )
        val section = InterfaceConfig.interfaceSection(parsed, "Backbone")!!
        assertEquals("pass#word", section["passphrase"])
        assertEquals("net#1", section["network_name"])
        assertEquals("BackboneInterface", section["type"])
    }
}
