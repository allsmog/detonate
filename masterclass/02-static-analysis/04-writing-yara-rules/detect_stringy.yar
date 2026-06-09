/*
 * detect_stringy.yar — Module 2.4 worked example.
 *
 * Two rules over the Module 2.1 `stringy` training binary, to teach the
 * difference between a BRITTLE rule and a ROBUST one.
 *
 * Test:
 *   yara detect_stringy.yar /tmp/stringy        # should match
 *   yara detect_stringy.yar /bin/ls             # should NOT match
 */

rule stringy_brittle
{
    /*
     * Brittle: keys off one specific C2 URL. Catches THIS sample but a trivial
     * config change (new domain) evades it. Useful for IOC-pinning a known
     * sample, useless as a family rule.
     */
    meta:
        author = "detonate-masterclass"
        description = "Brittle single-IOC match (teaching anti-pattern)"
    strings:
        $url = "http://example.com/gate.php?id=" ascii
    condition:
        $url
}

rule stringy_robust
{
    /*
     * Robust: keys off a COMBINATION of structural indicators that a whole
     * family would share (persistence registry path + a mutex-naming pattern +
     * a dropped-exe path shape). Requires several to co-occur, which kills
     * false positives while surviving cosmetic changes.
     */
    meta:
        author = "detonate-masterclass"
        description = "Family-style match on co-occurring behavioral strings"
    strings:
        $reg   = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $mutex = /Global\\[A-Za-z0-9_]{4,32}/ ascii
        $drop  = /C:\\Users\\Public\\[A-Za-z0-9_]+\.exe/ ascii
    condition:
        // require the persistence key AND at least one more indicator
        $reg and ($mutex or $drop)
}
