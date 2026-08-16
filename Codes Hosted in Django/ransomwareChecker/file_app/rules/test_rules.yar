rule YARAShield_Test
{
    meta:
        description = "Harmless functional test rule for YARAShield"
        author = "Nischita Paudel"
        family = "Not applicable - test rule"
        indicator_type = "Static text pattern"
        purpose = "Pipeline verification only"

    strings:
        $test_string = "YARASHIELD_TEST_PATTERN" ascii

    condition:
        $test_string
}