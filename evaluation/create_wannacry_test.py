from pathlib import Path


output_directory = Path(__file__).parent / "synthetic_samples"
output_directory.mkdir(parents=True, exist_ok=True)

output_file = output_directory / "WannaCry_inert_test.bin"

# Harmless synthetic data containing the patterns required by the YARA rule.
test_content = (
    b"MZ"
    + (b"\x00" * 100)
    + b"mssecsvc2.0"
    + (b"\x00" * 50)
    + (b"\x00" * 50)
    + b"@WanaDecryptor@.exe"
)

output_file.write_bytes(test_content)

print(f"Created harmless test file: {output_file.resolve()}")
print("This file contains static test patterns only.")
print("It does not contain executable ransomware code.")