import argparse
import os
from text_anonymizer import TextAnonymizer

def detect_pii(input_file, language=None):
    """
    Detects if a log file contains PII data.
    If no language is specified, it checks both English and German.
    """
    text_anonymizer = TextAnonymizer()
    detected_pii = False

    try:
        with open(input_file, "r", encoding="utf-8") as file:
            log_content = file.read()

        # If no language is provided, check both English and German
        languages_to_check = ["en", "de"] if language is None else [language]

        for lang in languages_to_check:
            print(f"🔍 Checking PII for language: {lang}")
            result = text_anonymizer.process(text=log_content, language=lang, detect=True)

            if result['entities']:
                print(f"⚠️ PII detected in '{input_file}' ({lang})!")
                for entity in result['entities']:
                    entity_text = log_content[entity['start']:entity['end']]
                    print(f'"{entity_text}" is a {entity["type"]} found at position {entity["start"]}-{entity["end"]}.')
                detected_pii = True

        if detected_pii:
            return 1  # Return non-zero exit code if PII is detected (so GitHub Actions sets pii_found=true)
        else:
            print(f"✅ No PII found in '{input_file}'.")
            return 0  # Return zero exit code if no PII is detected

    except Exception as e:
        print(f"❌ Error detecting PII: {e}")
        return 2  # Return error code if something goes wrong

def anonymize_pii(input_file, output_file, language=None, technique="replace"):
    """
    Anonymizes PII in a log file and saves the anonymized content.
    If no language is specified, it anonymizes for both English and German.
    """
    text_anonymizer = TextAnonymizer()

    try:
        with open(input_file, "r", encoding="utf-8") as file:
            log_content = file.read()

        # If no language is provided, anonymize in both English and German
        languages_to_check = ["en", "de"] if language is None else [language]

        for lang in languages_to_check:
            print(f"🛑 Anonymizing PII in {lang}...")
            result = text_anonymizer.process(text=log_content, language=lang, technique=technique)
            log_content = result['text']  # Update log content with anonymized text

        # Ensure the output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        # Save anonymized content
        with open(output_file, "w", encoding="utf-8") as file:
            file.write(log_content)

        print(f"✅ PII anonymized. Output saved to '{output_file}'")
        return 0

    except Exception as e:
        print(f"❌ Error anonymizing PII: {e}")
        return 2

def main():
    """CLI Entry Point for pii-detector."""
    parser = argparse.ArgumentParser(description="Detect and anonymize PII in logs.")

    parser.add_argument("action", choices=["detect", "anonymize"],
                        help="Choose 'detect' or 'anonymize' PII in logs.")
    parser.add_argument("input_file", help="Path to the log file.")
    parser.add_argument("--output_file", help="Path to save anonymized log file (required for anonymization).")
    parser.add_argument("--language", choices=["en", "de"], default=None,
                        help="Specify language: 'en' for English, 'de' for German. If not provided, checks both.")
    parser.add_argument("--technique", choices=["replace", "redact"], default="replace",
                        help="Anonymization technique: 'replace' or 'redact'.")

    args = parser.parse_args()

    if args.action == "detect":
        exit(detect_pii(args.input_file, args.language))  # Return exit code to GitHub Actions
    elif args.action == "anonymize":
        if not args.output_file:
            print("❌ Error: '--output_file' is required for anonymization.")
            exit(2)
        else:
            exit(anonymize_pii(args.input_file, args.output_file, args.language, args.technique))

if __name__ == "__main__":
    main()
