import argparse
import os
from text_anonymizer import TextAnonymizer


def detect_pii(input_file, language='en'):
    """Detects if a log file contains PII data."""
    text_anonymizer = TextAnonymizer()

    try:
        with open(input_file, "r", encoding="utf-8") as file:
            log_content = file.read()

        result = text_anonymizer.process(text=log_content, language=language, detect=True)

        if result['entities']:
            print(f"⚠️ Caution: The file '{input_file}' contains personal data!")
            for entity in result['entities']:
                entity_text = log_content[entity['start']:entity['end']]
                print(f'"{entity_text}" is a {entity["type"]} found at position {entity["start"]}-{entity["end"]}.')
            return True
        else:
            print(f"✅ No PII found in '{input_file}'.")
            return False

    except Exception as e:
        print(f"❌ Error detecting PII: {e}")
        return False


def anonymize_pii(input_file, output_file, language='en', technique='replace'):
    """Anonymizes PII in a log file and saves the anonymized content."""
    text_anonymizer = TextAnonymizer()

    try:
        with open(input_file, "r", encoding="utf-8") as file:
            log_content = file.read()

        result = text_anonymizer.process(text=log_content, language=language, technique=technique)

        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as file:
            file.write(result['text'])

        print(f"✅ PII anonymized in '{input_file}'. Output saved to '{output_file}'")

    except Exception as e:
        print(f"❌ Error anonymizing PII: {e}")


def main():
    """CLI Entry Point for pii-detector."""
    parser = argparse.ArgumentParser(description="Detect and anonymize PII in logs.")

    parser.add_argument("action", choices=["detect", "anonymize"],
                        help="Choose 'detect' or 'anonymize' PII in logs.")
    parser.add_argument("input_file", help="Path to the log file.")
    parser.add_argument("--output_file", help="Path to save anonymized log file (required for anonymization).")
    parser.add_argument("--language", choices=["en", "de"], default="en",
                        help="Specify language: 'en' for English, 'de' for German.")
    parser.add_argument("--technique", choices=["replace", "redact"], default="replace",
                        help="Anonymization technique.")

    args = parser.parse_args()

    if args.action == "detect":
        detect_pii(args.input_file, args.language)
    elif args.action == "anonymize":
        if not args.output_file:
            print("❌ Error: '--output_file' is required for anonymization.")
        else:
            anonymize_pii(args.input_file, args.output_file, args.language, args.technique)


if __name__ == "__main__":
    main()
