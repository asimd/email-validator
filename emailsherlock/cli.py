import argparse
import logging
from emailsherlock.core import validate_single_email, validate_emails_from_file, setup_logging

def main():
    parser = argparse.ArgumentParser(description="EmailSherlock: Email validation tool")
    parser.add_argument("--single", help="Validate a single email address")
    parser.add_argument("--file", help="Input file containing email addresses")
    parser.add_argument("--output", help="Output file for results", default="results.csv")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    # Parse arguments
    args = parser.parse_args()

    # Setup logging based on verbosity
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)

    # If no arguments are provided, print help and exit
    if not any(vars(args).values()):
        parser.print_help()
        return

    if args.single:
        validate_single_email(args.single, verbose=args.verbose)
    elif args.file:
        validate_emails_from_file(args.file, args.output, verbose=args.verbose)
        print(f"Results written to {args.output}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()