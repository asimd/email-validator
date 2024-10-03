#!/usr/bin/env python3

import sys
import os
import argparse
import logging
# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from emailsherlock import validate_single_email, validate_emails_from_file, setup_logging

def main():
    parser = argparse.ArgumentParser(description="EmailSherlock: Email validation tool")
    parser.add_argument("--single", help="Validate a single email address")
    parser.add_argument("--file", help="Input file containing email addresses")
    parser.add_argument("--output", help="Output file for results", default="results.txt")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    setup_logging(logging.DEBUG if args.verbose else logging.INFO)

    if args.single:
        validate_single_email(args.single, verbose=args.verbose)
    elif args.file:
        validate_emails_from_file(args.file, args.output, verbose=args.verbose)
        print(f"Results written to {args.output}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()