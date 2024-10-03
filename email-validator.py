import sys
import re
import dns.resolver
import logging
import concurrent.futures
from typing import Tuple, List, Optional
from dataclasses import dataclass
import socket
import smtplib
import ssl

@dataclass
class ValidationResult:
    email: str
    school: Optional[str]
    is_valid: bool
    confidence_score: int
    error_message: str = ""
    notes: str = ""

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def validate_email_format(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def check_domain_mx(domain: str) -> Tuple[bool, str, Optional[str]]:
    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(records[0].exchange).rstrip('.')
        return True, f"MX record found: {mx_record}", mx_record
    except dns.resolver.NXDOMAIN:
        return False, f"Domain {domain} does not exist", None
    except dns.resolver.NoAnswer:
        try:
            dns.resolver.resolve(domain, 'A')
            return True, f"No MX record, but A record found for {domain}", domain
        except dns.resolver.NoAnswer:
            return False, f"No MX or A records found for {domain}", None
    except dns.resolver.NoNameservers:
        return False, f"DNS query failed for {domain}. Check your network connection or DNS configuration.", None
    except Exception as e:
        return False, f"Error querying DNS for {domain}: {str(e)}", None

def clean_error_message(message: str) -> str:
    # Remove the "Please try" part and everything after it
    cleaned = re.sub(r'Please try.*', '', message, flags=re.DOTALL)
    # Remove any remaining newlines and extra spaces
    cleaned = ' '.join(cleaned.split())
    return cleaned

def check_smtp_connection(mx_record: str, email: str) -> Tuple[bool, str, int]:
    sender_email = "john@gmail.com"  # Use a real email you control
    try:
        # Try STARTTLS on port 587 first
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with smtplib.SMTP(mx_record, 587, timeout=10) as server:
            server.ehlo('gmail.com')
            if server.has_extn('STARTTLS'):
                server.starttls(context=context)
                server.ehlo()
            server.mail(sender_email)
            code, message = server.rcpt(email)
            if code == 250:
                return True, "SMTP server accepted the email address", 50
            else:
                return False, clean_error_message(message.decode()), 0
    except Exception as e:
        # If STARTTLS fails, try a direct SSL connection on port 465
        try:
            with smtplib.SMTP_SSL(mx_record, 465, context=context, timeout=10) as server:
                server.ehlo('your_server_name.com')
                server.mail(sender_email)
                code, message = server.rcpt(email)
                if code == 250:
                    return True, "SMTP server accepted the email address (SSL)", 50
                else:
                    return False, clean_error_message(message.decode()), 0
        except Exception as e2:
            # If both methods fail, try a plain connection on port 25
            try:
                with smtplib.SMTP(mx_record, 25, timeout=10) as server:
                    server.ehlo('gmail.com')
                    server.mail(sender_email)
                    code, message = server.rcpt(email)
                    if code == 250:
                        return True, "SMTP server accepted the email address (plain)", 50
                    else:
                        return False, clean_error_message(message.decode()), 0
            except Exception as e3:
                return False, f"Error connecting to SMTP server: STARTTLS: {str(e)}, SSL: {str(e2)}, Plain: {str(e3)}", 0

def verify_email(email: str) -> Tuple[bool, int, str, str]:
    if not validate_email_format(email):
        return False, 0, "Invalid email format", ""

    domain = email.split('@')[1]
    is_valid, message, mx_record = check_domain_mx(domain)
    
    confidence_score = 0
    notes = []

    if is_valid:
        confidence_score += 25
        notes.append("Domain has valid DNS records")
        
        if mx_record:
            confidence_score += 25
            notes.append("MX record found")
            
            smtp_connectable, smtp_message, smtp_score = check_smtp_connection(mx_record, email)
            confidence_score += smtp_score
            if smtp_connectable:
                notes.append("SMTP server accepted the email address")
            else:
                notes.append(f"SMTP check failed: {smtp_message}")
                if "does not exist" in smtp_message.lower():
                    confidence_score = 0
                    is_valid = False
        else:
            notes.append("No MX record, using A record")
    
    return is_valid, confidence_score, message, "; ".join(notes)

def process_line(line: str) -> ValidationResult:
    parts = line.strip().split(',')
    if len(parts) == 2:
        school, email = parts
    elif len(parts) == 1:
        school, email = None, parts[0]
    else:
        return ValidationResult(email="", school=None, is_valid=False, confidence_score=0, error_message="Invalid input format")
    
    is_valid, confidence_score, error_message, notes = verify_email(email)
    return ValidationResult(email, school, is_valid, confidence_score, error_message, notes)

def validate_emails_from_file(input_file: str, output_file: str, max_workers: int = 10):
    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        logging.error(f"Error reading input file: {e}")
        return

    results: List[ValidationResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_line = {executor.submit(process_line, line): line for line in lines}
        for future in concurrent.futures.as_completed(future_to_line):
            try:
                result = future.result()
                results.append(result)
                status = "Valid" if result.is_valid else "Invalid"
                log_message = f"[{status}] [Confidence: {result.confidence_score}%] {result.email} - {result.error_message} {result.notes}"
                logging.info(log_message)
            except Exception as e:
                logging.error(f"Error processing line: {future_to_line[future].strip()} - {str(e)}")

    try:
        with open(output_file, "w") as f:
            f.write("Disclaimer: Email validation without sending an actual email is inherently limited. "
                    "These results are based on DNS and SMTP checks and do not guarantee deliverability.\n\n")
            f.write("Email,School,Valid,Confidence Score,Notes\n")
            for result in results:
                if result.school:
                    f.write(f"{result.email},{result.school},{result.is_valid},{result.confidence_score}%,{result.notes}\n")
                else:
                    f.write(f"{result.email},N/A,{result.is_valid},{result.confidence_score}%,{result.notes}\n")
        logging.info(f"Results written to {output_file}")
    except IOError as e:
        logging.error(f"Error writing to output file: {e}")

def validate_single_email(email: str):
    is_valid, confidence_score, error_message, notes = verify_email(email)
    status = "Valid" if is_valid else "Invalid"
    print(f"Email: {email}")
    print(f"Status: {status}")
    print(f"Confidence Score: {confidence_score}%")
    print(f"Notes: {notes}")
    print(f"Error Message: {error_message}")

def print_usage():
    print("Usage:")
    print("  For single email validation:")
    print("    python email_validator.py --single <email_address>")
    print("  For file validation:")
    print("    python email_validator.py --file <input_file> [output_file]")

if __name__ == "__main__":
    setup_logging()

    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "--single":
        if len(sys.argv) != 3:
            print_usage()
            sys.exit(1)
        email = sys.argv[2]
        validate_single_email(email)
    elif mode == "--file":
        if len(sys.argv) == 3:
            input_file = sys.argv[2]
            output_file = "results.txt"
        elif len(sys.argv) == 4:
            input_file, output_file = sys.argv[2], sys.argv[3]
        else:
            print_usage()
            sys.exit(1)
        validate_emails_from_file(input_file, output_file)
    else:
        print_usage()
        sys.exit(1)

    logging.info("Email validation completed.")