import re
import dns.resolver
import logging
import concurrent.futures
from typing import Tuple, List, Optional
from dataclasses import dataclass
import socket
import smtplib
import ssl
import random

@dataclass
class ValidationResult:
    email: str
    school: Optional[str]
    is_valid: bool
    confidence_score: int
    error_message: str = ""
    notes: str = ""

def setup_logging(log_level=logging.INFO):
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

def validate_email_format(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def check_domain_mx(domain: str) -> Tuple[bool, str, Optional[str]]:
    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx_records = [str(r.exchange).rstrip('.') for r in records]
        return True, f"MX records found: {', '.join(mx_records)}", mx_records[0]
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
    cleaned = re.sub(r'Please try.*', '', message, flags=re.DOTALL)
    cleaned = ' '.join(cleaned.split())
    return cleaned

def check_smtp_connection(mx_record: str, email: str) -> Tuple[bool, str, int]:
    sender_email = f"verify_{random.randint(1000, 9999)}@example.com"
    ports_to_try = [(587, 'STARTTLS'), (465, 'SSL'), (25, 'Plain')]
    
    for port, connection_type in ports_to_try:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            if connection_type == 'SSL':
                with smtplib.SMTP_SSL(mx_record, port, context=context, timeout=10) as server:
                    return check_rcpt(server, sender_email, email)
            else:
                with smtplib.SMTP(mx_record, port, timeout=10) as server:
                    if connection_type == 'STARTTLS' and server.has_extn('STARTTLS'):
                        server.starttls(context=context)
                    return check_rcpt(server, sender_email, email)
        except Exception as e:
            continue
    
    return False, f"Error connecting to SMTP server on all ports", 0

def check_rcpt(server, sender_email, email):
    server.ehlo('example.com')
    server.mail(sender_email)
    code, message = server.rcpt(email)
    if code == 250:
        return True, "SMTP server accepted the email address", 50
    else:
        return False, clean_error_message(message.decode()), 0

def verify_email(email: str, verbose: bool = False) -> Tuple[bool, int, str, str]:
    if verbose:
        logging.debug(f"Verifying email: {email}")
    
    if not validate_email_format(email):
        if verbose:
            logging.debug(f"Invalid email format: {email}")
        return False, 0, "Invalid email format", ""

    domain = email.split('@')[1]
    is_valid, message, mx_record = check_domain_mx(domain)
    
    if verbose:
        logging.debug(f"Domain check result: {message}")
    
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
    
    if verbose:
        logging.debug(f"Verification result: Valid: {is_valid}, Confidence: {confidence_score}%, Notes: {'; '.join(notes)}")
    
    return is_valid, confidence_score, message, "; ".join(notes)

def process_line(line: str, verbose: bool = False) -> ValidationResult:
    parts = line.strip().split(',')
    if len(parts) == 2:
        school, email = parts
    elif len(parts) == 1:
        school, email = None, parts[0]
    else:
        return ValidationResult(email="", school=None, is_valid=False, confidence_score=0, error_message="Invalid input format")
    
    is_valid, confidence_score, error_message, notes = verify_email(email, verbose)
    return ValidationResult(email, school, is_valid, confidence_score, error_message, notes)

def validate_single_email(email: str, verbose: bool = False):
    is_valid, confidence_score, error_message, notes = verify_email(email, verbose)
    status = "Valid" if is_valid else "Invalid"
    print(f"Email: {email}")
    print(f"Status: {status}")
    print(f"Confidence Score: {confidence_score}%")
    print(f"Notes: {notes}")
    if error_message:
        print(f"Error Message: {error_message}")
    
    if verbose:
        logging.debug(f"Verbose output for {email}:")
        logging.debug(f"Is Valid: {is_valid}")
        logging.debug(f"Confidence Score: {confidence_score}")
        logging.debug(f"Notes: {notes}")
        logging.debug(f"Error Message: {error_message}")

def validate_emails_from_file(input_file: str, output_file: str, max_workers: int = 10, verbose: bool = False):
    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        logging.error(f"Error reading input file: {e}")
        return

    results: List[ValidationResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_line = {executor.submit(process_line, line, verbose): line for line in lines}
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