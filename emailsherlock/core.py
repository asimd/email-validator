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
import asyncio
import aiodns

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

async def check_domain_mx(domain: str) -> Tuple[bool, str, Optional[str]]:
    resolver = aiodns.DNSResolver()
    try:
        records = await resolver.query(domain, 'MX')
        mx_records = [str(r.host).rstrip('.') for r in records]
        return True, f"MX records found: {', '.join(mx_records)}", mx_records[0]
    except aiodns.error.DNSError as e:
        if e.args[0] == 4:  # NXDOMAIN
            return False, f"Domain {domain} does not exist", None
        elif e.args[0] == 1:  # No Answer
            try:
                await resolver.query(domain, 'A')
                return True, f"No MX record, but A record found for {domain}", domain
            except aiodns.error.DNSError:
                return False, f"No MX or A records found for {domain}", None
        else:
            return False, f"DNS query failed for {domain}: {str(e)}", None

async def check_smtp_connection(mx_record: str, email: str) -> Tuple[bool, str, int]:
    ports_to_try = [25, 587, 465]
    for port in ports_to_try:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(mx_record, port), timeout=5)
            writer.close()
            await writer.wait_closed()
            return True, "SMTP server connection successful", 50
        except (asyncio.TimeoutError, ConnectionRefusedError):
            continue
        except Exception as e:
            return False, f"Error connecting to SMTP server: {str(e)}", 0
    return False, "Unable to connect to SMTP server on any port", 0

async def verify_email(email: str, verbose: bool = False) -> Tuple[bool, int, str, str]:
    if verbose:
        logging.debug(f"Verifying email: {email}")
    
    if not validate_email_format(email):
        if verbose:
            logging.debug(f"Invalid email format: {email}")
        return False, 0, "Invalid email format", ""

    domain = email.split('@')[1]
    is_valid, message, mx_record = await check_domain_mx(domain)
    
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
            
            smtp_connectable, smtp_message, smtp_score = await check_smtp_connection(mx_record, email)
            confidence_score += smtp_score
            if smtp_connectable:
                notes.append("SMTP server connection successful")
            else:
                notes.append(f"SMTP check failed: {smtp_message}")
        else:
            notes.append("No MX record, using A record")
    
    if verbose:
        logging.debug(f"Verification result: Valid: {is_valid}, Confidence: {confidence_score}%, Notes: {'; '.join(notes)}")
    
    return is_valid, confidence_score, message, "; ".join(notes)

async def process_line(line: str, verbose: bool = False) -> ValidationResult:
    parts = line.strip().split(',')
    if len(parts) == 2:
        school, email = parts
    elif len(parts) == 1:
        school, email = None, parts[0]
    else:
        return ValidationResult(email="", school=None, is_valid=False, confidence_score=0, error_message="Invalid input format")
    
    is_valid, confidence_score, error_message, notes = await verify_email(email, verbose)
    return ValidationResult(email, school, is_valid, confidence_score, error_message, notes)

def validate_single_email(email: str, verbose: bool = False):
    loop = asyncio.get_event_loop()
    is_valid, confidence_score, error_message, notes = loop.run_until_complete(verify_email(email, verbose))
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

async def async_validate_emails_from_file(input_file: str, output_file: str, verbose: bool = False):
    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        logging.error(f"Error reading input file: {e}")
        return

    tasks = [process_line(line, verbose) for line in lines]
    results = await asyncio.gather(*tasks)

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

def validate_emails_from_file(input_file: str, output_file: str, max_workers: int = 10, verbose: bool = False):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(async_validate_emails_from_file(input_file, output_file, verbose))

def validate_emails_from_file(input_file: str, output_file: str, max_workers: int = 10, verbose: bool = False):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(async_validate_emails_from_file(input_file, output_file, verbose))

async def async_bulk_verify_emails(emails: List[str], verbose: bool = False) -> List[Tuple[bool, int, str, str]]:
    tasks = [verify_email(email, verbose) for email in emails]
    return await asyncio.gather(*tasks)

def bulk_verify_emails(emails: List[str], verbose: bool = False) -> List[Tuple[bool, int, str, str]]:
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(async_bulk_verify_emails(emails, verbose))

# Helper function to chunk a list
def chunk_list(lst, chunk_size):
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def validate_emails_from_file_with_progress(input_file: str, output_file: str, chunk_size: int = 100, verbose: bool = False):
    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()
    except IOError as e:
        logging.error(f"Error reading input file: {e}")
        return

    total_emails = len(lines)
    processed_emails = 0
    results = []

    for chunk in chunk_list(lines, chunk_size):
        emails = [line.strip().split(',')[-1] for line in chunk]
        chunk_results = bulk_verify_emails(emails, verbose)
        
        for line, (is_valid, confidence_score, error_message, notes) in zip(chunk, chunk_results):
            parts = line.strip().split(',')
            school = parts[0] if len(parts) == 2 else None
            email = parts[-1]
            results.append(ValidationResult(email, school, is_valid, confidence_score, error_message, notes))

        processed_emails += len(chunk)
        progress = (processed_emails / total_emails) * 100
        print(f"Progress: {progress:.2f}% ({processed_emails}/{total_emails})")

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