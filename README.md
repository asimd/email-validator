# Email Validator
A Python script for validating email addresses using DNS and SMTP checks, providing a confidence score for each email's validity and potential deliverability.

## Features
- Validates email format using regex
- Checks domain DNS records (MX and A records)
- Attempts SMTP connection to verify mail server responsiveness
- Provides a confidence score (0-100%) for each email
- Handles both single email validation and bulk validation from a file
- Multi-threaded for improved performance with large datasets

## Requirements
- Python 3.7+
- dnspython library

## Installation
1. Clone this repository:
   ```
   git clone https://github.com/yourusername/email-validator.git
   cd email-validator
   ```
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage
### Single Email Validation
To validate a single email address:
```
python email_validator.py --single email@example.com
```

### Bulk Email Validation from File
To validate multiple email addresses from a file:
```
python email_validator.py --file input_file.txt output_file.csv
```
The input file should contain one email address per line. If you want to include additional information (like a school name), use a comma to separate it from the email:
```
email1@example.com
email2@example.com
School Name,email3@example.com
```

## Output
The script will generate a CSV file with the following columns:
- Email
- School (if provided in the input)
- Valid (True/False)
- Confidence Score (0-100%)
- Notes
Additionally, a disclaimer about the limitations of email validation will be included at the top of the output file.

## Confidence Score Explanation
- 100%: Valid format, DNS records, MX records, and responsive SMTP server
- 75%: Valid format, DNS records, and MX records, but unresponsive SMTP server
- 50%: Valid format and DNS records, but no MX records or unresponsive SMTP server
- 0%: Invalid format or no valid DNS records

## Limitations
This tool provides an estimate of email validity based on DNS and SMTP checks. However, it cannot guarantee that an email address is actually in use or will successfully receive emails. The only way to be certain is to send an actual email and confirm receipt.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support the Project
If you find this tool useful, you can buy me a coffee:

[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/asimd)