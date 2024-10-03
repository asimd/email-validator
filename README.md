# EmailSherlock 🕵️‍♂️📧

EmailSherlock is a powerful Python tool for validating email addresses using DNS and SMTP checks. It provides a confidence score for each email's validity and potential deliverability, helping you deduce the legitimacy of email addresses with detective-like precision.

## Features

- Validates email format using regex
- Checks domain DNS records (MX and A records)
- Attempts SMTP connection to verify mail server responsiveness
- Provides a confidence score (0-100%) for each email
- Handles both single email validation and bulk validation from a file
- Multi-threaded for improved performance with large datasets
- Verbose mode for detailed output

## Installation

You can install EmailSherlock using pip:

```bash
pip install emailsherlock
```

## Usage

### Command Line Interface

1. Validate a single email:

```bash
emailsherlock --single example@email.com
```

2. Validate emails from a file:

```bash
emailsherlock --file input_emails.txt --output results.csv
```

3. Use verbose mode for detailed output:

```bash
emailsherlock --single example@email.com -v
```

### Python API

You can also use EmailSherlock in your Python scripts:

```python
from emailsherlock import validate_single_email, validate_emails_from_file

# Validate a single email
validate_single_email("example@email.com", verbose=True)

# Validate emails from a file
validate_emails_from_file("input_emails.txt", "results.csv", verbose=True)
```

### Running Manually

If you've cloned the repository or downloaded the source code, you can run EmailSherlock manually without installation:

1. Navigate to the project directory:

```bash
cd path/to/emailsherlock
```

2. Run the script directly:

```bash
python emailsherlock.py --single example@email.com
```

or

```bash
python emailsherlock.py --file input_emails.txt --output results.csv
```

Make sure you have the required dependencies installed (`dnspython`) before running the script manually.

## Output

The script generates a CSV file with the following columns:
- Email
- School (if provided in the input)
- Valid (True/False)
- Confidence Score (0-100%)
- Notes

## Confidence Score Explanation

- 100%: Valid format, DNS records, MX records, and responsive SMTP server
- 75%: Valid format, DNS records, and MX records, but unresponsive SMTP server
- 50%: Valid format and DNS records, but no MX records
- 25%: Valid format and DNS records, but no MX records and unresponsive SMTP server
- 0%: Invalid format, no valid DNS records, or explicitly rejected by SMTP server

## Limitations

EmailSherlock provides an estimate of email validity based on DNS and SMTP checks. However, it cannot guarantee that an email address is actually in use or will successfully receive emails. The only way to be certain is to send an actual email and confirm receipt.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

If you encounter any issues or have questions, please [open an issue](https://github.com/asimd/emailsherlock/issues) on GitHub.

## Buy Me a Coffee

If you find EmailSherlock useful and want to support its development, you can buy me a coffee:

[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/asimd)

Your support is greatly appreciated and helps maintain and improve EmailSherlock!