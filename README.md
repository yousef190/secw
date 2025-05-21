# Secure Document Management System

A Flask-based secure document management system with encryption, integrity verification, and HTTPS support.

## Features

- **Secure File Storage**: Files are encrypted using AES encryption before storage
- **File Integrity**: RSA digital signatures ensure file integrity
- **HTTPS Support**: All communications are protected using SSL/TLS
- **User Authentication**: Secure login system with password hashing
- **Access Control**: User-specific file access and management
- **Audit Logging**: Track user actions and file operations

## Security Features

- AES encryption for file storage
- RSA-SHA256 digital signatures for file integrity
- HTTPS/SSL encryption for data in transit
- Password hashing using bcrypt
- Session management with Flask-Session
- File integrity verification before downloads

## Prerequisites

- Python 3.x
- pip (Python package manager)
- OpenSSL (for HTTPS certificates)

## Required Packages

```
flask
flask-bcrypt
flask-sqlalchemy
flask-session
flask-migrate
flask-login
pyotp
pycryptodome
```

## Installation

1. Clone the repository or download the source code.

2. Install required packages:
```bash
pip install flask flask-bcrypt flask-sqlalchemy flask-session flask-migrate flask-login pyotp pycryptodome
```

3. Ensure SSL certificates are in place:
- `cert.pem` - SSL certificate
- `key.pem` - SSL private key
- `public_key.pem` - RSA public key for signatures
- `private_key.pem` - RSA private key for signatures

## Project Structure

```
├── app/
│   ├── __init__.py        # Application factory
│   ├── models.py          # Database models
│   ├── routes.py          # Route handlers
│   ├── utils.py           # Utility functions
│   ├── static/            # Static files
│   └── templates/         # HTML templates
├── uploaded_files/        # Original files
├── uploaded_files_encrypted/  # Encrypted files
├── config.py             # Configuration
├── run.py               # Application entry
└── README.md            # This file
```

## Running the Application

1. Make sure all required packages are installed
2. Ensure SSL certificates are in place
3. Run the application:
```bash
python run.py
```
4. Access the application at `https://localhost:5000`

## Security Notes

- Keep your SSL and RSA keys secure and private
- Regularly backup the encrypted files
- Monitor audit logs for suspicious activity
- Update dependencies regularly
- Never share your private keys

## Usage

1. Register a new account
2. Log in to access your dashboard
3. Upload files - they will be automatically encrypted
4. Download files - they will be verified and decrypted
5. Check file integrity using the "Check Integrity" button
6. View audit logs (admin only)

## File Operations

- **Upload**: Files are encrypted with AES and signed with RSA
- **Download**: Signatures are verified before decryption
- **Integrity Check**: Verify file signatures anytime
- **Delete**: Securely remove files and signatures

## License

This project is licensed under the MIT License.
