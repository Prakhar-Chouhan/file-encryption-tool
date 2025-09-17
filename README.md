# file-encryption-tool

🔧 How to Use
Encryption Process:

Go to "🔒 Encrypt Files" tab
Upload one or more files
Set a strong password (with confirmation)
Choose options (archive creation, timestamps)
Click "🔒 Encrypt Files"
Download the encrypted .enc files

Decryption Process:

Go to "🔓 Decrypt Files" tab
Upload the .enc file
Enter the decryption password
Click "🔓 Decrypt File"
Download the original file

Batch Operations:

Encrypt multiple files separately
Decrypt multiple files at once
Progress tracking for large operations

🛡️ Security Implementation
The app uses the cryptography library which provides:

Fernet encryption: Symmetric encryption using AES-128 in CBC mode
PBKDF2: Password-based key derivation with SHA-256
Random salts: Each encryption uses a unique salt
Authenticated encryption: Prevents tampering

🔄 File Structure
Encrypted files contain:

Metadata (original filename, size, type, timestamp)
Encrypted file data
Salt for key derivation
Authentication data

⚠️ Important Notes

Password Recovery: Lost passwords cannot be recovered
File Integrity: Don't modify encrypted files manually
Local Processing: No data is sent to external servers
Strong Passwords: Use complex passwords for better security

The application is ready to run and provides enterprise-level file encryption in a user-friendly Streamlit interface!
