import streamlit as st
import os
import io
import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime
import zipfile
import tempfile

# Page configuration
st.set_page_config(
    page_title="🔐 Secure File Encryptor",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        text-align: center;
        padding: 2rem 0;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        font-size: 3rem;
        font-weight: bold;
        margin-bottom: 2rem;
    }
    
    .security-note {
        background-color: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 10px;
        padding: 1rem;
        margin: 1rem 0;
        color: #856404;
    }
    
    .success-box {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 10px;
        padding: 1rem;
        margin: 1rem 0;
        color: #155724;
    }
    
    .error-box {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        border-radius: 10px;
        padding: 1rem;
        margin: 1rem 0;
        color: #721c24;
    }
    
    .file-stats {
        background-color: #e9ecef;
        border-radius: 10px;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

class FileEncryption:
    """Class to handle file encryption and decryption operations"""
    
    @staticmethod
    def generate_key_from_password(password: str, salt: bytes = None) -> tuple:
        """Generate encryption key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    @staticmethod
    def encrypt_file(file_data: bytes, password: str, filename: str, file_type: str) -> bytes:
        """Encrypt file data with password"""
        # Generate key and salt
        key, salt = FileEncryption.generate_key_from_password(password)
        fernet = Fernet(key)
        
        # Create metadata
        metadata = {
            'filename': filename,
            'file_type': file_type,
            'encrypted_at': datetime.now().isoformat(),
            'file_size': len(file_data)
        }
        
        # Combine metadata and file data
        combined_data = {
            'metadata': metadata,
            'file_data': base64.b64encode(file_data).decode('utf-8')
        }
        
        # Encrypt the combined data
        combined_json = json.dumps(combined_data).encode()
        encrypted_data = fernet.encrypt(combined_json)
        
        # Combine salt and encrypted data
        return salt + encrypted_data
    
    @staticmethod
    def decrypt_file(encrypted_data: bytes, password: str) -> tuple:
        """Decrypt file data with password"""
        try:
            # Extract salt and encrypted content
            salt = encrypted_data[:16]
            encrypted_content = encrypted_data[16:]
            
            # Generate key from password and salt
            key, _ = FileEncryption.generate_key_from_password(password, salt)
            fernet = Fernet(key)
            
            # Decrypt data
            decrypted_data = fernet.decrypt(encrypted_content)
            combined_data = json.loads(decrypted_data.decode())
            
            # Extract metadata and file data
            metadata = combined_data['metadata']
            file_data = base64.b64decode(combined_data['file_data'].encode())
            
            return file_data, metadata, None
            
        except Exception as e:
            return None, None, str(e)

def main():
    """Main Streamlit application"""
    
    # Header
    st.markdown('<h1 class="main-header">🔐 Secure File Encryptor</h1>', unsafe_allow_html=True)
    st.markdown("### Encrypt and decrypt your files securely with military-grade AES encryption")
    
    # Sidebar for navigation
    st.sidebar.title("🛡️ Navigation")
    operation = st.sidebar.selectbox(
        "Choose Operation",
        ["🔒 Encrypt Files", "🔓 Decrypt Files", "📊 Batch Operations", "ℹ️ About"]
    )
    
    if operation == "🔒 Encrypt Files":
        encrypt_files_tab()
    elif operation == "🔓 Decrypt Files":
        decrypt_files_tab()
    elif operation == "📊 Batch Operations":
        batch_operations_tab()
    else:
        about_tab()

def encrypt_files_tab():
    """File encryption interface"""
    st.header("🔒 File Encryption")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # File upload
        uploaded_files = st.file_uploader(
            "Choose files to encrypt",
            accept_multiple_files=True,
            help="You can upload multiple files of any type (images, documents, videos, etc.)"
        )
        
        if uploaded_files:
            st.success(f"✅ {len(uploaded_files)} file(s) selected")
            
            # Display file information
            total_size = 0
            for file in uploaded_files:
                file_size = len(file.getvalue()) / (1024 * 1024)  # MB
                total_size += file_size
                st.markdown(f"📄 **{file.name}** ({file_size:.2f} MB)")
            
            st.markdown(f"**Total size:** {total_size:.2f} MB")
    
    with col2:
        # Password input
        st.subheader("🔑 Encryption Settings")
        password = st.text_input(
            "Encryption Password",
            type="password",
            help="Choose a strong password. You'll need this exact password to decrypt your files."
        )
        
        password_confirm = st.text_input(
            "Confirm Password",
            type="password"
        )
        
        # Password strength indicator
        if password:
            strength = check_password_strength(password)
            if strength == "Strong":
                st.success("💪 Strong password")
            elif strength == "Medium":
                st.warning("⚡ Medium strength password")
            else:
                st.error("⚠️ Weak password - consider making it longer")
    
    # Encryption options
    encryption_options = st.expander("⚙️ Advanced Options")
    with encryption_options:
        create_archive = st.checkbox(
            "Create single encrypted archive", 
            value=True,
            help="Combine all files into one encrypted archive"
        )
        include_timestamp = st.checkbox(
            "Include timestamp in filename", 
            value=True
        )
    
    # Encrypt button
    if st.button("🔒 Encrypt Files", type="primary", use_container_width=True):
        if not uploaded_files:
            st.error("❌ Please select files to encrypt")
        elif not password:
            st.error("❌ Please enter a password")
        elif password != password_confirm:
            st.error("❌ Passwords don't match")
        elif len(password) < 6:
            st.error("❌ Password must be at least 6 characters long")
        else:
            encrypt_files(uploaded_files, password, create_archive, include_timestamp)

def decrypt_files_tab():
    """File decryption interface"""
    st.header("🔓 File Decryption")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # File upload for encrypted files
        encrypted_file = st.file_uploader(
            "Choose encrypted file",
            type=['enc', 'encrypted'],
            help="Select the .enc or .encrypted file you want to decrypt"
        )
        
        if encrypted_file:
            file_size = len(encrypted_file.getvalue()) / (1024 * 1024)  # MB
            st.success(f"✅ Encrypted file selected: {encrypted_file.name} ({file_size:.2f} MB)")
    
    with col2:
        # Password input
        st.subheader("🔑 Decryption Settings")
        decrypt_password = st.text_input(
            "Decryption Password",
            type="password",
            help="Enter the password used to encrypt this file"
        )
    
    # Decrypt button
    if st.button("🔓 Decrypt File", type="primary", use_container_width=True):
        if not encrypted_file:
            st.error("❌ Please select an encrypted file")
        elif not decrypt_password:
            st.error("❌ Please enter the decryption password")
        else:
            decrypt_file(encrypted_file, decrypt_password)

def batch_operations_tab():
    """Batch operations interface"""
    st.header("📊 Batch Operations")
    
    batch_type = st.radio(
        "Select batch operation:",
        ["Encrypt multiple files separately", "Decrypt multiple files"]
    )
    
    if batch_type == "Encrypt multiple files separately":
        st.subheader("🔒 Batch Encryption")
        
        uploaded_files = st.file_uploader(
            "Choose multiple files to encrypt",
            accept_multiple_files=True
        )
        
        if uploaded_files:
            password = st.text_input("Batch encryption password", type="password")
            
            if st.button("🔒 Encrypt All Files Separately"):
                if password and len(password) >= 6:
                    batch_encrypt_files(uploaded_files, password)
                else:
                    st.error("❌ Please enter a valid password (at least 6 characters)")
    
    else:
        st.subheader("🔓 Batch Decryption")
        st.info("📝 Upload multiple .enc files to decrypt them all at once")
        
        encrypted_files = st.file_uploader(
            "Choose encrypted files",
            accept_multiple_files=True,
            type=['enc', 'encrypted']
        )
        
        if encrypted_files:
            decrypt_password = st.text_input("Batch decryption password", type="password")
            
            if st.button("🔓 Decrypt All Files"):
                if decrypt_password:
                    batch_decrypt_files(encrypted_files, decrypt_password)
                else:
                    st.error("❌ Please enter the decryption password")

def about_tab():
    """About and help information"""
    st.header("ℹ️ About Secure File Encryptor")
    
    st.markdown("""
    ### 🛡️ Security Features
    
    - **AES-256 Encryption**: Military-grade encryption standard
    - **PBKDF2 Key Derivation**: 100,000 iterations with random salt
    - **Local Processing**: All encryption/decryption happens on your device
    - **No Data Storage**: Your files and passwords are never stored
    
    ### 📝 How to Use
    
    1. **Encryption**: Upload files, set a strong password, click encrypt
    2. **Decryption**: Upload encrypted file, enter the same password, click decrypt
    3. **Batch Operations**: Process multiple files at once
    
    ### 🔐 Security Best Practices
    
    - Use strong, unique passwords (12+ characters)
    - Include numbers, symbols, and mixed case
    - Store passwords securely (password manager recommended)
    - Keep encrypted files and passwords separate
    
    ### ⚠️ Important Notes
    
    - **Password Recovery**: There's no way to recover lost passwords
    - **File Integrity**: Don't modify encrypted files manually
    - **Backup**: Keep copies of important encrypted files
    """)
    
    # Security note
    st.markdown("""
    <div class="security-note">
        <strong>🔒 Privacy Guarantee</strong><br>
        All encryption and decryption operations happen locally on your device. 
        Your files, passwords, and data never leave your computer or get sent to any server.
    </div>
    """, unsafe_allow_html=True)

def check_password_strength(password: str) -> str:
    """Check password strength"""
    if len(password) >= 12 and any(c.isupper() for c in password) and any(c.islower() for c in password) and any(c.isdigit() for c in password) and any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return "Strong"
    elif len(password) >= 8 and (any(c.isupper() for c in password) or any(c.islower() for c in password)) and any(c.isdigit() for c in password):
        return "Medium"
    else:
        return "Weak"

def encrypt_files(uploaded_files, password, create_archive, include_timestamp):
    """Encrypt uploaded files"""
    try:
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        if create_archive and len(uploaded_files) > 1:
            # Create archive with all files
            status_text.text("Creating encrypted archive...")
            
            # Create a zip in memory
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for i, file in enumerate(uploaded_files):
                    zip_file.writestr(file.name, file.getvalue())
                    progress_bar.progress((i + 1) / len(uploaded_files) * 0.5)
            
            zip_data = zip_buffer.getvalue()
            
            # Encrypt the zip file
            status_text.text("Encrypting archive...")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S") if include_timestamp else ""
            archive_name = f"encrypted_archive_{timestamp}.zip" if timestamp else "encrypted_archive.zip"
            
            encrypted_data = FileEncryption.encrypt_file(
                zip_data, password, archive_name, "application/zip"
            )
            
            progress_bar.progress(1.0)
            
            # Download button
            filename = f"encrypted_archive_{timestamp}.enc" if timestamp else "encrypted_archive.enc"
            st.download_button(
                label="📥 Download Encrypted Archive",
                data=encrypted_data,
                file_name=filename,
                mime="application/octet-stream",
                type="primary"
            )
            
            st.markdown(f"""
            <div class="success-box">
                <strong>✅ Success!</strong><br>
                Archive encrypted successfully! Contains {len(uploaded_files)} files.
            </div>
            """, unsafe_allow_html=True)
            
        else:
            # Encrypt files individually
            encrypted_files = []
            
            for i, file in enumerate(uploaded_files):
                status_text.text(f"Encrypting {file.name}...")
                
                encrypted_data = FileEncryption.encrypt_file(
                    file.getvalue(), password, file.name, file.type or "application/octet-stream"
                )
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S") if include_timestamp else ""
                filename = f"{file.name}_{timestamp}.enc" if timestamp else f"{file.name}.enc"
                
                encrypted_files.append((filename, encrypted_data))
                progress_bar.progress((i + 1) / len(uploaded_files))
            
            # Provide download buttons for each file
            st.markdown("""
            <div class="success-box">
                <strong>✅ Success!</strong><br>
                Files encrypted successfully! Download them below:
            </div>
            """, unsafe_allow_html=True)
            
            for filename, encrypted_data in encrypted_files:
                st.download_button(
                    label=f"📥 Download {filename}",
                    data=encrypted_data,
                    file_name=filename,
                    mime="application/octet-stream"
                )
        
        status_text.text("✅ Encryption completed!")
        
    except Exception as e:
        st.error(f"❌ Encryption failed: {str(e)}")

def decrypt_file(encrypted_file, password):
    """Decrypt uploaded file"""
    try:
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        status_text.text("Decrypting file...")
        progress_bar.progress(0.3)
        
        # Decrypt the file
        file_data, metadata, error = FileEncryption.decrypt_file(
            encrypted_file.getvalue(), password
        )
        
        progress_bar.progress(0.8)
        
        if error:
            st.error(f"❌ Decryption failed: {error}")
            st.error("Please check your password and ensure the file is a valid encrypted file.")
            return
        
        progress_bar.progress(1.0)
        status_text.text("✅ Decryption completed!")
        
        # Show file information
        st.markdown(f"""
        <div class="file-stats">
            <strong>📄 File Information:</strong><br>
            • <strong>Original filename:</strong> {metadata['filename']}<br>
            • <strong>File size:</strong> {metadata['file_size'] / (1024*1024):.2f} MB<br>
            • <strong>Encrypted on:</strong> {metadata['encrypted_at']}<br>
            • <strong>File type:</strong> {metadata['file_type']}
        </div>
        """, unsafe_allow_html=True)
        
        # Download button
        st.download_button(
            label=f"📥 Download {metadata['filename']}",
            data=file_data,
            file_name=metadata['filename'],
            mime=metadata['file_type'],
            type="primary"
        )
        
        st.markdown("""
        <div class="success-box">
            <strong>✅ Success!</strong><br>
            File decrypted successfully!
        </div>
        """, unsafe_allow_html=True)
        
    except Exception as e:
        st.error(f"❌ Decryption failed: {str(e)}")

def batch_encrypt_files(uploaded_files, password):
    """Batch encrypt multiple files"""
    try:
        progress_bar = st.progress(0)
        encrypted_files = []
        
        for i, file in enumerate(uploaded_files):
            encrypted_data = FileEncryption.encrypt_file(
                file.getvalue(), password, file.name, file.type or "application/octet-stream"
            )
            encrypted_files.append((f"{file.name}.enc", encrypted_data))
            progress_bar.progress((i + 1) / len(uploaded_files))
        
        st.success(f"✅ Successfully encrypted {len(encrypted_files)} files!")
        
        # Provide download buttons
        for filename, encrypted_data in encrypted_files:
            st.download_button(
                label=f"📥 Download {filename}",
                data=encrypted_data,
                file_name=filename,
                mime="application/octet-stream"
            )
            
    except Exception as e:
        st.error(f"❌ Batch encryption failed: {str(e)}")

def batch_decrypt_files(encrypted_files, password):
    """Batch decrypt multiple files"""
    try:
        progress_bar = st.progress(0)
        decrypted_files = []
        failed_files = []
        
        for i, file in enumerate(encrypted_files):
            file_data, metadata, error = FileEncryption.decrypt_file(
                file.getvalue(), password
            )
            
            if error:
                failed_files.append(file.name)
            else:
                decrypted_files.append((metadata['filename'], file_data, metadata['file_type']))
            
            progress_bar.progress((i + 1) / len(encrypted_files))
        
        if decrypted_files:
            st.success(f"✅ Successfully decrypted {len(decrypted_files)} files!")
            
            for filename, file_data, file_type in decrypted_files:
                st.download_button(
                    label=f"📥 Download {filename}",
                    data=file_data,
                    file_name=filename,
                    mime=file_type
                )
        
        if failed_files:
            st.error(f"❌ Failed to decrypt {len(failed_files)} files: {', '.join(failed_files)}")
            
    except Exception as e:
        st.error(f"❌ Batch decryption failed: {str(e)}")

if __name__ == "__main__":
    main()