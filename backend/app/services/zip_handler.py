"""Safe ZIP file extraction with security validation."""
import zipfile
import os
import tempfile
import shutil
import io
from pathlib import Path
from contextlib import contextmanager

# Configuration
MAX_ZIP_SIZE = 25 * 1024 * 1024  # 25MB
MAX_EXTRACTED_SIZE = 100 * 1024 * 1024  # 100MB
MAX_FILE_COUNT = 1000
MAX_SINGLE_FILE_SIZE = 1 * 1024 * 1024  # 1MB

# Directories to skip during scanning
SKIP_DIRS = {
    "node_modules",
    ".git",
    "dist",
    "build",
    ".next",
    "venv",
    "__pycache__",
    ".cache",
}

# Allowed file extensions for scanning
ALLOWED_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx",
    ".py",
    ".env",
    ".json",
    ".yml", ".yaml",
    ".toml", ".ini",
}


def is_allowed_scan_file(file_path: str) -> bool:
    """Check whether a file name is supported by the scanners."""
    path = Path(file_path)
    name = path.name.lower()
    
    if name == ".env" or name.startswith(".env."):
        return True
    
    return path.suffix.lower() in ALLOWED_EXTENSIONS


class ZipExtractionError(Exception):
    """Raised when ZIP extraction fails validation."""
    pass


def _validate_zip_entry(entry_name: str, extract_path: Path) -> bool:
    """
    Validate a ZIP entry for security issues.
    
    Checks for:
    - Zip Slip (../../ paths)
    - Absolute paths
    - Symlinks
    
    Returns True if valid, False otherwise.
    """
    # Reject absolute paths
    if os.path.isabs(entry_name):
        raise ZipExtractionError(f"Absolute path not allowed: {entry_name}")
    
    # Reject null bytes
    if "\x00" in entry_name:
        raise ZipExtractionError(f"Null byte in path: {entry_name}")
    
    # Resolve the full path and check it's within extract_path
    normalized_path = (extract_path / entry_name).resolve()
    try:
        normalized_path.relative_to(extract_path.resolve())
    except ValueError:
        raise ZipExtractionError(f"Zip Slip detected: {entry_name}")
    
    return True


def extract_zip(zip_content: bytes) -> str:
    """
    Safely extract a ZIP file from bytes.
    
    Validates:
    - ZIP file format
    - Entry paths (Zip Slip prevention)
    - Total extracted size (100MB limit)
    - File count (1000 limit)
    - Individual file size (1MB limit)
    
    Returns the path to the extracted directory.
    The caller is responsible for cleanup (or use with context manager).
    
    Raises ZipExtractionError on validation failure.
    """
    # Create temporary directory for extraction
    temp_dir = tempfile.mkdtemp(prefix="vibeguard_")
    extract_path = Path(temp_dir)
    
    try:
        # Validate ZIP format
        try:
            # Wrap bytes in BytesIO to provide seek() method
            zip_buffer = io.BytesIO(zip_content)
            zip_file = zipfile.ZipFile(zip_buffer, "r")
        except (zipfile.BadZipFile, Exception) as e:
            raise ZipExtractionError(f"Invalid ZIP file: {str(e)}")
        
        # Check for suspicious ZIP structures
        try:
            bad_file = zip_file.testzip()
            if bad_file is not None:
                raise ZipExtractionError(f"Corrupted ZIP entry: {bad_file}")
        except Exception as e:
            raise ZipExtractionError(f"ZIP validation failed: {str(e)}")
        
        # Validate entries and extract
        total_extracted = 0
        file_count = 0
        
        for entry in zip_file.infolist():
            # Validate path
            _validate_zip_entry(entry.filename, extract_path)
            
            # Skip directories
            if entry.is_dir():
                continue
            
            # Check individual file size
            if entry.file_size > MAX_SINGLE_FILE_SIZE:
                raise ZipExtractionError(
                    f"File exceeds 1MB limit: {entry.filename} ({entry.file_size} bytes)"
                )
            
            # Check total extracted size
            total_extracted += entry.file_size
            if total_extracted > MAX_EXTRACTED_SIZE:
                raise ZipExtractionError(
                    f"Total extracted size exceeds 100MB limit"
                )
            
            # Check file count
            file_count += 1
            if file_count > MAX_FILE_COUNT:
                raise ZipExtractionError(
                    f"File count exceeds 1000 limit"
                )
            
            # Extract file
            zip_file.extract(entry, extract_path)
        
        zip_file.close()
        return str(extract_path)
        
    except ZipExtractionError:
        # Clean up on validation error
        shutil.rmtree(extract_path, ignore_errors=True)
        raise
    except Exception as e:
        # Clean up on any other error
        shutil.rmtree(extract_path, ignore_errors=True)
        raise ZipExtractionError(f"Extraction failed: {str(e)}")


@contextmanager
def extract_zip_temp(zip_content: bytes):
    """
    Context manager for safe ZIP extraction with automatic cleanup.
    
    Usage:
        with extract_zip_temp(zip_bytes) as extract_dir:
            # scan extract_dir
    """
    extract_dir = extract_zip(zip_content)
    try:
        yield extract_dir
    finally:
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir, ignore_errors=True)


def should_skip_file(file_path: str) -> bool:
    """Check if a file should be skipped during scanning."""
    path_parts = Path(file_path).parts
    
    # Skip if in excluded directory
    for part in path_parts:
        if part in SKIP_DIRS:
            return True
    
    # Check file extension or supported dotfile name
    if not is_allowed_scan_file(file_path):
        return True
    
    return False
