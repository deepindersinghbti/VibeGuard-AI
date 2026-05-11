"""Tests for ZIP extraction and security validation."""
import pytest
import os
import zipfile
import io
from app.services.zip_handler import (
    extract_zip,
    extract_zip_temp,
    ZipExtractionError,
)


class TestZipExtraction:
    """Tests for safe ZIP extraction."""
    
    def test_extract_valid_zip(self, safe_project_zip):
        """Test extracting a valid ZIP file."""
        extract_dir = extract_zip(safe_project_zip)
        
        try:
            # Verify files were extracted
            assert os.path.exists(extract_dir)
            assert os.path.exists(os.path.join(extract_dir, "utils.py"))
            assert os.path.exists(os.path.join(extract_dir, "lib.js"))
        finally:
            import shutil
            if os.path.exists(extract_dir):
                shutil.rmtree(extract_dir)
    
    def test_extract_zip_temp_context_manager(self, safe_project_zip):
        """Test context manager automatically cleans up."""
        extract_dir = None
        
        with extract_zip_temp(safe_project_zip) as temp_dir:
            extract_dir = temp_dir
            assert os.path.exists(extract_dir)
        
        # After context, directory should be deleted
        assert not os.path.exists(extract_dir)
    
    def test_reject_invalid_zip(self):
        """Test rejection of invalid ZIP file."""
        with pytest.raises(ZipExtractionError):
            extract_zip(b"Not a ZIP file")
    
    def test_reject_corrupted_zip(self):
        """Test rejection of corrupted ZIP."""
        # Create a file that looks like ZIP but is corrupted
        bad_zip = b"PK\x03\x04" + b"corrupted_data"
        
        with pytest.raises(ZipExtractionError):
            extract_zip(bad_zip)
    
    def test_zip_slip_prevention(self):
        """Test prevention of Zip Slip (../../ paths)."""
        # Create a ZIP with malicious path
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as z:
            z.writestr("../../etc/passwd", "malicious content")
        
        zip_buffer.seek(0)
        
        with pytest.raises(ZipExtractionError):
            extract_zip(zip_buffer.getvalue())
    
    def test_absolute_path_rejection(self):
        """Test rejection of absolute paths."""
        # Create a ZIP with absolute path
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as z:
            z.writestr("/etc/passwd", "malicious content")
        
        zip_buffer.seek(0)
        
        with pytest.raises(ZipExtractionError):
            extract_zip(zip_buffer.getvalue())
    
    def test_file_size_limit(self):
        """Test rejection of files exceeding 1MB limit."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as z:
            # Create a file larger than 1MB
            large_content = b"x" * (2 * 1024 * 1024)
            z.writestr("large_file.bin", large_content)
        
        zip_buffer.seek(0)
        
        with pytest.raises(ZipExtractionError):
            extract_zip(zip_buffer.getvalue())
    
    def test_total_size_limit(self):
        """Test rejection when total extracted size exceeds 100MB."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as z:
            # Create multiple files that total > 100MB
            content = b"x" * (51 * 1024 * 1024)
            z.writestr("file1.bin", content)
            z.writestr("file2.bin", content)
        
        zip_buffer.seek(0)
        
        with pytest.raises(ZipExtractionError):
            extract_zip(zip_buffer.getvalue())
    
    def test_file_count_limit(self):
        """Test rejection when file count exceeds 1000."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as z:
            for i in range(1001):
                z.writestr(f"file_{i}.txt", "content")
        
        zip_buffer.seek(0)
        
        with pytest.raises(ZipExtractionError):
            extract_zip(zip_buffer.getvalue())
