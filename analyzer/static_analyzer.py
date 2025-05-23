#!/usr/bin/env python3
import os
import re
import pefile
import hashlib
import math
import logging
import zipfile
import tarfile
import tempfile
import shutil
from pathlib import Path
from collections import Counter

class ArchiveHandler:
    """Handler for compressed archive files (zip, tar, etc.)"""
    
    def __init__(self, file_path):
        """Initialize with the path to an archive file."""
        self.file_path = file_path
        self.temp_dir = None
        self.extracted_files = []
        self.archive_type = self._determine_archive_type()
    
    def _determine_archive_type(self):
        """Determine the type of archive based on file extension and signature."""
        file_ext = os.path.splitext(self.file_path)[1].lower()
        
        # Check by extension first
        if file_ext in ['.zip', '.jar', '.apk']:
            return 'zip'
        elif file_ext in ['.tar', '.gz', '.tgz', '.bz2', '.tbz2']:
            return 'tar'
        elif file_ext in ['.rar']:
            return 'rar'
        elif file_ext in ['.7z']:
            return '7z'
        
        # If extension doesn't match, try to check file signature
        try:
            with open(self.file_path, 'rb') as f:
                header = f.read(4)
                if header.startswith(b'PK\x03\x04'):
                    return 'zip'
                elif header.startswith(b'\x1f\x8b'):
                    return 'tar'  # gzip, likely a tar.gz
                # Add other signatures as needed
        except Exception as e:
            logging.error(f"Error reading file header: {e}")
        
        return None
    
    def extract(self):
        """Extract the archive to a temporary directory."""
        if not self.archive_type:
            logging.warning(f"Unable to determine archive type for {self.file_path}")
            return False
        
        try:
            # Create temporary directory
            self.temp_dir = tempfile.mkdtemp(prefix="maltriage_archive_")
            
            if self.archive_type == 'zip':
                self._extract_zip()
            elif self.archive_type == 'tar':
                self._extract_tar()
            # Add support for other archive types as needed
            
            # Get list of all extracted files
            for root, _, files in os.walk(self.temp_dir):
                for file in files:
                    self.extracted_files.append(os.path.join(root, file))
            
            logging.info(f"Extracted {len(self.extracted_files)} files from archive to {self.temp_dir}")
            return True
        except Exception as e:
            logging.error(f"Error extracting archive: {e}")
            self.cleanup()
            return False
    
    def _extract_zip(self):
        """Extract a ZIP archive."""
        with zipfile.ZipFile(self.file_path, 'r') as zip_ref:
            # Check for zip bombs - huge compression ratio
            total_size = sum(info.file_size for info in zip_ref.infolist())
            if total_size > 1_000_000_000:  # 1GB limit
                logging.warning(f"Archive too large (potential zip bomb): {total_size} bytes")
                raise ValueError("Archive extraction aborted: potential zip bomb detected")
            
            # Check for path traversal attacks
            for info in zip_ref.infolist():
                if '..' in info.filename or info.filename.startswith('/'):
                    logging.warning(f"Suspicious path in zip: {info.filename}")
                    continue
                
                # Safe extraction
                try:
                    zip_ref.extract(info, self.temp_dir)
                except Exception as e:
                    logging.error(f"Error extracting {info.filename}: {e}")
    
    def _extract_tar(self):
        """Extract a TAR archive (including compressed variants)."""
        mode = 'r'
        if self.file_path.endswith('.gz') or self.file_path.endswith('.tgz'):
            mode = 'r:gz'
        elif self.file_path.endswith('.bz2') or self.file_path.endswith('.tbz2'):
            mode = 'r:bz2'
        
        with tarfile.open(self.file_path, mode) as tar_ref:
            # Check for tar bombs
            total_size = sum(info.size for info in tar_ref.getmembers() if info.isfile())
            if total_size > 1_000_000_000:  # 1GB limit
                logging.warning(f"Archive too large (potential tar bomb): {total_size} bytes")
                raise ValueError("Archive extraction aborted: potential tar bomb detected")
            
            # Check for path traversal attacks
            for member in tar_ref.getmembers():
                if '..' in member.name or member.name.startswith('/'):
                    logging.warning(f"Suspicious path in tar: {member.name}")
                    continue
                
                # Safe extraction
                try:
                    tar_ref.extract(member, self.temp_dir)
                except Exception as e:
                    logging.error(f"Error extracting {member.name}: {e}")
    
    def cleanup(self):
        """Remove the temporary directory and extracted files."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
                logging.info(f"Cleaned up temporary directory: {self.temp_dir}")
                self.temp_dir = None
                self.extracted_files = []
            except Exception as e:
                logging.error(f"Error cleaning up temporary directory: {e}")


class StaticAnalyzer:
    def __init__(self, file_path):
        """Initialize the static analyzer with the file path."""
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)
        self.file_size = os.path.getsize(file_path)
        self.file_type = None
        self.md5 = None
        self.sha1 = None
        self.sha256 = None
        self.is_pe = False
        self.is_archive = False
        self.pe_data = None
        self.archive_data = None
        self.strings = None
        self.entropy = None
    
    def calculate_hashes(self):
        """Calculate MD5, SHA1, and SHA256 hashes of the file."""
        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()
                self.md5 = hashlib.md5(content).hexdigest()
                self.sha1 = hashlib.sha1(content).hexdigest()
                self.sha256 = hashlib.sha256(content).hexdigest()
            return {
                "md5": self.md5,
                "sha1": self.sha1,
                "sha256": self.sha256
            }
        except Exception as e:
            logging.error(f"Error calculating hashes: {e}")
            return None
    
    def extract_strings(self, min_length=4):
        """Extract printable strings from the file."""
        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()
                # Regular expression for printable ASCII characters
                pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
                self.strings = re.findall(pattern, content)
                return [s.decode('ascii', errors='ignore') for s in self.strings]
        except Exception as e:
            logging.error(f"Error extracting strings: {e}")
            return []
    
    def calculate_entropy(self):
        """Calculate Shannon entropy of the file."""
        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()
                if not content:
                    return 0.0
                
                byte_counts = Counter(content)
                file_size = len(content)
                
                entropy = 0
                for count in byte_counts.values():
                    probability = count / file_size
                    entropy -= probability * math.log2(probability)
                
                self.entropy = entropy
                return entropy
        except Exception as e:
            logging.error(f"Error calculating entropy: {e}")
            return None
    
    def analyze_pe(self):
        """Analyze PE file structure if the file is a PE file."""
        try:
            pe = pefile.PE(self.file_path)
            self.is_pe = True
            self.pe_data = {
                "machine_type": hex(pe.FILE_HEADER.Machine),
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "sections": [],
                "imports": {},
                "exports": [],
                "dlls": []
            }
            
            # Extract sections
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                self.pe_data["sections"].append({
                    "name": section_name,
                    "virtual_size": section.Misc_VirtualSize,
                    "virtual_address": section.VirtualAddress,
                    "size_of_raw_data": section.SizeOfRawData,
                    "entropy": section.get_entropy()
                })
            
            # Extract imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    self.pe_data["dlls"].append(dll_name)
                    self.pe_data["imports"][dll_name] = []
                    
                    for imp in entry.imports:
                        func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"ord_{imp.ordinal}"
                        self.pe_data["imports"][dll_name].append(func_name)
            
            # Extract exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        self.pe_data["exports"].append(exp.name.decode('utf-8', errors='ignore'))
            
            return self.pe_data
            
        except pefile.PEFormatError:
            self.is_pe = False
            return None
        except Exception as e:
            logging.error(f"Error analyzing PE file: {e}")
            return None
    
    def analyze(self):
        """Run all analysis methods and return the results."""
        results = {
            "file_info": {
                "name": self.file_name,
                "size": self.file_size,
                "path": self.file_path
            },
            "hashes": self.calculate_hashes(),
            "entropy": self.calculate_entropy(),
        }
        
        # Check if this is an archive file
        archive_handler = ArchiveHandler(self.file_path)
        if archive_handler.archive_type:
            self.is_archive = True
            results["file_type"] = f"archive-{archive_handler.archive_type}"
            
            # Archive-specific analysis
            archive_analysis = self._analyze_archive(archive_handler)
            if archive_analysis:
                results["archive_analysis"] = archive_analysis
        
        # Standard PE analysis
        try:
            pe_data = self.analyze_pe()
            if pe_data:
                results["pe_data"] = pe_data
                results["file_type"] = "PE"
            elif not self.is_archive:
                results["file_type"] = "non-PE"
        except Exception as e:
            results["pe_analysis_error"] = str(e)
        
        # Extract strings only if needed (can be expensive)
        strings = self.extract_strings()
        if strings:
            results["suspicious_strings"] = self._find_suspicious_strings(strings)
            results["urls"] = self._find_urls(strings)
            results["ips"] = self._find_ips(strings)
        
        return results
    
    def _analyze_archive(self, archive_handler):
        """Analyze the contents of an archive file."""
        if not archive_handler.extract():
            return {"error": "Failed to extract archive"}
        
        try:
            # Analyze each file in the archive
            archive_results = {
                "archive_type": archive_handler.archive_type,
                "num_files": len(archive_handler.extracted_files),
                "files": []
            }
            
            # Limit to a reasonable number of files to analyze
            max_files_to_analyze = 20
            files_to_analyze = archive_handler.extracted_files[:max_files_to_analyze]
            
            for extracted_file in files_to_analyze:
                file_size = os.path.getsize(extracted_file)
                file_name = os.path.basename(extracted_file)
                rel_path = os.path.relpath(extracted_file, archive_handler.temp_dir)
                
                # Calculate basic file info
                with open(extracted_file, 'rb') as f:
                    content = f.read()
                    file_md5 = hashlib.md5(content).hexdigest()
                
                # Determine file type by extension
                file_ext = os.path.splitext(extracted_file)[1].lower()
                
                archive_results["files"].append({
                    "name": file_name,
                    "path": rel_path,
                    "size": file_size,
                    "md5": file_md5,
                    "extension": file_ext
                })
            
            if len(archive_handler.extracted_files) > max_files_to_analyze:
                archive_results["note"] = f"Only analyzed {max_files_to_analyze} of {len(archive_handler.extracted_files)} files"
            
            return archive_results
        finally:
            # Clean up extracted files
            archive_handler.cleanup()
    
    def _find_suspicious_strings(self, strings):
        """Find potentially suspicious strings."""
        suspicious_keywords = [
            'execute', 'download', 'http://', 'https://', 'cmd.exe', 'powershell',
            'rundll32', 'shell', 'exploit', 'exec', 'system', 'admin', 'privilege',
            'registry', 'inject', 'payload', 'malware', 'virus', 'trojan', 'backdoor',
            'password', 'credential', 'encrypt', 'decrypt', 'ransom', 'bitcoin',
            'base64', 'hidden', 'shadow', 'hack', 'crack', 'keylog', 'screenshot'
        ]
        
        return [s for s in strings if any(keyword.lower() in s.lower() for keyword in suspicious_keywords)]
    
    def _find_urls(self, strings):
        """Extract URLs from strings."""
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        urls = []
        
        for s in strings:
            found_urls = re.findall(url_pattern, s)
            urls.extend(found_urls)
        
        return urls
    
    def _find_ips(self, strings):
        """Extract IP addresses from strings."""
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        ips = []
        
        for s in strings:
            found_ips = re.findall(ip_pattern, s)
            # Basic validation of IP format
            ips.extend([ip for ip in found_ips if all(0 <= int(octet) <= 255 for octet in ip.split('.'))])
        
        return ips

if __name__ == "__main__":
    # Simple test
    import sys
    if len(sys.argv) > 1:
        analyzer = StaticAnalyzer(sys.argv[1])
        results = analyzer.analyze()
        import json
        print(json.dumps(results, indent=4))
    else:
        print("Usage: python static_analyzer.py <file_path>")