#!/usr/bin/env python3
import os
import json
import re
import logging
import yara
from typing import Dict, List, Any, Union, Optional

class HeuristicAnalyzer:
    def __init__(self, signature_path: Optional[str] = None):
        """
        Initialize the heuristic analyzer.
        
        Args:
            signature_path: Path to signature file (JSON format or YARA rules)
        """
        self.signatures = {}
        self.yara_rules = None
        
        # Default signatures path if none provided
        if signature_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(current_dir)
            signature_path = os.path.join(parent_dir, "signatures", "known_signatures.json")
        
        self.signature_path = signature_path
        self._load_signatures()
    
    def _load_signatures(self) -> None:
        """Load signatures from the signature file."""
        try:
            if self.signature_path.endswith('.json'):
                with open(self.signature_path, 'r') as f:
                    self.signatures = json.load(f)
                logging.info(f"Loaded {len(self.signatures.get('hash_signatures', []))} hash signatures and "
                           f"{len(self.signatures.get('string_signatures', []))} string signatures")
            elif self.signature_path.endswith('.yar') or self.signature_path.endswith('.yara'):
                self.yara_rules = yara.compile(filepath=self.signature_path)
                logging.info(f"Loaded YARA rules from {self.signature_path}")
            else:
                logging.error(f"Unsupported signature file format: {self.signature_path}")
        except Exception as e:
            logging.error(f"Failed to load signatures: {e}")
    
    def check_hash_indicators(self, file_hashes: Dict[str, str]) -> List[Dict[str, str]]:
        """
        Check if file hashes match known malicious hashes.
        
        Args:
            file_hashes: Dictionary with md5, sha1, and sha256 hashes
            
        Returns:
            List of matched signatures
        """
        results = []
        
        if not self.signatures or 'hash_signatures' not in self.signatures:
            return results
        
        for hash_sig in self.signatures['hash_signatures']:
            for hash_type, hash_value in file_hashes.items():
                if hash_type in hash_sig and hash_sig[hash_type].lower() == hash_value.lower():
                    results.append({
                        'type': 'hash_match',
                        'hash_type': hash_type,
                        'signature': hash_sig
                    })
        
        return results
    
    def check_string_indicators(self, strings: List[str]) -> List[Dict[str, str]]:
        """
        Check if any strings match known malicious string patterns.
        
        Args:
            strings: List of strings extracted from the file
            
        Returns:
            List of matched signatures
        """
        results = []
        
        if not self.signatures or 'string_signatures' not in self.signatures:
            return results
        
        for string_sig in self.signatures['string_signatures']:
            pattern = string_sig['pattern']
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                for s in strings:
                    if regex.search(s):
                        results.append({
                            'type': 'string_match',
                            'string': s,
                            'signature': string_sig
                        })
            except re.error as e:
                logging.error(f"Invalid regex pattern '{pattern}': {e}")
        
        return results
    
    def check_yara_rules(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Check if the file matches any YARA rules.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            List of matched YARA rules
        """
        results = []
        
        if not self.yara_rules:
            return results
        
        try:
            matches = self.yara_rules.match(file_path)
            for match in matches:
                results.append({
                    'type': 'yara_match',
                    'rule_name': match.rule,
                    'tags': match.tags,
                    'meta': match.meta
                })
        except Exception as e:
            logging.error(f"Error checking YARA rules: {e}")
        
        return results
    
    def check_pe_anomalies(self, pe_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check for anomalies in PE file structure.
        
        Args:
            pe_data: Dictionary containing PE file analysis data
            
        Returns:
            List of detected anomalies
        """
        results = []
        
        if not pe_data:
            return results
        
        # Check for high entropy sections (potential packing/encryption)
        if 'sections' in pe_data:
            for section in pe_data['sections']:
                if section.get('entropy', 0) > 7.0:
                    results.append({
                        'type': 'high_entropy_section',
                        'section_name': section.get('name', 'Unknown'),
                        'entropy': section.get('entropy', 0),
                        'description': 'Section has high entropy, possibly packed or encrypted'
                    })
        
        # Check for suspicious imports
        suspicious_dlls = ['wininet.dll', 'urlmon.dll', 'wsock32.dll', 'ws2_32.dll', 'advapi32.dll']
        suspicious_apis = ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory', 'ShellExecute', 'WinExec']
        
        if 'imports' in pe_data:
            for dll, imports in pe_data['imports'].items():
                if dll.lower() in [d.lower() for d in suspicious_dlls]:
                    results.append({
                        'type': 'suspicious_import_dll',
                        'dll': dll,
                        'description': f'Potentially suspicious DLL import: {dll}'
                    })
                
                for api in imports:
                    if any(sus_api.lower() in api.lower() for sus_api in suspicious_apis):
                        results.append({
                            'type': 'suspicious_import_api',
                            'dll': dll,
                            'api': api,
                            'description': f'Potentially suspicious API import: {dll}:{api}'
                        })
        
        return results
    
    def analyze(self, file_path: str, static_analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform heuristic analysis on a file using various indicators.
        
        Args:
            file_path: Path to the file to analyze
            static_analysis_results: Results from static analysis
            
        Returns:
            Dictionary with analysis results
        """
        results = {
            'hash_matches': [],
            'string_matches': [],
            'yara_matches': [],
            'pe_anomalies': [],
            'verdict': 'unknown',
            'score': 0
        }
        
        # Check file hashes
        if 'hashes' in static_analysis_results:
            results['hash_matches'] = self.check_hash_indicators(static_analysis_results['hashes'])
        
        # Check strings
        strings = []
        if 'suspicious_strings' in static_analysis_results:
            strings = static_analysis_results['suspicious_strings']
        results['string_matches'] = self.check_string_indicators(strings)
        
        # Check YARA rules
        results['yara_matches'] = self.check_yara_rules(file_path)
        
        # Check PE anomalies if it's a PE file
        if 'pe_data' in static_analysis_results:
            results['pe_anomalies'] = self.check_pe_anomalies(static_analysis_results['pe_data'])
        
        # Calculate a simple risk score
        score = 0
        score += len(results['hash_matches']) * 100  # Definite match
        score += len(results['yara_matches']) * 75   # Strong indicator
        score += len(results['string_matches']) * 20 # Moderate indicator
        score += len(results['pe_anomalies']) * 15   # Weak indicator
        
        # Set verdict based on score
        if score >= 100:
            verdict = "malicious"
        elif score >= 50:
            verdict = "suspicious"
        elif score >= 20:
            verdict = "potentially unwanted"
        else:
            verdict = "likely benign"
        
        results['score'] = score
        results['verdict'] = verdict
        
        return results

def create_default_signature_file(signature_path):
    """Create a default signature file if one doesn't exist."""
    if os.path.exists(signature_path):
        return
    
    default_signatures = {
        "hash_signatures": [
            {
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "description": "Example malicious file (this is just a placeholder)",
                "threat_name": "Example.Malware"
            }
        ],
        "string_signatures": [
            {
                "pattern": "(?i)this is (malware|a virus)",
                "description": "Example string pattern",
                "threat_name": "Example.StringMatch"
            },
            {
                "pattern": "(?i)botnet command and control",
                "description": "C2 communication indicator",
                "threat_name": "Generic.Botnet"
            }
        ]
    }
    
    os.makedirs(os.path.dirname(signature_path), exist_ok=True)
    
    with open(signature_path, 'w') as f:
        json.dump(default_signatures, f, indent=4)
    
    logging.info(f"Created default signature file at {signature_path}")

def create_default_yara_file(yara_path):
    """Create a default YARA rule file if one doesn't exist."""
    if os.path.exists(yara_path):
        return
    
    default_yara = """
rule example_malware {
    meta:
        description = "Example YARA rule for demonstration"
        author = "maltriage"
        severity = "high"
    strings:
        $s1 = "This is an example malicious string" nocase
        $s2 = "virus" nocase
        $s3 = "malware" nocase
        $hex1 = { 4D 5A 90 00 03 00 00 00 } // Example MZ header pattern
    condition:
        uint16(0) == 0x5A4D and // MZ header check
        ($s1 or (2 of ($s2, $s3, $hex1)))
}
    """
    
    os.makedirs(os.path.dirname(yara_path), exist_ok=True)
    
    with open(yara_path, 'w') as f:
        f.write(default_yara)
    
    logging.info(f"Created default YARA rule file at {yara_path}")

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    
    # Create default signature files if they don't exist
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    default_sig_path = os.path.join(parent_dir, "signatures", "known_signatures.json")
    default_yara_path = os.path.join(parent_dir, "signatures", "rules.yar")
    
    create_default_signature_file(default_sig_path)
    create_default_yara_file(default_yara_path)
    
    if len(sys.argv) > 1:
        # For testing, we need some static analysis results
        # In a real scenario, these would come from the StaticAnalyzer
        mock_static_results = {
            "hashes": {
                "md5": "d41d8cd98f00b204e9800998ecf8427e",  # This is just the MD5 of an empty file
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
            "suspicious_strings": ["This is an example malicious string", "botnet command and control"],
            "pe_data": {
                "sections": [
                    {"name": ".text", "entropy": 6.2},
                    {"name": ".data", "entropy": 7.8}  # High entropy section
                ],
                "imports": {
                    "kernel32.dll": ["CreateProcessA", "ReadFile", "WriteFile"],
                    "wininet.dll": ["InternetOpenA", "InternetConnectA"],
                    "advapi32.dll": ["RegOpenKeyExA", "RegSetValueExA"]
                }
            }
        }
        
        analyzer = HeuristicAnalyzer()
        results = analyzer.analyze(sys.argv[1], mock_static_results)
        print(json.dumps(results, indent=4))
    else:
        print("Usage: python heuristics.py <file_path>")