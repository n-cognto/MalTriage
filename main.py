#!/usr/bin/env python3
import os
import sys
import json
import time
import logging
import argparse
from datetime import datetime
from pathlib import Path
import matplotlib.pyplot as plt
import pandas as pd
from tqdm import tqdm

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from analyzer.static_analyzer import StaticAnalyzer, ArchiveHandler
from analyzer.dynamic_analyzer import DynamicAnalyzer, CuckooIntegration
from analyzer.heuristics import HeuristicAnalyzer, create_default_signature_file, create_default_yara_file
from analyzer.ml_detector import MalwareDetector, create_default_model_file

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('maltriage.log')
    ]
)

logger = logging.getLogger('maltriage')

class MalTriage:
    """Main class for the maltriage tool."""
    
    def __init__(self):
        """Initialize the maltriage tool."""
        self.project_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Ensure directories exist
        self._ensure_directories()
        
        # Initialize default files if they don't exist
        self._initialize_default_files()
        
        # Initialize analyzers
        self.static_analyzer = None
        self.dynamic_analyzer = None
        self.heuristic_analyzer = HeuristicAnalyzer()
        self.ml_detector = MalwareDetector()
        
        self.current_file = None
        self.analysis_results = {}
    
    def _ensure_directories(self):
        """Ensure that the required directories exist."""
        for dir_path in ['samples', 'signatures', 'model', 'reports']:
            full_path = os.path.join(self.project_dir, dir_path)
            os.makedirs(full_path, exist_ok=True)
            logger.info(f"Ensured directory exists: {full_path}")
    
    def _initialize_default_files(self):
        """Initialize default files if they don't exist."""
        # Default signature file
        sig_path = os.path.join(self.project_dir, "signatures", "known_signatures.json")
        create_default_signature_file(sig_path)
        
        # Default YARA rules
        yara_path = os.path.join(self.project_dir, "signatures", "rules.yar")
        create_default_yara_file(yara_path)
        
        # Default ML model
        model_path = os.path.join(self.project_dir, "model", "malware_model.pkl")
        create_default_model_file(model_path)
    
    def analyze_file(self, file_path, dynamic=True, timeout=60, sandbox="safe", recursive=False):
        """
        Analyze a single file.
        
        Args:
            file_path: Path to the file to analyze
            dynamic: Whether to perform dynamic analysis
            timeout: Timeout for dynamic analysis in seconds
            sandbox: Sandbox type for dynamic analysis ("safe" or "vm")
            recursive: Whether to recursively analyze archive contents
        
        Returns:
            Dictionary containing the analysis results
        """
        if not os.path.exists(file_path):
            logger.error(f"File does not exist: {file_path}")
            return {"error": "File does not exist"}
        
        file_path = os.path.abspath(file_path)
        self.current_file = file_path
        self.analysis_results = {
            "file": file_path,
            "analysis_time": datetime.now().isoformat(),
            "static_analysis": None,
            "dynamic_analysis": None,
            "heuristic_analysis": None,
            "ml_analysis": None,
            "overall_verdict": None,
            "child_analyses": []
        }
        
        logger.info(f"Analyzing file: {file_path}")
        
        # Static analysis
        try:
            logger.info("Performing static analysis...")
            self.static_analyzer = StaticAnalyzer(file_path)
            static_results = self.static_analyzer.analyze()
            self.analysis_results["static_analysis"] = static_results
            logger.info("Static analysis completed")
            
            # Check if this is an archive and recursive analysis is requested
            if recursive and static_results.get("file_type", "").startswith("archive-"):
                logger.info("Archive detected, performing recursive analysis...")
                if "archive_analysis" in static_results and "files" in static_results["archive_analysis"]:
                    archive_files = static_results["archive_analysis"]["files"]
                    
                    # Extract archive to temporary directory
                    archive_handler = ArchiveHandler(file_path)
                    if archive_handler.extract():
                        try:
                            # Analyze each extracted file with a size limit
                            max_file_size = 50 * 1024 * 1024  # 50MB limit for extracted files
                            for archive_file_info in archive_files:
                                extracted_path = os.path.join(archive_handler.temp_dir, archive_file_info["path"])
                                
                                if os.path.exists(extracted_path) and os.path.getsize(extracted_path) <= max_file_size:
                                    logger.info(f"Recursively analyzing extracted file: {archive_file_info['path']}")
                                    
                                    # Don't do dynamic analysis on extracted files by default (safer)
                                    child_analysis = self.analyze_file(
                                        extracted_path, 
                                        dynamic=False,
                                        timeout=timeout,
                                        sandbox=sandbox,
                                        recursive=False  # Prevent infinite recursion
                                    )
                                    
                                    # Add to child analyses with context
                                    self.analysis_results["child_analyses"].append({
                                        "path_in_archive": archive_file_info["path"],
                                        "analysis": child_analysis
                                    })
                            
                            logger.info(f"Completed recursive analysis of {len(self.analysis_results['child_analyses'])} files")
                        finally:
                            # Clean up extracted files
                            archive_handler.cleanup()
                
        except Exception as e:
            logger.error(f"Error in static analysis: {e}")
            self.analysis_results["static_analysis"] = {"error": str(e)}
        
        # Dynamic analysis (optional)
        if dynamic:
            try:
                logger.info("Performing dynamic analysis...")
                self.dynamic_analyzer = DynamicAnalyzer(file_path, timeout=timeout, sandbox_mode=sandbox)
                dynamic_results = self.dynamic_analyzer.analyze()
                self.analysis_results["dynamic_analysis"] = dynamic_results
                logger.info("Dynamic analysis completed")
            except Exception as e:
                logger.error(f"Error in dynamic analysis: {e}")
                self.analysis_results["dynamic_analysis"] = {"error": str(e)}
        
        # Heuristic analysis
        try:
            logger.info("Performing heuristic analysis...")
            heuristic_results = self.heuristic_analyzer.analyze(
                file_path,
                self.analysis_results["static_analysis"]
            )
            self.analysis_results["heuristic_analysis"] = heuristic_results
            logger.info("Heuristic analysis completed")
        except Exception as e:
            logger.error(f"Error in heuristic analysis: {e}")
            self.analysis_results["heuristic_analysis"] = {"error": str(e)}
        
        # ML analysis
        try:
            logger.info("Performing ML analysis...")
            ml_results = self.ml_detector.predict(
                self.analysis_results["static_analysis"],
                self.analysis_results.get("dynamic_analysis", {})
            )
            self.analysis_results["ml_analysis"] = ml_results
            logger.info("ML analysis completed")
        except Exception as e:
            logger.error(f"Error in ML analysis: {e}")
            self.analysis_results["ml_analysis"] = {"error": str(e)}
        
        # Overall verdict
        self._determine_overall_verdict()
        
        logger.info(f"Analysis completed for: {file_path}")
        return self.analysis_results
    
    def _determine_overall_verdict(self):
        """Determine the overall verdict based on all analysis methods."""
        verdicts = []
        
        # Heuristic verdict
        if self.analysis_results.get("heuristic_analysis") and "verdict" in self.analysis_results["heuristic_analysis"]:
            verdict = self.analysis_results["heuristic_analysis"]["verdict"]
            score = self.analysis_results["heuristic_analysis"].get("score", 0)
            verdicts.append((verdict, score))
        
        # ML verdict
        if self.analysis_results.get("ml_analysis") and "prediction" in self.analysis_results["ml_analysis"]:
            verdict = self.analysis_results["ml_analysis"]["prediction"]
            score = self.analysis_results["ml_analysis"].get("probability", 0) * 100  # Convert to scale of 0-100
            verdicts.append((verdict, score))
        
        # Map verdicts to numeric scores for weighting
        verdict_scores = {
            "malicious": 100,
            "suspicious": 70,
            "potentially unwanted": 40,
            "likely benign": 10,
            "benign": 0,
            "unknown": 50  # Default middle score
        }
        
        # Calculate weighted verdict
        total_score = 0
        total_weight = 0
        
        for verdict, confidence in verdicts:
            if verdict in verdict_scores:
                weight = confidence
                total_score += verdict_scores[verdict] * weight
                total_weight += weight
        
        if total_weight > 0:
            final_score = total_score / total_weight
        else:
            final_score = 50  # Default to middle if no weights
        
        # Map back to verdict labels
        if final_score >= 80:
            overall_verdict = "malicious"
        elif final_score >= 50:
            overall_verdict = "suspicious"
        elif final_score >= 30:
            overall_verdict = "potentially unwanted"
        else:
            overall_verdict = "benign"
        
        self.analysis_results["overall_verdict"] = {
            "verdict": overall_verdict,
            "confidence_score": final_score,
            "component_verdicts": verdicts
        }
    
    def save_report(self, output_format="json"):
        """
        Save the analysis report to a file.
        
        Args:
            output_format: Format to save the report in ("json" or "txt")
            
        Returns:
            Path to the saved report file
        """
        if not self.analysis_results:
            logger.error("No analysis results to save")
            return None
        
        # Create report directory if it doesn't exist
        reports_dir = os.path.join(self.project_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        # Generate report filename
        file_name = os.path.basename(self.current_file)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(reports_dir, f"{file_name}_report_{timestamp}.{output_format}")
        
        try:
            if output_format == "json":
                with open(report_file, 'w') as f:
                    json.dump(self.analysis_results, f, indent=4)
            elif output_format == "txt":
                with open(report_file, 'w') as f:
                    f.write(f"MALTRIAGE REPORT\n")
                    f.write(f"==============\n\n")
                    f.write(f"File: {self.current_file}\n")
                    f.write(f"Analysis Time: {self.analysis_results['analysis_time']}\n")
                    f.write(f"Overall Verdict: {self.analysis_results['overall_verdict']['verdict']} "
                            f"(Confidence: {self.analysis_results['overall_verdict']['confidence_score']:.2f}%)\n\n")
                    
                    # Include key findings
                    f.write("KEY FINDINGS\n")
                    f.write("------------\n")
                    
                    # Hash match findings
                    if self.analysis_results.get("heuristic_analysis", {}).get("hash_matches"):
                        f.write("Hash Matches:\n")
                        for match in self.analysis_results["heuristic_analysis"]["hash_matches"]:
                            f.write(f"  - {match['hash_type']}: {match['signature'].get('description', 'Unknown')}\n")
                    
                    # YARA matches
                    if self.analysis_results.get("heuristic_analysis", {}).get("yara_matches"):
                        f.write("YARA Matches:\n")
                        for match in self.analysis_results["heuristic_analysis"]["yara_matches"]:
                            f.write(f"  - {match['rule_name']}: {match.get('meta', {}).get('description', 'No description')}\n")
                    
                    # Suspicious strings
                    if self.analysis_results.get("static_analysis", {}).get("suspicious_strings"):
                        f.write("Suspicious Strings (sample):\n")
                        for i, s in enumerate(self.analysis_results["static_analysis"]["suspicious_strings"][:5]):
                            f.write(f"  - {s}\n")
                        if len(self.analysis_results["static_analysis"]["suspicious_strings"]) > 5:
                            f.write(f"  - ... ({len(self.analysis_results['static_analysis']['suspicious_strings']) - 5} more)\n")
                    
                    # Network activity
                    if self.analysis_results.get("dynamic_analysis", {}).get("network_activity"):
                        f.write("Network Activity:\n")
                        for i, conn in enumerate(self.analysis_results["dynamic_analysis"]["network_activity"][:5]):
                            f.write(f"  - {conn.get('remote_ip', 'Unknown')}:{conn.get('remote_port', 'Unknown')}\n")
                        if len(self.analysis_results["dynamic_analysis"]["network_activity"]) > 5:
                            f.write(f"  - ... ({len(self.analysis_results['dynamic_analysis']['network_activity']) - 5} more)\n")
                    
                    # Include more detailed sections
                    for section in ["static_analysis", "dynamic_analysis", "heuristic_analysis", "ml_analysis"]:
                        if section in self.analysis_results and self.analysis_results[section]:
                            f.write(f"\n{section.upper().replace('_', ' ')}\n")
                            f.write("=" * len(section.upper().replace('_', ' ')) + "\n")
                            # Write a reasonable summary of each section
                            if section == "static_analysis":
                                self._write_static_summary(f)
                            elif section == "dynamic_analysis":
                                self._write_dynamic_summary(f)
                            elif section == "heuristic_analysis":
                                self._write_heuristic_summary(f)
                            elif section == "ml_analysis":
                                self._write_ml_summary(f)
            else:
                logger.error(f"Unsupported output format: {output_format}")
                return None
            
            logger.info(f"Saved report to {report_file}")
            return report_file
        
        except Exception as e:
            logger.error(f"Error saving report: {e}")
            return None
    
    def _write_static_summary(self, file):
        """Write a summary of static analysis results to the report file."""
        sa = self.analysis_results["static_analysis"]
        file.write(f"File Information:\n")
        file.write(f"  - Name: {sa.get('file_info', {}).get('name', 'Unknown')}\n")
        file.write(f"  - Size: {sa.get('file_info', {}).get('size', 'Unknown')} bytes\n")
        file.write(f"  - Type: {sa.get('file_type', 'Unknown')}\n")
        
        if "hashes" in sa and sa["hashes"]:
            file.write(f"Hashes:\n")
            for hash_type, hash_val in sa["hashes"].items():
                file.write(f"  - {hash_type}: {hash_val}\n")
        
        if "entropy" in sa:
            file.write(f"Entropy: {sa['entropy']:.2f}\n")
        
        if "pe_data" in sa:
            file.write(f"PE Information:\n")
            sections = sa["pe_data"].get("sections", [])
            file.write(f"  - Number of sections: {len(sections)}\n")
            
            # List sections with high entropy
            high_entropy_sections = [s for s in sections if s.get("entropy", 0) > 7.0]
            if high_entropy_sections:
                file.write(f"  - High entropy sections ({len(high_entropy_sections)}):\n")
                for s in high_entropy_sections:
                    file.write(f"    - {s['name']}: {s.get('entropy', 0):.2f}\n")
            
            # List DLLs
            dlls = sa["pe_data"].get("dlls", [])
            if dlls:
                file.write(f"  - Imported DLLs ({len(dlls)}):\n")
                for dll in dlls[:5]:
                    file.write(f"    - {dll}\n")
                if len(dlls) > 5:
                    file.write(f"    - ... ({len(dlls) - 5} more)\n")
    
    def _write_dynamic_summary(self, file):
        """Write a summary of dynamic analysis results to the report file."""
        da = self.analysis_results["dynamic_analysis"]
        
        # Execution information
        if "execution" in da:
            file.write(f"Execution:\n")
            file.write(f"  - Duration: {da['execution'].get('duration', 'Unknown')} seconds\n")
            file.write(f"  - Return code: {da['execution'].get('return_code', 'Unknown')}\n")
        
        # Network activity
        network = da.get("network_activity", [])
        if network:
            file.write(f"Network Activity ({len(network)}):\n")
            for conn in network[:5]:
                file.write(f"  - {conn.get('local_ip', 'Unknown')}:{conn.get('local_port', 'Unknown')} -> "
                          f"{conn.get('remote_ip', 'Unknown')}:{conn.get('remote_port', 'Unknown')}\n")
            if len(network) > 5:
                file.write(f"  - ... ({len(network) - 5} more connections)\n")
        
        # Process activity
        processes = da.get("process_activity", [])
        if processes:
            file.write(f"Process Activity ({len(processes)}):\n")
            for proc in processes[:5]:
                file.write(f"  - {proc.get('name', 'Unknown')} (PID: {proc.get('pid', 'Unknown')})\n")
            if len(processes) > 5:
                file.write(f"  - ... ({len(processes) - 5} more)\n")
    
    def _write_heuristic_summary(self, file):
        """Write a summary of heuristic analysis results to the report file."""
        ha = self.analysis_results["heuristic_analysis"]
        
        file.write(f"Verdict: {ha.get('verdict', 'Unknown')}\n")
        file.write(f"Score: {ha.get('score', 0)}\n")
        
        # Hash matches
        hash_matches = ha.get("hash_matches", [])
        if hash_matches:
            file.write(f"Hash Matches ({len(hash_matches)}):\n")
            for match in hash_matches:
                file.write(f"  - {match['hash_type']}: {match['signature'].get('description', 'Unknown')}\n")
        
        # String matches
        string_matches = ha.get("string_matches", [])
        if string_matches:
            file.write(f"String Matches ({len(string_matches)}):\n")
            for match in string_matches[:5]:
                file.write(f"  - {match['string']}: {match['signature'].get('description', 'Unknown')}\n")
            if len(string_matches) > 5:
                file.write(f"  - ... ({len(string_matches) - 5} more)\n")
        
        # YARA matches
        yara_matches = ha.get("yara_matches", [])
        if yara_matches:
            file.write(f"YARA Matches ({len(yara_matches)}):\n")
            for match in yara_matches:
                file.write(f"  - {match['rule_name']}: {match.get('meta', {}).get('description', 'No description')}\n")
        
        # PE anomalies
        pe_anomalies = ha.get("pe_anomalies", [])
        if pe_anomalies:
            file.write(f"PE Anomalies ({len(pe_anomalies)}):\n")
            for anomaly in pe_anomalies:
                file.write(f"  - {anomaly['type']}: {anomaly['description']}\n")
    
    def _write_ml_summary(self, file):
        """Write a summary of ML analysis results to the report file."""
        ml = self.analysis_results["ml_analysis"]
        
        file.write(f"Prediction: {ml.get('prediction', 'Unknown')}\n")
        file.write(f"Probability: {ml.get('probability', 0) * 100:.2f}%\n")
        
        features = ml.get("features_used", [])
        if features:
            file.write(f"Features Used ({len(features)}):\n")
            for feature in features[:10]:
                file.write(f"  - {feature}\n")
            if len(features) > 10:
                file.write(f"  - ... ({len(features) - 10} more)\n")
    
    def batch_analyze(self, directory, output_dir=None, dynamic=True, timeout=60, sandbox="safe"):
        """
        Analyze all files in a directory and generate reports.
        
        Args:
            directory: Directory containing files to analyze
            output_dir: Directory to save reports (defaults to project reports dir)
            dynamic: Whether to perform dynamic analysis
            timeout: Timeout for dynamic analysis in seconds
            sandbox: Sandbox type for dynamic analysis ("safe" or "vm")
        
        Returns:
            List of analysis results
        """
        if not os.path.isdir(directory):
            logger.error(f"Not a directory: {directory}")
            return []
        
        if not output_dir:
            output_dir = os.path.join(self.project_dir, "reports")
        
        os.makedirs(output_dir, exist_ok=True)
        
        results = []
        files = list(Path(directory).rglob("*"))
        files = [f for f in files if f.is_file()]
        
        logger.info(f"Found {len(files)} files to analyze in {directory}")
        
        for file_path in tqdm(files, desc="Analyzing files"):
            file_result = self.analyze_file(str(file_path), dynamic, timeout, sandbox)
            results.append(file_result)
            
            # Save individual report
            report_path = self.save_report(output_format="json")
            logger.info(f"Saved report for {file_path} to {report_path}")
        
        # Generate summary report
        self._generate_batch_summary(results, output_dir)
        
        return results
    
    def _generate_batch_summary(self, results, output_dir):
        """Generate a summary report for batch analysis."""
        if not results:
            return
        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        summary_file = os.path.join(output_dir, f"batch_summary_{timestamp}.json")
        
        summary = {
            "batch_time": datetime.now().isoformat(),
            "total_files": len(results),
            "verdicts": {
                "malicious": 0,
                "suspicious": 0,
                "potentially unwanted": 0,
                "benign": 0,
                "unknown": 0
            },
            "avg_score": 0.0,
            "files": []
        }
        
        total_score = 0
        
        for result in results:
            if "overall_verdict" in result and result["overall_verdict"]:
                verdict = result["overall_verdict"]["verdict"]
                score = result["overall_verdict"].get("confidence_score", 0)
                
                summary["verdicts"][verdict] = summary["verdicts"].get(verdict, 0) + 1
                total_score += score
                
                summary["files"].append({
                    "file": result.get("file", "Unknown"),
                    "verdict": verdict,
                    "score": score
                })
            else:
                summary["verdicts"]["unknown"] = summary["verdicts"].get("unknown", 0) + 1
        
        if results:
            summary["avg_score"] = total_score / len(results)
        
        # Save summary report
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=4)
        
        logger.info(f"Generated batch summary report at {summary_file}")
        
        # Generate visualizations
        self._generate_batch_visualizations(summary, output_dir)
    
    def _generate_batch_visualizations(self, summary, output_dir):
        """Generate visualizations for batch analysis results."""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        viz_file = os.path.join(output_dir, f"batch_viz_{timestamp}.png")
        
        try:
            # Create a figure with subplots
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 7))
            
            # Plot verdict distribution
            verdicts = summary["verdicts"]
            labels = list(verdicts.keys())
            sizes = list(verdicts.values())
            colors = ['red', 'orange', 'yellow', 'green', 'gray']
            
            ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
            ax1.axis('equal')
            ax1.set_title('File Verdict Distribution')
            
            # Plot score distribution
            scores = [f["score"] for f in summary["files"] if "score" in f]
            
            ax2.hist(scores, bins=10, color='blue', alpha=0.7)
            ax2.set_xlabel('Maliciousness Score')
            ax2.set_ylabel('Number of Files')
            ax2.set_title('Score Distribution')
            
            # Save the figure
            plt.tight_layout()
            plt.savefig(viz_file)
            plt.close()
            
            logger.info(f"Generated batch visualization at {viz_file}")
        except Exception as e:
            logger.error(f"Error generating visualizations: {e}")

def main():
    """Main function for the command-line interface."""
    parser = argparse.ArgumentParser(description="MalTriage - A basic file triaging tool")
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Single file analysis command
    file_parser = subparsers.add_parser('analyze', help='Analyze a single file')
    file_parser.add_argument('file_path', help='Path to the file to analyze')
    file_parser.add_argument('--no-dynamic', dest='dynamic', action='store_false', 
                            help='Disable dynamic analysis')
    file_parser.add_argument('--timeout', type=int, default=60, 
                            help='Timeout for dynamic analysis in seconds')
    file_parser.add_argument('--sandbox', choices=['safe', 'vm'], default='safe',
                            help='Sandbox type for dynamic analysis')
    file_parser.add_argument('--output', choices=['json', 'txt'], default='json',
                            help='Output format for the report')
    file_parser.add_argument('--recursive', action='store_true',
                            help='Recursively analyze archive contents')
    
    # Batch analysis command
    batch_parser = subparsers.add_parser('batch', help='Analyze multiple files in a directory')
    batch_parser.add_argument('directory', help='Directory containing files to analyze')
    batch_parser.add_argument('--output-dir', help='Directory to save reports')
    batch_parser.add_argument('--no-dynamic', dest='dynamic', action='store_false',
                             help='Disable dynamic analysis')
    batch_parser.add_argument('--timeout', type=int, default=30,
                             help='Timeout for dynamic analysis in seconds')
    batch_parser.add_argument('--sandbox', choices=['safe', 'vm'], default='safe',
                             help='Sandbox type for dynamic analysis')
    
    args = parser.parse_args()
    
    # Create maltriage instance
    maltriage = MalTriage()
    
    try:
        if args.command == 'analyze':
            # Analyze a single file
            logger.info(f"Analyzing file: {args.file_path}")
            maltriage.analyze_file(args.file_path, args.dynamic, args.timeout, args.sandbox, args.recursive)
            report_path = maltriage.save_report(args.output)
            
            if report_path:
                print(f"\nAnalysis complete! Report saved to: {report_path}")
                
                # Print a brief summary to the console
                verdict = maltriage.analysis_results["overall_verdict"]["verdict"]
                confidence = maltriage.analysis_results["overall_verdict"]["confidence_score"]
                print(f"\nSUMMARY:")
                print(f"Verdict: {verdict.upper()} (Confidence: {confidence:.2f}%)")
                
                # Print key findings
                if maltriage.analysis_results["heuristic_analysis"]["hash_matches"]:
                    print(f"Hash matches found: {len(maltriage.analysis_results['heuristic_analysis']['hash_matches'])}")
                
                if maltriage.analysis_results["heuristic_analysis"]["yara_matches"]:
                    print(f"YARA rule matches found: {len(maltriage.analysis_results['heuristic_analysis']['yara_matches'])}")
                
                if maltriage.analysis_results.get("static_analysis", {}).get("suspicious_strings"):
                    print(f"Suspicious strings found: {len(maltriage.analysis_results['static_analysis']['suspicious_strings'])}")
                
                if maltriage.analysis_results.get("dynamic_analysis", {}).get("network_activity"):
                    print(f"Network connections detected: {len(maltriage.analysis_results['dynamic_analysis']['network_activity'])}")
            
        elif args.command == 'batch':
            # Analyze multiple files
            logger.info(f"Batch analyzing files in: {args.directory}")
            results = maltriage.batch_analyze(
                args.directory,
                args.output_dir,
                args.dynamic,
                args.timeout,
                args.sandbox
            )
            
            print(f"\nBatch analysis complete! Analyzed {len(results)} files.")
            print(f"Reports saved to: {args.output_dir or os.path.join(maltriage.project_dir, 'reports')}")
            
            # Print a brief summary
            malicious_count = sum(1 for r in results if r.get("overall_verdict", {}).get("verdict") == "malicious")
            suspicious_count = sum(1 for r in results if r.get("overall_verdict", {}).get("verdict") == "suspicious")
            print(f"\nSUMMARY:")
            print(f"Malicious files: {malicious_count}")
            print(f"Suspicious files: {suspicious_count}")
            print(f"Total files: {len(results)}")
        
        else:
            parser.print_help()
    
    except Exception as e:
        logger.error(f"Error: {e}")
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()