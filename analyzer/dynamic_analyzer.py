#!/usr/bin/env python3
import os
import tempfile
import subprocess
import json
import time
import logging
import psutil
import socket
from datetime import datetime

class DynamicAnalyzer:
    def __init__(self, file_path, timeout=60, sandbox_mode="safe"):
        """
        Initialize the dynamic analyzer.
        
        Args:
            file_path: Path to the file to analyze
            timeout: Maximum execution time in seconds
            sandbox_mode: Either 'safe' (subprocess only) or 'vm' (requires VM setup)
        """
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)
        self.timeout = timeout
        self.sandbox_mode = sandbox_mode
        self.result_dir = tempfile.mkdtemp(prefix="maltriage_")
        self.process = None
        self.start_time = None
        self.end_time = None
        self.network_connections = []
        self.file_operations = []
        self.registry_operations = []
        self.process_operations = []
    
    def _safe_execute(self):
        """
        Execute the file in a controlled subprocess environment.
        WARNING: This is NOT truly safe for malware analysis. Use only with known safe files or in isolated environments.
        """
        logging.info(f"Starting safe execution of {self.file_path}")
        self.start_time = datetime.now()
        
        try:
            # Capture process information before execution
            before_processes = set(p.pid for p in psutil.process_iter())
            before_connections = set((c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port) 
                                    for c in psutil.net_connections() if c.raddr and c.raddr.ip)
            
            # Start the process
            self.process = subprocess.Popen(
                [self.file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False  # Never use shell=True with untrusted input
            )
            
            # Monitor the process for the timeout period
            start_monitoring = time.time()
            while time.time() - start_monitoring < self.timeout:
                if self.process.poll() is not None:
                    # Process has terminated
                    break
                
                # Monitor network connections
                current_connections = set((c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port) 
                                       for c in psutil.net_connections() if c.raddr and c.raddr.ip)
                new_connections = current_connections - before_connections
                for conn in new_connections:
                    self.network_connections.append({
                        "local_ip": conn[0],
                        "local_port": conn[1],
                        "remote_ip": conn[2],
                        "remote_port": conn[3],
                        "timestamp": time.time() - start_monitoring
                    })
                    before_connections.add(conn)
                
                # Monitor new processes
                current_processes = set(p.pid for p in psutil.process_iter())
                new_processes = current_processes - before_processes
                for pid in new_processes:
                    try:
                        p = psutil.Process(pid)
                        self.process_operations.append({
                            "pid": pid,
                            "name": p.name(),
                            "cmdline": p.cmdline(),
                            "timestamp": time.time() - start_monitoring
                        })
                        before_processes.add(pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                time.sleep(0.5)  # Prevent high CPU usage
            
            # Kill the process if it's still running after timeout
            if self.process.poll() is None:
                logging.warning(f"Process timed out after {self.timeout} seconds. Terminating.")
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
            
            stdout, stderr = self.process.communicate()
            
            self.end_time = datetime.now()
            
            return {
                "stdout": stdout.decode('utf-8', errors='ignore'),
                "stderr": stderr.decode('utf-8', errors='ignore'),
                "return_code": self.process.returncode
            }
            
        except Exception as e:
            logging.error(f"Error during dynamic analysis: {e}")
            return {"error": str(e)}
    
    def _vm_execute(self):
        """
        Execute the file in a virtual machine environment.
        This is a placeholder for integration with tools like Cuckoo Sandbox.
        """
        logging.warning("VM execution mode is not implemented yet. Falling back to safe mode.")
        return self._safe_execute()
    
    def analyze(self):
        """Run the dynamic analysis and return the results."""
        if not os.path.exists(self.file_path):
            return {"error": "File does not exist"}
        
        if not os.access(self.file_path, os.X_OK):
            return {"error": "File is not executable"}
        
        if self.sandbox_mode == "vm":
            execution_result = self._vm_execute()
        else:
            execution_result = self._safe_execute()
        
        duration = (self.end_time - self.start_time).total_seconds() if self.end_time else None
        
        result = {
            "execution": {
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
                "duration": duration,
                **execution_result
            },
            "network_activity": self.network_connections,
            "process_activity": self.process_operations,
            "file_operations": self.file_operations  # Currently not populated
        }
        
        return result

    def cleanup(self):
        """Clean up any temporary files or processes."""
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except:
                self.process.kill()
        
        if os.path.exists(self.result_dir):
            try:
                import shutil
                shutil.rmtree(self.result_dir)
            except Exception as e:
                logging.error(f"Error cleaning up result directory: {e}")

class CuckooIntegration:
    """
    Integration with Cuckoo Sandbox for more secure and thorough dynamic analysis.
    This is a placeholder class that would need to be implemented with a real Cuckoo installation.
    """
    
    def __init__(self, cuckoo_api_url="http://localhost:8090"):
        self.api_url = cuckoo_api_url
        
    def submit_sample(self, file_path):
        """Submit a sample to Cuckoo Sandbox for analysis."""
        # This would be implemented using the Cuckoo REST API
        logging.info(f"Submitting {file_path} to Cuckoo (placeholder)")
        return {"task_id": "sample-task-id"}
    
    def get_report(self, task_id):
        """Get the report for a submitted sample."""
        # This would be implemented using the Cuckoo REST API
        logging.info(f"Getting report for task {task_id} (placeholder)")
        return {"status": "placeholder"}

if __name__ == "__main__":
    # Simple test
    import sys
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) > 1:
        analyzer = DynamicAnalyzer(sys.argv[1], timeout=30)
        try:
            results = analyzer.analyze()
            print(json.dumps(results, indent=4))
        finally:
            analyzer.cleanup()
    else:
        print("Usage: python dynamic_analyzer.py <file_path>")