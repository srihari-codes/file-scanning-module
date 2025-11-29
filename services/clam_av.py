import asyncio
import json
import subprocess
import tempfile
import os
import time
import re
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import socket
from utils.logger import get_logger

logger = get_logger(__name__)


class ClamAVService:
    """
    ClamAV antivirus scanning service with daemon support, automatic updates,
    and normalized JSON output.
    
    Features:
    - Prefers clamd (daemon) for speed, falls back to clamscan
    - Automatic signature updates before scanning
    - Machine-readable output normalization
    - Comprehensive error handling and logging
    """
    
    # Scan result constants
    CLEAN = "clean"
    INFECTED = "infected"
    ERROR = "error"
    UNKNOWN = "unknown"
    
    def __init__(
        self,
        use_daemon: bool = True,
        daemon_host: str = "localhost",
        daemon_port: int = 3310,
        update_before_scan: bool = False,
        update_interval_hours: int = 6,
        log_dir: Optional[str] = None,
        timeout: int = 300
    ):
        """
        Initialize ClamAV service
        
        Args:
            use_daemon: Try to use clamd daemon first
            daemon_host: ClamAV daemon host
            daemon_port: ClamAV daemon port
            update_before_scan: Run freshclam update (throttled by update_interval_hours)
            update_interval_hours: Minimum hours between signature updates (default: 6)
            log_dir: Directory for scan logs (None = temp directory)
            timeout: Scan timeout in seconds
        """
        self.use_daemon = use_daemon
        self.daemon_host = daemon_host
        self.daemon_port = daemon_port
        self.update_before_scan = update_before_scan
        self.update_interval_hours = update_interval_hours
        self.log_dir = log_dir or tempfile.gettempdir()
        self.timeout = timeout
        
        # Track last update time for throttling
        self.last_update_time: Optional[datetime] = None
        self._update_lock = asyncio.Lock()
        
        # Ensure log directory exists with proper error handling
        try:
            Path(self.log_dir).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning(f"Cannot create log directory {self.log_dir}: {e}. Using temp.")
            self.log_dir = tempfile.gettempdir()
        
        # Check daemon availability on init
        self.daemon_available = False
        if self.use_daemon:
            self.daemon_available = self._check_daemon_availability()
        
        logger.info(
            f"ClamAVService initialized | "
            f"Daemon: {'available' if self.daemon_available else 'not available'} | "
            f"Auto-update: {self.update_before_scan} (throttled to every {self.update_interval_hours}h) | "
            f"Timeout: {self.timeout}s"
        )
    
    def _check_daemon_availability(self) -> bool:
        """Check if ClamAV daemon is running and accessible via socket connection"""
        try:
            # Try direct socket connection to clamd - more reliable than clamdscan --ping
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.daemon_host, self.daemon_port))
            sock.close()
            
            if result == 0:
                logger.info(f"ClamAV daemon available at {self.daemon_host}:{self.daemon_port}")
                return True
            else:
                logger.warning(f"ClamAV daemon not reachable at {self.daemon_host}:{self.daemon_port}")
                return False
                
        except socket.error as e:
            logger.warning(f"Socket error checking daemon: {e}")
            return False
        except Exception as e:
            logger.warning(f"Could not check daemon availability: {e}")
            return False
    
    async def scan(
        self, 
        file_data: bytes, 
        filename: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Main entry point - Scan file data with ClamAV
        
        Args:
            file_data: Binary file data to scan
            filename: Original filename (optional, for logging)
            
        Returns:
            Normalized JSON result with scan status and details
        """
        scan_id = self._generate_scan_id()
        temp_file_path = None
        start_time = time.time()
        
        try:
            # Update signatures if configured
            if self.update_before_scan:
                await self._update_signatures()
            
            # Write file data to temporary file
            temp_file_path = await self._write_temp_file(file_data, scan_id)
            
            logger.info(
                f"Starting ClamAV scan | "
                f"Scan ID: {scan_id} | "
                f"File: {filename or 'unknown'} | "
                f"Size: {len(file_data)} bytes"
            )
            
            # Try daemon first, fallback to clamscan
            if self.use_daemon:
                # Re-check daemon availability if it was previously unavailable
                if not self.daemon_available:
                    self.daemon_available = self._check_daemon_availability()
                
                if self.daemon_available:
                    result = await self._scan_with_daemon(temp_file_path, scan_id, filename)
                else:
                    result = await self._scan_with_clamscan(temp_file_path, scan_id, filename)
            else:
                result = await self._scan_with_clamscan(temp_file_path, scan_id, filename)
            
            # Calculate scan duration
            scan_duration_ms = int((time.time() - start_time) * 1000)
            result["scan_duration_ms"] = scan_duration_ms
            
            # Get engine version and DB age
            version_info = await self._get_engine_info()
            result["engine_version"] = version_info.get("engine_version", "unknown")
            result["db_age_days"] = version_info.get("db_age_days", 0)
            
            # Wrap in new format
            wrapped_result = {"clamav": result}
            
            # Log result
            if result["status"] == self.INFECTED:
                logger.warning(
                    f"THREAT DETECTED | "
                    f"Scan ID: {scan_id} | "
                    f"File: {filename or 'unknown'} | "
                    f"Threat: {result.get('threat_name', 'unknown')}"
                )
            else:
                logger.info(
                    f"Scan completed | "
                    f"Scan ID: {scan_id} | "
                    f"Status: {result['status']}"
                )
            
            return wrapped_result
            
        except Exception as e:
            logger.error(f"ClamAV scan error for {filename}: {e}", exc_info=True)
            scan_duration_ms = int((time.time() - start_time) * 1000)
            error_result = self._create_error_result(scan_id, str(e), filename)
            error_result["scan_duration_ms"] = scan_duration_ms
            version_info = await self._get_engine_info()
            error_result["engine_version"] = version_info.get("engine_version", "unknown")
            error_result["db_age_days"] = version_info.get("db_age_days", 0)
            return {"clamav": error_result}
            
        finally:
            # Cleanup temporary file and log file immediately (zero storage footprint)
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.unlink(temp_file_path)
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp file {temp_file_path}: {e}")
            
            # Delete log file immediately after scan
            log_file = os.path.join(self.log_dir, f"clamav_{scan_id}.log")
            if os.path.exists(log_file):
                try:
                    os.unlink(log_file)
                except Exception as e:
                    logger.debug(f"Could not cleanup log file {log_file}: {e}")
    
    async def _update_signatures(self) -> None:
        """
        Update ClamAV virus signatures using freshclam (throttled)
        
        Runs freshclam to update main.cvd, daily.cvd, and any custom signatures.
        Throttled to prevent excessive updates during high throughput scanning.
        """
        # Check if update is needed based on throttle interval
        if self.last_update_time:
            time_since_update = datetime.utcnow() - self.last_update_time
            if time_since_update < timedelta(hours=self.update_interval_hours):
                logger.debug(
                    f"Skipping update - last update was {time_since_update.total_seconds() / 3600:.1f}h ago "
                    f"(threshold: {self.update_interval_hours}h)"
                )
                return
        
        # Use lock to prevent concurrent updates
        async with self._update_lock:
            # Double-check after acquiring lock
            if self.last_update_time:
                time_since_update = datetime.utcnow() - self.last_update_time
                if time_since_update < timedelta(hours=self.update_interval_hours):
                    return
            
            try:
                logger.info("Updating ClamAV signatures...")
                
                process = await asyncio.create_subprocess_exec(
                    "freshclam",
                    "--quiet",  # Use quiet mode for production
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=180  # 3 minute timeout for updates
                )
                
                if process.returncode == 0:
                    logger.info("ClamAV signatures updated successfully")
                    self.last_update_time = datetime.utcnow()
                else:
                    # Return code 1 often means "already up to date"
                    stdout_str = stdout.decode('utf-8', errors='ignore').lower()
                    stderr_str = stderr.decode('utf-8', errors='ignore').lower()
                    
                    if "up-to-date" in stdout_str or "up-to-date" in stderr_str or "up to date" in stdout_str:
                        logger.info("ClamAV signatures already up-to-date")
                        self.last_update_time = datetime.utcnow()
                    else:
                        logger.warning(
                            f"freshclam returned {process.returncode}: "
                            f"{stderr_str}"
                        )
                        
            except asyncio.TimeoutError:
                logger.error("ClamAV signature update timed out after 3 minutes")
            except FileNotFoundError:
                logger.error("freshclam not found, skipping signature update")
            except Exception as e:
                logger.error(f"Failed to update ClamAV signatures: {e}")
    
    async def _write_temp_file(self, file_data: bytes, scan_id: str) -> str:
        """Write file data to temporary file for scanning"""
        temp_file = tempfile.NamedTemporaryFile(
            mode='wb',
            delete=False,
            prefix=f'clamav_{scan_id}_',
            suffix='.tmp'
        )
        
        try:
            await asyncio.to_thread(temp_file.write, file_data)
            temp_file.close()
            return temp_file.name
        except Exception as e:
            temp_file.close()
            if os.path.exists(temp_file.name):
                os.unlink(temp_file.name)
            raise RuntimeError(f"Failed to write temporary file: {e}")
    
    async def _scan_with_daemon(
        self, 
        file_path: str, 
        scan_id: str,
        filename: Optional[str]
    ) -> Dict[str, Any]:
        """
        Scan file using clamdscan (daemon mode - faster)
        
        Options:
        --infected: Only print infected files
        --no-summary: Don't print summary
        --fdpass: Pass file descriptor to avoid permission issues
        """
        log_file = os.path.join(self.log_dir, f"clamav_{scan_id}.log")
        
        try:
            cmd = [
                "clamdscan",
                "--fdpass",             # Pass file descriptor (avoids permission issues)
                "--infected",           # Only show infected files
                "--no-summary",         # No summary line
                f"--log={log_file}",    # Log to file
                file_path
            ]
            
            logger.debug(f"Running clamdscan: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )
            
            # Parse results
            return await self._parse_scan_output(
                stdout.decode('utf-8', errors='ignore'),
                stderr.decode('utf-8', errors='ignore'),
                process.returncode if process.returncode is not None else 2,
                scan_id,
                filename,
                log_file,
                scanner="clamdscan"
            )
            
        except asyncio.TimeoutError:
            logger.error(f"clamdscan timed out after {self.timeout}s")
            return self._create_error_result(
                scan_id, 
                f"Scan timed out after {self.timeout}s",
                filename
            )
        except Exception as e:
            logger.error(f"clamdscan error: {e}")
            # Fallback to clamscan
            logger.info("Falling back to clamscan...")
            return await self._scan_with_clamscan(file_path, scan_id, filename)
    
    async def _scan_with_clamscan(
        self, 
        file_path: str, 
        scan_id: str,
        filename: Optional[str]
    ) -> Dict[str, Any]:
        """
        Scan file using clamscan (standalone mode - slower but more reliable)
        
        Options:
        --infected: Only print infected files
        --remove=no: Don't remove infected files
        --no-summary: Don't print summary
        """
        log_file = os.path.join(self.log_dir, f"clamav_{scan_id}.log")
        
        try:
            cmd = [
                "clamscan",
                "--infected",           # Only show infected files
                "--remove=no",          # Don't remove files
                "--no-summary",         # No summary line
                f"--log={log_file}",    # Log to file
                file_path
            ]
            
            logger.debug(f"Running clamscan: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )
            
            # Parse results
            return await self._parse_scan_output(
                stdout.decode('utf-8', errors='ignore'),
                stderr.decode('utf-8', errors='ignore'),
                process.returncode if process.returncode is not None else 2,
                scan_id,
                filename,
                log_file,
                scanner="clamscan"
            )
            
        except asyncio.TimeoutError:
            logger.error(f"clamscan timed out after {self.timeout}s")
            return self._create_error_result(
                scan_id,
                f"Scan timed out after {self.timeout}s",
                filename
            )
        except FileNotFoundError:
            logger.error("clamscan not found - ClamAV not installed?")
            return self._create_error_result(
                scan_id,
                "ClamAV not installed or not in PATH",
                filename
            )
        except Exception as e:
            logger.error(f"clamscan error: {e}", exc_info=True)
            return self._create_error_result(scan_id, str(e), filename)
    
    async def _parse_scan_output(
        self,
        stdout: str,
        stderr: str,
        return_code: int,
        scan_id: str,
        filename: Optional[str],
        log_file: str,
        scanner: str
    ) -> Dict[str, Any]:
        """
        Parse ClamAV output and normalize to JSON schema
        
        ClamAV return codes:
        0 = No virus found
        1 = Virus found
        2+ = Error
        """
        result = {
            "scan_success": return_code in [0, 1],
            "status": self.UNKNOWN,
            "return_code": return_code,
            "infected": False,
            "threat_name": None,
            "threat_count": 0,
            "is_heuristic": False,
            "is_pua": False,
            "signature_family": None,
            "signature_prefix": None,
            "subfiles_infected": 0,
            "subfiles_scanned": 0,
            "max_archive_depth": 0,
            "scan_duration_ms": 0,
            "engine_version": "unknown",
            "db_age_days": 0
        }
        
        try:
            # Parse based on return code
            if return_code == 0:
                # Clean - no virus found
                result["status"] = self.CLEAN
                result["infected"] = False
                result["threat_count"] = 0
                
            elif return_code == 1:
                # Infected - virus found
                result["status"] = self.INFECTED
                result["infected"] = True
                
                # Parse threat name from output (check both stdout and stderr)
                combined_output = stdout + "\n" + stderr
                threat_info = self._extract_threat_info(combined_output)
                
                if threat_info:
                    result["threat_name"] = threat_info["name"]
                    result["threat_count"] = len(threat_info["details"])
                    
                    # Analyze signature characteristics
                    sig_analysis = self._analyze_signature(threat_info["name"])
                    result["is_heuristic"] = sig_analysis["is_heuristic"]
                    result["is_pua"] = sig_analysis["is_pua"]
                    result["signature_family"] = sig_analysis["family"]
                    result["signature_prefix"] = sig_analysis["prefix"]
                else:
                    result["threat_name"] = "Unknown threat"
                    result["threat_count"] = 1
                
                # Parse archive/subfile information from output
                archive_info = self._parse_archive_info(combined_output)
                result["subfiles_infected"] = archive_info["infected_count"]
                result["subfiles_scanned"] = archive_info["scanned_count"]
                result["max_archive_depth"] = archive_info["max_depth"]
                
            else:
                # Error (return code 2+)
                result["status"] = self.ERROR
                result["scan_success"] = False
                
        except Exception as e:
            logger.error(f"Error parsing scan output: {e}")
            result["status"] = self.ERROR
            result["scan_success"] = False
        
        return result
    
    def _extract_threat_info(self, output: str) -> Optional[Dict[str, Any]]:
        """
        Extract threat information from ClamAV output
        
        ClamAV output formats:
        /path/to/file: ThreatName FOUND
        /path/to/file: ThreatName.UNOFFICIAL FOUND (custom signatures)
        May appear in different locales
        """
        threats = []
        output_lower = output.lower()
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Look for "FOUND" keyword (case-insensitive for localized versions)
            line_lower = line.lower()
            if 'found' in line_lower or 'infected' in line_lower:
                try:
                    # Split by ': ' to separate path and threat
                    parts = line.split(': ')
                    if len(parts) >= 2:
                        # Extract threat name (remove FOUND, INFECTED, etc.)
                        threat_part = parts[-1]
                        for keyword in [' FOUND', ' found', ' INFECTED', ' infected', ' ERROR', ' error']:
                            threat_part = threat_part.replace(keyword, '')
                        threat_part = threat_part.strip()
                        
                        if threat_part:  # Only add if we got a non-empty threat name
                            threats.append({
                                "name": threat_part,
                                "line": line
                            })
                except Exception as e:
                    logger.warning(f"Failed to parse threat line: {line} - {e}")
        
        if not threats:
            return None
        
        # Return first threat (usually only one per file)
        return {
            "name": threats[0]["name"],
            "details": threats
        }
    
    def _create_error_result(
        self,
        scan_id: str,
        error_message: str,
        filename: Optional[str]
    ) -> Dict[str, Any]:
        """Create standardized error result"""
        return {
            "scan_success": False,
            "status": self.ERROR,
            "return_code": 2,
            "infected": False,
            "threat_name": None,
            "threat_count": 0,
            "is_heuristic": False,
            "is_pua": False,
            "signature_family": None,
            "signature_prefix": None,
            "subfiles_infected": 0,
            "subfiles_scanned": 0,
            "max_archive_depth": 0,
            "scan_duration_ms": 0,
            "engine_version": "unknown",
            "db_age_days": 0
        }
    
    def _analyze_signature(self, threat_name: str) -> Dict[str, Any]:
        """
        Analyze threat signature for characteristics
        
        Examples:
        - Heur.Trojan.Win32.Generic
        - PUA.Win.Adware.Conduit
        - Win.Trojan.Agent-1234567
        - JS.Downloader.Trojan
        """
        if not threat_name:
            return {
                "is_heuristic": False,
                "is_pua": False,
                "family": None,
                "prefix": None
            }
        
        threat_upper = threat_name.upper()
        
        # Check if heuristic detection
        is_heuristic = threat_upper.startswith("HEUR.") or "HEURISTIC" in threat_upper
        
        # Check if PUA (Potentially Unwanted Application)
        is_pua = threat_upper.startswith("PUA.") or "PUA:" in threat_upper
        
        # Extract signature family (Trojan, Worm, Backdoor, etc.)
        family = None
        family_patterns = [
            r"\.(Trojan|Worm|Backdoor|Ransomware|Rootkit|Downloader|Dropper|Adware|Spyware|Keylogger)",
            r"(Trojan|Worm|Backdoor|Ransomware|Rootkit|Downloader|Dropper|Adware|Spyware|Keylogger)[.:-]"
        ]
        for pattern in family_patterns:
            match = re.search(pattern, threat_name, re.IGNORECASE)
            if match:
                family = match.group(1).capitalize()
                break
        
        # Extract platform prefix (Win, OSX, Linux, JS, HTML, etc.)
        prefix = None
        prefix_patterns = [
            r"^(Win|W32|W64|OSX|MacOS|Linux|Unix|Android|JS|HTML|PHP|Python|Perl|VBS|BAT|PDF|DOC|XLS)",
            r"\.(Win|W32|W64|OSX|MacOS|Linux|Unix|Android|JS|HTML|PHP|Python|Perl|VBS|BAT|PDF|DOC|XLS)\."
        ]
        for pattern in prefix_patterns:
            match = re.search(pattern, threat_name, re.IGNORECASE)
            if match:
                prefix = match.group(1).upper()
                # Normalize W32/W64 to Win
                if prefix in ["W32", "W64"]:
                    prefix = "Win"
                break
        
        return {
            "is_heuristic": is_heuristic,
            "is_pua": is_pua,
            "family": family,
            "prefix": prefix
        }
    
    def _parse_archive_info(self, output: str) -> Dict[str, int]:
        """
        Parse archive/subfile information from ClamAV output
        
        ClamAV may report:
        - Files scanned in archives
        - Nested archive depth
        - Multiple infections in container files
        """
        info = {
            "infected_count": 0,
            "scanned_count": 0,
            "max_depth": 0
        }
        
        # Count infected files (lines with FOUND)
        infected_lines = [line for line in output.split('\n') if 'FOUND' in line.upper()]
        info["infected_count"] = len(infected_lines)
        
        # Try to extract scanned files count
        scanned_match = re.search(r'Scanned files: (\d+)', output, re.IGNORECASE)
        if scanned_match:
            info["scanned_count"] = int(scanned_match.group(1))
        
        # Estimate archive depth from path separators in infected file paths
        for line in infected_lines:
            # Count archive indicators like -> or : in path
            depth = line.count('->')
            if depth > info["max_depth"]:
                info["max_depth"] = depth
        
        return info
    
    async def _get_engine_info(self) -> Dict[str, Any]:
        """
        Get ClamAV engine version and database age
        """
        try:
            # Get version info
            process = await asyncio.create_subprocess_exec(
                "clamscan" if not self.daemon_available else "clamdscan",
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=5)
            version_output = stdout.decode('utf-8', errors='ignore')
            
            # Extract engine version (e.g., "ClamAV 0.103.9")
            engine_version = "unknown"
            version_match = re.search(r'ClamAV (\d+\.\d+\.\d+)', version_output)
            if version_match:
                engine_version = version_match.group(1)
            
            # Get database age (check daily.cvd/cld modification time)
            db_age_days = 0
            try:
                # Common ClamAV database locations
                db_paths = [
                    "/var/lib/clamav/daily.cvd",
                    "/var/lib/clamav/daily.cld",
                    "C:\\ProgramData\\clamav\\daily.cvd",
                    "C:\\ProgramData\\clamav\\daily.cld"
                ]
                
                for db_path in db_paths:
                    if os.path.exists(db_path):
                        mtime = os.path.getmtime(db_path)
                        age_seconds = time.time() - mtime
                        db_age_days = int(age_seconds / 86400)  # Convert to days
                        break
            except Exception:
                pass
            
            return {
                "engine_version": engine_version,
                "db_age_days": db_age_days
            }
            
        except Exception as e:
            logger.debug(f"Could not get engine info: {e}")
            return {
                "engine_version": "unknown",
                "db_age_days": 0
            }
    
    def _generate_scan_id(self) -> str:
        """Generate unique scan ID"""
        from datetime import datetime
        import random
        import string
        
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"{timestamp}_{random_suffix}"
    
    async def get_version(self) -> Dict[str, Any]:
        """Get ClamAV version and database information"""
        try:
            process = await asyncio.create_subprocess_exec(
                "clamdscan" if self.daemon_available else "clamscan",
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=10
            )
            
            version_info = stdout.decode('utf-8', errors='ignore').strip()
            
            return {
                "available": True,
                "version": version_info,
                "daemon_available": self.daemon_available
            }
            
        except Exception as e:
            logger.error(f"Failed to get ClamAV version: {e}")
            return {
                "available": False,
                "error": str(e),
                "daemon_available": self.daemon_available
            }
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on ClamAV service
        
        Note: Temporarily disables signature updates to avoid state changes
        and long delays during health checks.
        
        Returns:
            Dictionary with health status and details
        """
        health = {
            "service": "clamav",
            "healthy": False,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "checks": {}
        }
        
        try:
            # Check 1: Version/availability
            version = await self.get_version()
            health["checks"]["version"] = version
            
            # Check 2: Daemon availability (if configured)
            if self.use_daemon:
                daemon_status = self._check_daemon_availability()
                health["checks"]["daemon"] = {
                    "available": daemon_status,
                    "host": self.daemon_host,
                    "port": self.daemon_port
                }
            
            # Check 3: Test scan with EICAR test string
            # Temporarily disable updates for health check
            original_update_setting = self.update_before_scan
            self.update_before_scan = False
            
            eicar_test = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            test_result = await self.scan(eicar_test, filename="eicar_test.txt")
            
            # Restore original setting
            self.update_before_scan = original_update_setting
            
            health["checks"]["test_scan"] = {
                "executed": True,
                "detected_eicar": test_result.get("status") == self.INFECTED
            }
            
            # Overall health
            health["healthy"] = (
                version.get("available", False) and
                test_result.get("status") == self.INFECTED  # Should detect EICAR
            )
            
            logger.info(f"ClamAV health check: {'HEALTHY' if health['healthy'] else 'UNHEALTHY'}")
            
        except Exception as e:
            logger.error(f"ClamAV health check failed: {e}")
            health["error"] = str(e)
        
        return health
