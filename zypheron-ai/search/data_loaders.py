"""
Data Loaders for Security Intelligence Sources

Provides automated data loading and synchronization from:
- CVE Database (NVD API)
- MITRE ATT&CK Framework (STIX/TAXII)
- Nuclei Templates (Local YAML parsing)
- Exploit-DB (Local database parsing)

Each loader supports:
- Background synchronization with threading
- Progress tracking and status updates
- Error handling and retry logic
- Metadata tracking in sync_metadata table
"""

import logging
import threading
import time
import json
import csv
import requests
import re
from pathlib import Path
from typing import Optional, Callable, Dict, List, Any
from datetime import datetime, timedelta
from dataclasses import dataclass

try:
    import yaml
except ImportError:
    yaml = None

from .fts_search import SearchDB

logger = logging.getLogger(__name__)


@dataclass
class SyncProgress:
    """Progress tracking for data synchronization"""
    loader_name: str
    status: str  # 'idle', 'running', 'completed', 'failed'
    total_records: int
    processed_records: int
    current_operation: str
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    @property
    def progress_percent(self) -> float:
        if self.total_records == 0:
            return 0.0
        return (self.processed_records / self.total_records) * 100

    def to_dict(self) -> Dict[str, Any]:
        return {
            'loader_name': self.loader_name,
            'status': self.status,
            'total_records': self.total_records,
            'processed_records': self.processed_records,
            'progress_percent': self.progress_percent,
            'current_operation': self.current_operation,
            'error_message': self.error_message,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
        }


class BaseLoader:
    """Base class for all data loaders with threading support"""

    def __init__(self, db: Optional[SearchDB] = None):
        self.db = db or SearchDB()
        self.progress = SyncProgress(
            loader_name=self.__class__.__name__,
            status='idle',
            total_records=0,
            processed_records=0,
            current_operation='Initialized'
        )
        self._sync_thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._lock = threading.Lock()

    def _set_progress(self, **updates):
        """Thread-safe atomic progress update (fixes race condition)"""
        with self._lock:
            for key, value in updates.items():
                setattr(self.progress, key, value)

    def sync(self, background: bool = False, progress_callback: Optional[Callable[[SyncProgress], None]] = None):
        """Start synchronization"""
        if background:
            if self._sync_thread and self._sync_thread.is_alive():
                logger.warning(f"{self.progress.loader_name} sync already running")
                return

            self._stop_flag.clear()
            self._sync_thread = threading.Thread(
                target=self._sync_wrapper,
                args=(progress_callback,),
                daemon=True,
                name=f"{self.progress.loader_name}-sync"
            )
            self._sync_thread.start()
            logger.info(f"{self.progress.loader_name} sync started in background")
        else:
            self._sync_wrapper(progress_callback)

    def _sync_wrapper(self, progress_callback: Optional[Callable[[SyncProgress], None]] = None):
        try:
            # Atomic state transition to 'running'
            self._set_progress(
                status='running',
                started_at=datetime.now(),
                error_message=None,
                processed_records=0
            )

            logger.info(f"Starting {self.progress.loader_name} synchronization")
            self._do_sync(progress_callback)

            # Atomic state transition to 'completed'
            self._set_progress(
                status='completed',
                completed_at=datetime.now(),
                current_operation='Sync completed successfully'
            )

            logger.info(f"{self.progress.loader_name} sync completed: {self.progress.processed_records} records")

        except Exception as e:
            logger.error(f"{self.progress.loader_name} sync failed: {e}", exc_info=True)
            # Atomic state transition to 'failed'
            self._set_progress(
                status='failed',
                error_message=str(e),
                completed_at=datetime.now(),
                current_operation=f'Failed: {str(e)[:100]}'
            )

        finally:
            if progress_callback:
                progress_callback(self.get_progress())

    def _do_sync(self, progress_callback: Optional[Callable[[SyncProgress], None]] = None):
        raise NotImplementedError("Subclasses must implement _do_sync()")

    def _update_progress(self, current_operation: str, progress_callback: Optional[Callable[[SyncProgress], None]] = None):
        self._set_progress(current_operation=current_operation)
        if progress_callback:
            progress_callback(self.get_progress())

    def _increment_processed(self, count: int = 1):
        """Thread-safe increment of processed records"""
        with self._lock:
            self.progress.processed_records += count

    def stop(self):
        self._stop_flag.set()
        if self._sync_thread and self._sync_thread.is_alive():
            self._sync_thread.join(timeout=5.0)
            logger.info(f"{self.progress.loader_name} sync stopped")

    def get_progress(self) -> SyncProgress:
        """Return a snapshot copy of progress (thread-safe)"""
        with self._lock:
            # Return a copy to prevent external modification
            return SyncProgress(
                loader_name=self.progress.loader_name,
                status=self.progress.status,
                total_records=self.progress.total_records,
                processed_records=self.progress.processed_records,
                current_operation=self.progress.current_operation,
                error_message=self.progress.error_message,
                started_at=self.progress.started_at,
                completed_at=self.progress.completed_at
            )


class CVELoader(BaseLoader):
    """CVE Database Loader - Fetches from NIST NVD API (last 7 years)"""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    BATCH_SIZE = 2000
    RATE_LIMIT_DELAY = 6

    def __init__(self, db: Optional[SearchDB] = None, api_key: Optional[str] = None, days_back: int = 2555):
        super().__init__(db)
        self.api_key = api_key
        self.days_back = days_back

    def _redact_api_key(self, key: Optional[str]) -> str:
        """Security: Redact API key for logging (show only first/last 4 chars)"""
        if not key or len(key) < 12:
            return "[REDACTED]" if key else "[NONE]"
        return f"{key[:4]}...{key[-4:]}"

    def _do_sync(self, progress_callback: Optional[Callable[[SyncProgress], None]] = None):
        self._update_progress("Calculating date range", progress_callback)

        end_date = datetime.now()
        start_date = end_date - timedelta(days=self.days_back)
        start_date_str = start_date.strftime("%Y-%m-%dT00:00:00.000")
        end_date_str = end_date.strftime("%Y-%m-%dT23:59:59.999")

        # Security: Log with redacted API key
        logger.info(f"Fetching CVEs from {start_date_str} to {end_date_str} "
                   f"(API key: {self._redact_api_key(self.api_key)})")

        cves_collected = []
        start_index = 0
        total_results = None

        while not self._stop_flag.is_set():
            self._update_progress(f"Fetching CVEs (offset {start_index})", progress_callback)

            try:
                params = {
                    'pubStartDate': start_date_str,
                    'pubEndDate': end_date_str,
                    'startIndex': start_index,
                    'resultsPerPage': self.BATCH_SIZE
                }
                # Security: API key in headers but never logged
                headers = {'apiKey': self.api_key} if self.api_key else {}

                response = requests.get(self.NVD_API_BASE, params=params, headers=headers, timeout=30)
                response.raise_for_status()
                data = response.json()

                if total_results is None:
                    total_results = data.get('totalResults', 0)
                    self._set_progress(total_records=total_results)
                    logger.info(f"Total CVEs to fetch: {total_results}")

                vulnerabilities = data.get('vulnerabilities', [])
                if not vulnerabilities:
                    break

                for vuln_data in vulnerabilities:
                    if self._stop_flag.is_set():
                        break
                    cve = self._parse_cve(vuln_data)
                    if cve:
                        cves_collected.append(cve)
                    self._increment_processed()

                start_index += len(vulnerabilities)
                if start_index >= total_results:
                    break

                if not self.api_key:
                    time.sleep(self.RATE_LIMIT_DELAY)

            except requests.RequestException as e:
                # Security: Don't include headers in error message
                raise Exception(f"Failed to fetch CVEs from NVD API: {type(e).__name__}")

        if cves_collected:
            self._update_progress(f"Inserting {len(cves_collected)} CVEs", progress_callback)
            self.db.add_cves_batch(cves_collected)
            self.db.update_sync_metadata('cve_search', len(cves_collected), f'NVD API (last {self.days_back} days)')

    def _parse_cve(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, str]]:
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id', '')

            descriptions = cve.get('descriptions', [])
            description = next((d.get('value', '') for d in descriptions if d.get('lang') == 'en'), '')

            metrics = cve.get('metrics', {})
            cvss_score = 'N/A'
            for metric_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if metric_key in metrics and metrics[metric_key]:
                    cvss_score = str(metrics[metric_key][0].get('cvssData', {}).get('baseScore', 'N/A'))
                    break

            affected_products = []
            for config in cve.get('configurations', []):
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        cpe = cpe_match.get('criteria', '')
                        if cpe:
                            parts = cpe.split(':')
                            if len(parts) >= 5:
                                affected_products.append(f"{parts[3]}:{parts[4]}")

            return {
                'cve_id': cve_id,
                'description': description,
                'affected_products': ', '.join(affected_products[:10]),
                'cvss_score': cvss_score,
                'published_date': cve.get('published', '')
            }
        except Exception as e:
            logger.warning(f"Failed to parse CVE: {e}")
            return None


class MITRELoader(BaseLoader):
    """MITRE ATT&CK Framework Loader - Downloads from GitHub"""

    MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    def _do_sync(self, progress_callback: Optional[Callable[[SyncProgress], None]] = None):
        self._update_progress("Downloading MITRE ATT&CK data", progress_callback)

        try:
            response = requests.get(self.MITRE_URL, timeout=60)
            response.raise_for_status()
            stix_data = response.json()
        except requests.RequestException as e:
            raise Exception(f"Failed to fetch MITRE ATT&CK data: {e}")

        self._update_progress("Parsing techniques", progress_callback)
        objects = stix_data.get('objects', [])
        attack_patterns = [obj for obj in objects if obj.get('type') == 'attack-pattern']

        with self._lock:
            self.progress.total_records = len(attack_patterns)

        techniques = []
        for obj in attack_patterns:
            if self._stop_flag.is_set():
                break
            technique = self._parse_technique(obj)
            if technique:
                techniques.append(technique)
            with self._lock:
                self.progress.processed_records += 1

        if techniques:
            self._update_progress(f"Inserting {len(techniques)} techniques", progress_callback)
            self.db.add_attack_techniques_batch(techniques)
            self.db.update_sync_metadata('attack_search', len(techniques), 'MITRE ATT&CK Enterprise')

    def _parse_technique(self, obj: Dict[str, Any]) -> Optional[Dict[str, str]]:
        try:
            technique_id = ''
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    technique_id = ref.get('external_id', '')
                    break
            if not technique_id:
                return None

            tactics = []
            for phase in obj.get('kill_chain_phases', []):
                if phase.get('kill_chain_name') == 'mitre-attack':
                    tactics.append(phase.get('phase_name', '').replace('-', ' ').title())

            return {
                'technique_id': technique_id,
                'name': obj.get('name', ''),
                'description': obj.get('description', ''),
                'tactics': ', '.join(tactics),
                'platforms': ', '.join(obj.get('x_mitre_platforms', []))
            }
        except Exception as e:
            logger.warning(f"Failed to parse technique: {e}")
            return None


class NucleiLoader(BaseLoader):
    """Nuclei Templates Loader - Parses local YAML files"""

    def __init__(self, db: Optional[SearchDB] = None, templates_dir: Optional[Path] = None):
        super().__init__(db)
        self.templates_dir = Path(templates_dir) if templates_dir else Path.home() / ".zypheron" / "nuclei-templates"

    def _do_sync(self, progress_callback: Optional[Callable[[SyncProgress], None]] = None):
        if not self.templates_dir.exists():
            raise FileNotFoundError(f"Nuclei templates not found: {self.templates_dir}")

        if yaml is None:
            raise ImportError("PyYAML required: pip install pyyaml")

        self._update_progress("Scanning YAML files", progress_callback)
        yaml_files = list(self.templates_dir.rglob("*.yaml")) + list(self.templates_dir.rglob("*.yml"))

        with self._lock:
            self.progress.total_records = len(yaml_files)

        templates = []
        for yaml_file in yaml_files:
            if self._stop_flag.is_set():
                break
            template = self._parse_template(yaml_file)
            if template:
                templates.append(template)
            with self._lock:
                self.progress.processed_records += 1

        if templates:
            self._update_progress(f"Inserting {len(templates)} templates", progress_callback)
            self.db.add_nuclei_templates_batch(templates)
            self.db.update_sync_metadata('nuclei_search', len(templates), str(self.templates_dir))

    def _parse_template(self, yaml_file: Path) -> Optional[Dict[str, str]]:
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            if not data:
                return None

            info = data.get('info', {})
            tags = info.get('tags', [])
            if isinstance(tags, str):
                tags = [tags]

            return {
                'template_id': data.get('id', yaml_file.stem),
                'name': info.get('name', ''),
                'description': info.get('description', ''),
                'severity': info.get('severity', 'info'),
                'tags': ', '.join(str(t) for t in tags) if tags else ''
            }
        except Exception:
            return None


class ExploitDBLoader(BaseLoader):
    """Exploit-DB Loader - Parses local CSV database"""

    DEFAULT_PATHS = [Path("/usr/share/exploitdb"), Path.home() / ".zypheron" / "exploitdb"]

    def __init__(self, db: Optional[SearchDB] = None, exploitdb_dir: Optional[Path] = None):
        super().__init__(db)
        self.exploitdb_dir = Path(exploitdb_dir) if exploitdb_dir else self._find_exploitdb_dir()

    def _find_exploitdb_dir(self) -> Path:
        for path in self.DEFAULT_PATHS:
            if path.exists() and (path / "files_exploits.csv").exists():
                return path
        return self.DEFAULT_PATHS[1]

    def _do_sync(self, progress_callback: Optional[Callable[[SyncProgress], None]] = None):
        csv_file = self.exploitdb_dir / "files_exploits.csv"
        if not csv_file.exists():
            raise FileNotFoundError(f"Exploit-DB CSV not found: {csv_file}")

        self._update_progress("Counting exploits", progress_callback)
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            total_rows = sum(1 for _ in f) - 1

        with self._lock:
            self.progress.total_records = total_rows

        exploits = []
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            for row in csv.DictReader(f):
                if self._stop_flag.is_set():
                    break
                exploit = self._parse_exploit(row)
                if exploit:
                    exploits.append(exploit)
                with self._lock:
                    self.progress.processed_records += 1

        if exploits:
            self._update_progress(f"Inserting {len(exploits)} exploits", progress_callback)
            self.db.add_exploits_batch(exploits)
            self.db.update_sync_metadata('exploit_search', len(exploits), str(self.exploitdb_dir))

    def _parse_exploit(self, row: Dict[str, str]) -> Optional[Dict[str, str]]:
        try:
            exploit_id = row.get('id', '').strip()
            if not exploit_id:
                return None

            title = row.get('description', '').strip()
            cves = re.findall(r'CVE-\d{4}-\d{4,7}', title, re.IGNORECASE)

            return {
                'exploit_id': exploit_id,
                'title': title,
                'description': f"[{row.get('type', '')}] {title}",
                'platform': row.get('platform', ''),
                'cve_references': ', '.join(set(c.upper() for c in cves))
            }
        except Exception:
            return None


class DataLoaderManager:
    """Manager for coordinating multiple data loaders"""

    def __init__(self, db: Optional[SearchDB] = None):
        self.db = db or SearchDB()
        self.loaders = {
            'cve': CVELoader(self.db),
            'mitre': MITRELoader(self.db),
            'nuclei': NucleiLoader(self.db),
            'exploitdb': ExploitDBLoader(self.db)
        }

    def sync_all(self, background: bool = True, sources: Optional[List[str]] = None,
                 progress_callback: Optional[Callable[[str, SyncProgress], None]] = None):
        sources_to_sync = sources or list(self.loaders.keys())
        for source_name in sources_to_sync:
            if source_name in self.loaders:
                callback = None
                if progress_callback:
                    callback = lambda p, n=source_name: progress_callback(n, p)
                self.loaders[source_name].sync(background=background, progress_callback=callback)

    def stop_all(self):
        for loader in self.loaders.values():
            loader.stop()

    def get_all_progress(self) -> Dict[str, SyncProgress]:
        return {name: loader.get_progress() for name, loader in self.loaders.items()}

    def get_sync_status(self) -> Dict[str, Any]:
        return {
            'loaders': {name: prog.to_dict() for name, prog in self.get_all_progress().items()},
            'database_stats': self.db.get_stats(),
            'timestamp': datetime.now().isoformat()
        }


# Convenience functions
def sync_cves(background: bool = True, api_key: Optional[str] = None) -> CVELoader:
    loader = CVELoader(api_key=api_key)
    loader.sync(background=background)
    return loader

def sync_mitre(background: bool = True) -> MITRELoader:
    loader = MITRELoader()
    loader.sync(background=background)
    return loader

def sync_nuclei(background: bool = True, templates_dir: Optional[Path] = None) -> NucleiLoader:
    loader = NucleiLoader(templates_dir=templates_dir)
    loader.sync(background=background)
    return loader

def sync_exploitdb(background: bool = True, exploitdb_dir: Optional[Path] = None) -> ExploitDBLoader:
    loader = ExploitDBLoader(exploitdb_dir=exploitdb_dir)
    loader.sync(background=background)
    return loader
