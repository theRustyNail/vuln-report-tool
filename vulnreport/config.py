"""Project paths and runtime configuration."""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    # python-dotenv is optional. Environment variables still work without it.
    pass

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent

DATA_DIR = PROJECT_ROOT / "data"
SAMPLE_DIR = DATA_DIR / "sample"
CACHE_DIR = DATA_DIR / "cache"
REPORTS_DIR = PROJECT_ROOT / "reports"

# The NVD CVE API accepts anonymous requests at a low rate. A free key raises
# the limit. Keep the key in a local .env file, never in the source.
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Create the output and cache folders on first import so later stages do not
# fail on a missing directory. Both are git-ignored.
for _directory in (CACHE_DIR, REPORTS_DIR):
    _directory.mkdir(parents=True, exist_ok=True)
