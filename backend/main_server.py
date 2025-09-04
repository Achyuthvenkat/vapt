from fastapi import FastAPI, HTTPException, UploadFile, File, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.sql import func
import pymysql
import requests
import xml.etree.ElementTree as ET
import json
import os
import pandas as pd
from datetime import datetime
from typing import List, Optional
import re
import asyncio
from tqdm.asyncio import tqdm_asyncio
from tqdm import tqdm
from dotenv import load_dotenv
from openai import AsyncOpenAI
from analyze import INSTRUCTIONS, OUTPUT_SCHEMA
import nest_asyncio
import time
from sqlalchemy import UniqueConstraint
from sqlalchemy.exc import IntegrityError

# Apply nest_asyncio for async compatibility
nest_asyncio.apply()
load_dotenv()

app = FastAPI(
    title="Unified SBOM & Qualys Security Dashboard",
    description="Unified API for SBOM vulnerability analysis and Qualys vulnerability management",
    version="1.0.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Global cache for QID titles
qid_title_cache = {}


# Database Models
class SBOMData(Base):
    __tablename__ = "sbom_data"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), nullable=False)
    package_name = Column(String(255), nullable=False)
    package_type = Column(String(50), nullable=False)
    installed_version = Column(String(100), nullable=False)
    latest_version = Column(String(100))
    license = Column(Text)
    vulnerabilities = Column(Text)
    suggestions = Column(Text)
    license_summary = Column(Text)
    verdict = Column(String(100))
    package_url = Column(Text)
    distribution_url = Column(Text)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint(
            "hostname", "package_name", "installed_version", name="uq_host_pkg_version"
        ),
    )


class QualysData(Base):
    __tablename__ = "qualys_data"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(String(50))
    asset_ip = Column(String(45))
    asset_name = Column(String(255))
    netbios = Column(String(255))
    os = Column(Text)
    asset_tags = Column(Text)
    last_scan_datetime = Column(DateTime)
    unique_vuln_id = Column(String(100))
    qid = Column(String(20))
    vulnerability_title = Column(Text)  # Added vulnerability title field
    vuln_type = Column(String(50))
    severity = Column(Integer)
    port = Column(String(10))
    protocol = Column(String(10))
    ssl = Column(String(10))
    status = Column(String(20))
    first_found_datetime = Column(DateTime)
    last_found_datetime = Column(DateTime)
    last_test_datetime = Column(DateTime)
    last_update_datetime = Column(DateTime)
    times_found = Column(Integer)
    results = Column(Text)
    qds = Column(Float)
    qds_severity = Column(String(20))
    qds_factors = Column(Text)
    created_at = Column(DateTime, default=func.now())


# Create tables
Base.metadata.create_all(bind=engine)

# OpenAI client
client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))


async def analyze_package_vulnerabilities(package_dict):
    """Analyze package vulnerabilities using OpenAI"""
    try:
        response = await client.responses.create(
            instructions=INSTRUCTIONS,
            model="gpt-4o",
            input=[
                {
                    "role": "developer",
                    "content": [{"type": "input_text", "text": str(package_dict)}],
                }
            ],
            text={"format": OUTPUT_SCHEMA},
            tools=[{"type": "web_search_preview"}],
            temperature=0.2,
        )
        out_txt = response.output_text.strip()
        return json.loads(out_txt)
    except Exception as e:
        print(f"OpenAI analysis failed: {e}")
        # Return default structure
        return {
            "Name": package_dict.get("name", ""),
            "Variation": package_dict.get("type", ""),
            "Installed Version": package_dict.get("version", ""),
            "Latest Version": package_dict.get("latest", ""),
            "Package URL": package_dict.get("purl", ""),
            "Distribution URL": package_dict.get("dist_url", ""),
            "License": package_dict.get("license", ""),
            "Vulnerabilities": "Analysis failed",
            "Suggestions": "Manual review required",
            "License Summary": "Review required",
            "Verdict": "⚠️ Requires Legal Review",
        }


async def worker(pkg, semaphore):
    """Worker function with semaphore for rate limiting"""
    async with semaphore:
        return await analyze_package_vulnerabilities(pkg)


async def analyze_packages_batch(package_dicts, concurrency=10):
    """Analyze packages in batches using async processing"""
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [asyncio.create_task(worker(pkg, semaphore)) for pkg in package_dicts]
    results = []
    for f in tqdm_asyncio.as_completed(
        tasks, total=len(tasks), desc="Analyzing Vulnerabilities"
    ):
        result = await f
        results.append(result)

    return results


# Pydantic models
class SBOMRequest(BaseModel):
    hostname: str
    packages: List[dict]


class PackageRequest(BaseModel):
    package_name: str
    package_type: str


class LicenseResponse(BaseModel):
    license: str


class VersionResponse(BaseModel):
    latest_version: str


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class BulkSBOMRequest(BaseModel):
    hostname: str
    analyzed_packages: List[dict]


def fetch_vulnerability_titles(qids_list):
    """
    Fetch vulnerability titles for a list of QIDs from KnowledgeBase API.
    """
    global qid_title_cache

    if not qids_list:
        return {}

    # Remove duplicates and filter out cached QIDs
    unique_qids = list(set(qids_list) - set(qid_title_cache.keys()))

    if not unique_qids:
        return qid_title_cache

    print(f"Fetching titles for {len(unique_qids)} unique QIDs...")

    # Qualys KB API configuration
    QUALYS_KB_API_URL = (
        "https://qualysapi.qg2.apps.qualys.com/api/2.0/fo/knowledge_base/vuln/"
    )
    USERNAME = os.getenv("USERNAME1")
    PASSWORD = os.getenv("PASSWORD")

    # Process QIDs in batches of 100 (API limitation)
    batch_size = 100
    headers = {"X-Requested-With": "requests"}

    for i in tqdm(
        range(0, len(unique_qids), batch_size), desc="Fetching titles", unit="batch"
    ):
        batch_qids = unique_qids[i : i + batch_size]
        qids_param = ",".join(map(str, batch_qids))

        kb_params = {
            "action": "list",
            "ids": qids_param,
            "details": "Basic",  # Get basic details including title
        }

        try:
            response = requests.post(
                QUALYS_KB_API_URL,
                auth=(USERNAME, PASSWORD),
                data=kb_params,
                headers=headers,
            )

            if response.status_code == 200:
                parse_kb_response(response.text)
            else:
                print(
                    f"Warning: Failed to fetch titles for batch {i//batch_size + 1}. Status: {response.status_code}"
                )
                # Add placeholder titles for failed QIDs
                for qid in batch_qids:
                    qid_title_cache[qid] = f"Title unavailable for QID {qid}"

            # Rate limiting - small delay between requests
            time.sleep(0.5)

        except requests.exceptions.RequestException as e:
            print(f"Error fetching titles for batch {i//batch_size + 1}: {e}")
            # Add placeholder titles for failed QIDs
            for qid in batch_qids:
                qid_title_cache[qid] = f"Error fetching title for QID {qid}"

    return qid_title_cache


def parse_kb_response(xml_data):
    """
    Parse KnowledgeBase API response to extract QID to title mappings.
    """
    global qid_title_cache

    try:
        root = ET.fromstring(xml_data)

        for vuln in root.findall(".//VULN"):
            qid = vuln.findtext("QID")
            title = vuln.findtext("TITLE")

            if qid and title:
                qid_title_cache[qid] = title.strip()

    except ET.ParseError as e:
        print(f"Error parsing KnowledgeBase response: {e}")


class AnalyzeRequest(BaseModel):
    all_components: list
    hostname: str


# SBOM Routes (unchanged)
@app.post("/api/sbom/analyze")
async def analyze_sbom(request: AnalyzeRequest, db: Session = Depends(get_db)):
    """Analyze SBOM packages and store in database"""
    try:
        analyzed_packages = asyncio.run(
            analyze_packages_batch(request.all_components, concurrency=10)
        )
        hostname = request.hostname
        packages = analyzed_packages

        # Collect all analyzed packages first
        # analyzed_packages = []
        sbom_entries = []

        print(f"Starting analysis of {len(packages)} packages for {hostname}")

        # Analyze each package and collect results
        for i, package_result in enumerate(packages, 1):
            print(
                f"Analyzing package {i}/{len(packages)}: {package_result.get('Name', 'Unknown')}"
            )

            # Call OpenAI for vulnerability analysis
            # analysis_result = await analyze_package_vulnerabilities(package)
            # analyzed_packages.append(analysis_result)

            # Prepare database entry (don't add to session yet)
            sbom_entry = SBOMData(
                hostname=hostname,
                package_name=package_result.get("Name", ""),
                package_type=package_result.get("Variation", ""),
                installed_version=package_result.get("Installed Version", ""),
                latest_version=package_result.get("Latest Version", ""),
                license=package_result.get("License", ""),
                vulnerabilities=package_result.get("Vulnerabilities", ""),
                suggestions=package_result.get("Suggestions", ""),
                license_summary=package_result.get("License Summary", ""),
                verdict=package_result.get("Verdict", ""),
                package_url=package_result.get("Package URL", ""),
                distribution_url=package_result.get("Distribution URL", ""),
            )
            sbom_entries.append(sbom_entry)

        # Bulk insert all entries at once
        print(f"Bulk inserting {len(sbom_entries)} entries to database")
        db.add_all(sbom_entries)
        db.commit()
        print("Successfully committed all entries")

        return {
            "status": "success",
            "message": f"Analyzed {len(analyzed_packages)} packages for {hostname}",
            "data": analyzed_packages,  # Return actual data instead of string
        }

    except Exception as e:
        db.rollback()
        print(f"Error during analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/api/sbom/data")
async def get_sbom_data(hostname: Optional[str] = None, db: Session = Depends(get_db)):
    """Get SBOM data with optional hostname filter"""
    query = db.query(SBOMData)
    if hostname:
        query = query.filter(SBOMData.hostname == hostname)

    data = query.order_by(SBOMData.created_at.desc()).all()

    return {
        "status": "success",
        "data": [
            {
                "id": item.id,
                "hostname": item.hostname,
                "package_name": item.package_name,
                "package_type": item.package_type,
                "installed_version": item.installed_version,
                "latest_version": item.latest_version,
                "license": item.license,
                "vulnerabilities": item.vulnerabilities,
                "suggestions": item.suggestions,
                "license_summary": item.license_summary,
                "verdict": item.verdict,
                "package_url": item.package_url,
                "distribution_url": item.distribution_url,
                "created_at": item.created_at.isoformat() if item.created_at else None,
            }
            for item in data
        ],
    }


@app.post("/api/sbom/bulk-insert")
async def bulk_insert_analyzed_sbom(request: dict, db: Session = Depends(get_db)):
    """Bulk insert pre-analyzed SBOM data into database (skip duplicates)."""
    try:
        hostname = request.get("hostname")
        analyzed_packages = request.get("analyzed_packages", [])

        if not hostname or not analyzed_packages:
            raise HTTPException(
                status_code=400, detail="hostname and analyzed_packages are required"
            )

        print(
            f"Bulk inserting {len(analyzed_packages)} analyzed components for {hostname}"
        )

        successful_entries, skipped_entries, failed_entries = 0, 0, 0

        for analysis_result in analyzed_packages:
            try:
                sbom_entry = SBOMData(
                    hostname=hostname,
                    package_name=analysis_result.get("Name", ""),
                    package_type=analysis_result.get("Variation", ""),
                    installed_version=analysis_result.get("Installed Version", ""),
                    latest_version=analysis_result.get("Latest Version", ""),
                    license=analysis_result.get("License", ""),
                    vulnerabilities=analysis_result.get("Vulnerabilities", ""),
                    suggestions=analysis_result.get("Suggestions", ""),
                    license_summary=analysis_result.get("License Summary", ""),
                    verdict=analysis_result.get("Verdict", ""),
                    package_url=analysis_result.get("Package URL", ""),
                    distribution_url=analysis_result.get("Distribution URL", ""),
                )
                db.add(sbom_entry)
                db.commit()
                successful_entries += 1

            except IntegrityError:
                db.rollback()
                skipped_entries += 1  # duplicate → skip

            except Exception as e:
                db.rollback()
                print(f"Error inserting {analysis_result.get('Name', 'Unknown')}: {e}")
                failed_entries += 1

        return {
            "status": "success",
            "message": f"Processed {len(analyzed_packages)} components "
            f"({successful_entries} new, {skipped_entries} skipped, {failed_entries} failed)",
            "new_entries": successful_entries,
            "skipped_entries": skipped_entries,
            "failed_entries": failed_entries,
            "total_processed": len(analyzed_packages),
        }

    except Exception as e:
        db.rollback()
        print(f"Error during bulk insert: {e}")
        raise HTTPException(status_code=500, detail=f"Bulk insert failed: {str(e)}")


@app.get("/api/sbom/export")
async def export_sbom_data(
    hostname: Optional[str] = None, db: Session = Depends(get_db)
):
    """Export SBOM data to Excel"""
    query = db.query(SBOMData)
    if hostname:
        query = query.filter(SBOMData.hostname == hostname)

    data = query.all()

    # Convert to DataFrame
    df = pd.DataFrame(
        [
            {
                "Hostname": item.hostname,
                "Package Name": item.package_name,
                "Package Type": item.package_type,
                "Installed Version": item.installed_version,
                "Latest Version": item.latest_version,
                "License": item.license,
                "Vulnerabilities": item.vulnerabilities,
                "Suggestions": item.suggestions,
                "License Summary": item.license_summary,
                "Verdict": item.verdict,
                "Package URL": item.package_url,
                "Distribution URL": item.distribution_url,
                "Created At": item.created_at.isoformat() if item.created_at else None,
            }
            for item in data
        ]
    )

    # Save to Excel
    filename = f"sbom_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    df.to_excel(filename, index=False)

    return FileResponse(filename, filename=filename)


# Qualys Routes
@app.post("/api/qualys/import")
async def import_qualys_data(db: Session = Depends(get_db)):
    """Import Qualys vulnerability data"""
    try:
        # Qualys API configuration
        QUALYS_API_URL = os.getenv("QUALYS_API_URL")
        USERNAME = os.getenv("USERNAME1")
        PASSWORD = os.getenv("PASSWORD")

        if not all([QUALYS_API_URL, USERNAME, PASSWORD]):
            raise HTTPException(
                status_code=400, detail="Qualys API credentials not configured"
            )

        # Fetch all detections handling pagination
        all_detections = await fetch_all_qualys_detections(
            QUALYS_API_URL, USERNAME, PASSWORD
        )

        if not all_detections:
            raise HTTPException(status_code=404, detail="No Qualys data found")

        # Insert new data
        new_records = 0
        for detection in all_detections:
            # Check if record already exists (avoid duplicates)
            existing = (
                db.query(QualysData)
                .filter(
                    QualysData.asset_id == detection.get("AssetID"),
                    QualysData.qid == detection.get("QID"),
                    QualysData.unique_vuln_id == detection.get("UniqueVulnID"),
                )
                .first()
            )

            if not existing:
                qualys_entry = QualysData(
                    asset_id=detection.get("AssetID"),
                    asset_ip=detection.get("AssetIP"),
                    asset_name=detection.get("AssetName"),
                    netbios=detection.get("NetBIOS"),
                    os=detection.get("OS"),
                    asset_tags=detection.get("AssetTags"),
                    last_scan_datetime=parse_datetime(
                        detection.get("LastScanDateTime")
                    ),
                    unique_vuln_id=detection.get("UniqueVulnID"),
                    qid=detection.get("QID"),
                    vulnerability_title=detection.get(
                        "VulnerabilityTitle", ""
                    ),  # Added title
                    vuln_type=detection.get("Type"),
                    severity=parse_int(detection.get("Severity")),
                    port=detection.get("Port"),
                    protocol=detection.get("Protocol"),
                    ssl=detection.get("SSL"),
                    status=detection.get("Status"),
                    first_found_datetime=parse_datetime(
                        detection.get("FirstFoundDateTime")
                    ),
                    last_found_datetime=parse_datetime(
                        detection.get("LastFoundDateTime")
                    ),
                    last_test_datetime=parse_datetime(
                        detection.get("LastTestDateTime")
                    ),
                    last_update_datetime=parse_datetime(
                        detection.get("LastUpdateDateTime")
                    ),
                    times_found=parse_int(detection.get("TimesFound")),
                    results=detection.get("Results"),
                    qds=parse_float(detection.get("QDS")),
                    qds_severity=detection.get("QDSSeverity"),
                    qds_factors=detection.get("QDSFactors"),
                )
                db.add(qualys_entry)
                new_records += 1

        db.commit()

        return {
            "status": "success",
            "message": f"Imported {new_records} new vulnerability records out of {len(all_detections)} total",
            "data": new_records,
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Import failed: {str(e)}")


async def fetch_all_qualys_detections(api_url: str, username: str, password: str):
    """Fetch all Qualys detections handling pagination"""
    all_detections = []
    next_url = None
    page_count = 1

    REQUEST_PARAMS = {
        "action": "list",
        "output_format": "XML",
        "truncation_limit": 1000,  # Increased for better performance
        "show_qds": "1",
        "show_qds_factors": "1",
    }

    while True:
        print(f"Fetching Qualys data page {page_count}...")

        try:
            if next_url:
                # Use the next URL provided by Qualys for pagination
                headers = {"X-Requested-With": "requests"}
                response = requests.get(
                    next_url, auth=(username, password), headers=headers, timeout=300
                )
            else:
                # First request
                headers = {"X-Requested-With": "requests"}
                response = requests.post(
                    api_url,
                    auth=(username, password),
                    data=REQUEST_PARAMS,
                    headers=headers,
                    timeout=300,
                )

            if response.status_code != 200:
                print(f"Qualys API error: {response.status_code} - {response.text}")
                break

            # Parse the current page
            detections = parse_qualys_xml(response.text)
            if detections:
                all_detections.extend(detections)
                print(f"Page {page_count}: Found {len(detections)} detections")

            # Check for truncation and get next URL
            next_url = handle_qualys_truncation(response.text)

            if not next_url:
                break

            page_count += 1

            # Safety break to avoid infinite loops
            if page_count > 100:
                print("Warning: Reached maximum page limit (100). Breaking.")
                break

        except Exception as e:
            print(f"Error fetching Qualys page {page_count}: {e}")
            break

    print(f"Total Qualys detections fetched: {len(all_detections)}")
    return all_detections


def handle_qualys_truncation(xml_data):
    """Check if the response is truncated and return the next URL if needed"""
    try:
        root = ET.fromstring(xml_data)
        warning = root.find(".//WARNING")

        if warning is not None:
            code = warning.findtext("CODE")
            text = warning.findtext("TEXT")
            next_url = warning.findtext("URL")

            if code == "1980":  # Truncation warning code
                print(f"Warning: {text}")
                print(f"Next URL: {next_url}")
                return next_url
    except Exception as e:
        print(f"Error checking truncation: {e}")

    return None


@app.get("/api/qualys/data")
async def get_qualys_data(
    critical_only: bool = False,
    limit: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """Get Qualys data with optional filtering"""
    query = db.query(QualysData)

    if critical_only:
        query = query.filter(QualysData.qds_severity == "CRITICAL")

    if limit:
        query = query.limit(limit)

    data = query.order_by(QualysData.created_at.desc()).all()

    return {
        "status": "success",
        "data": [
            {
                "id": item.id,
                "asset_id": item.asset_id,
                "asset_ip": item.asset_ip,
                "asset_name": item.asset_name,
                "netbios": item.netbios,
                "os": item.os,
                "asset_tags": item.asset_tags,
                "last_scan_datetime": (
                    item.last_scan_datetime.isoformat()
                    if item.last_scan_datetime
                    else None
                ),
                "unique_vuln_id": item.unique_vuln_id,
                "qid": item.qid,
                "vulnerability_title": item.vulnerability_title,  # Added title
                "vuln_type": item.vuln_type,
                "severity": item.severity,
                "port": item.port,
                "protocol": item.protocol,
                "ssl": item.ssl,
                "status": item.status,
                "first_found_datetime": (
                    item.first_found_datetime.isoformat()
                    if item.first_found_datetime
                    else None
                ),
                "last_found_datetime": (
                    item.last_found_datetime.isoformat()
                    if item.last_found_datetime
                    else None
                ),
                "last_test_datetime": (
                    item.last_test_datetime.isoformat()
                    if item.last_test_datetime
                    else None
                ),
                "last_update_datetime": (
                    item.last_update_datetime.isoformat()
                    if item.last_update_datetime
                    else None
                ),
                "times_found": item.times_found,
                "results": item.results,
                "qds": item.qds,
                "qds_severity": item.qds_severity,
                "qds_factors": item.qds_factors,
                "created_at": item.created_at.isoformat() if item.created_at else None,
            }
            for item in data
        ],
    }


@app.get("/api/qualys/export")
async def export_qualys_data(db: Session = Depends(get_db)):
    """Export all Qualys data to Excel"""
    data = db.query(QualysData).all()

    # Convert to DataFrame
    df = pd.DataFrame(
        [
            {
                "Asset ID": item.asset_id,
                "Asset IP": item.asset_ip,
                "Asset Name": item.asset_name,
                "NetBIOS": item.netbios,
                "OS": item.os,
                "Asset Tags": item.asset_tags,
                "Last Scan DateTime": (
                    item.last_scan_datetime.isoformat()
                    if item.last_scan_datetime
                    else None
                ),
                "Unique Vuln ID": item.unique_vuln_id,
                "QID": item.qid,
                "Vulnerability Title": item.vulnerability_title,  # Added title
                "Vuln Type": item.vuln_type,
                "Severity": item.severity,
                "Port": item.port,
                "Protocol": item.protocol,
                "SSL": item.ssl,
                "Status": item.status,
                "First Found DateTime": (
                    item.first_found_datetime.isoformat()
                    if item.first_found_datetime
                    else None
                ),
                "Last Found DateTime": (
                    item.last_found_datetime.isoformat()
                    if item.last_found_datetime
                    else None
                ),
                "Last Test DateTime": (
                    item.last_test_datetime.isoformat()
                    if item.last_test_datetime
                    else None
                ),
                "Last Update DateTime": (
                    item.last_update_datetime.isoformat()
                    if item.last_update_datetime
                    else None
                ),
                "Times Found": item.times_found,
                "Results": item.results,
                "QDS": item.qds,
                "QDS Severity": item.qds_severity,
                "QDS Factors": item.qds_factors,
                "Created At": item.created_at.isoformat() if item.created_at else None,
            }
            for item in data
        ]
    )

    # Save to Excel
    filename = f"qualys_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    df.to_excel(filename, index=False)

    return FileResponse(filename, filename=filename)


# Package management routes (from original server)
@app.post("/api/get-latest-version", response_model=VersionResponse)
async def get_latest_version(package_request: PackageRequest):
    """Get latest version of a package"""
    # Implementation from original server
    pkg_name = package_request.package_name
    pkg_type = package_request.package_type.lower()

    latest_version = ""
    try:
        if pkg_type == "pypi":
            resp = requests.get(f"https://pypi.org/pypi/{pkg_name}/json", timeout=5)
            if resp.status_code == 200:
                latest_version = resp.json()["info"]["version"]
        elif pkg_type == "npm":
            resp = requests.get(f"https://registry.npmjs.org/{pkg_name}", timeout=5)
            if resp.status_code == 200:
                latest_version = resp.json()["dist-tags"]["latest"]
        # Add other package types...
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to fetch version: {str(e)}"
        )

    return VersionResponse(latest_version=latest_version)


@app.post("/api/get-license", response_model=LicenseResponse)
async def get_license(package_request: PackageRequest):
    """Get license information for a package"""
    # Implementation from original server
    return LicenseResponse(license="Implementation needed")


def parse_qualys_xml(xml_data):
    """Parse Qualys XML response and extract vulnerability data with titles"""
    try:
        root = ET.fromstring(xml_data)
        results = []
        unique_qids = set()

        hosts = root.findall(".//HOST")

        # First pass: collect unique QIDs
        print("Collecting unique QIDs...")
        for host in hosts:
            detections = host.findall("DETECTION_LIST/DETECTION")
            for det in detections:
                qid = det.findtext("QID")
                if qid:
                    unique_qids.add(qid)

        # Fetch titles for all unique QIDs
        if unique_qids:
            fetch_vulnerability_titles(list(unique_qids))

        # Second pass: parse all detection data
        print("Parsing host detection data...")
        for host in tqdm(hosts, desc="Parsing hosts", unit="host"):
            asset_id = host.findtext("ID")
            asset_ip = host.findtext("IP")
            asset_name = host.findtext("DNS")
            netbios = host.findtext("NETBIOS")
            os_info = host.findtext("OS")

            # Handle asset tags if they exist
            asset_tags_elems = host.findall("TAG_LIST/TAG")
            asset_tags = (
                ",".join(
                    [
                        tag.findtext("NAME")
                        for tag in asset_tags_elems
                        if tag.findtext("NAME")
                    ]
                )
                if asset_tags_elems
                else ""
            )

            # Get last scan information
            last_scan_datetime = host.findtext("LAST_SCAN_DATETIME")
            last_vm_scanned_date = host.findtext("LAST_VM_SCANNED_DATE")

            detections = host.findall("DETECTION_LIST/DETECTION")
            for det in detections:
                qid = det.findtext("QID")
                unique_vuln_id = det.findtext("UNIQUE_VULN_ID")
                vuln_type = det.findtext("TYPE")
                severity = det.findtext("SEVERITY")
                port = det.findtext("PORT")
                protocol = det.findtext("PROTOCOL")
                ssl = det.findtext("SSL")
                status = det.findtext("STATUS")
                first_found = det.findtext("FIRST_FOUND_DATETIME")
                last_found = det.findtext("LAST_FOUND_DATETIME")
                last_test = det.findtext("LAST_TEST_DATETIME")
                last_update = det.findtext("LAST_UPDATE_DATETIME")
                times_found = det.findtext("TIMES_FOUND")
                results_text = det.findtext("RESULTS")

                # Get vulnerability title from cache
                vuln_title = qid_title_cache.get(qid, f"Title not found for QID {qid}")

                # QDS (Qualys Detection Score) if available
                qds_elem = det.find("QDS")
                qds = qds_elem.text if qds_elem is not None else ""
                qds_severity = qds_elem.get("severity") if qds_elem is not None else ""

                # QDS Factors if available
                qds_factors = []
                qds_factors_elem = det.find("QDS_FACTORS")
                if qds_factors_elem is not None:
                    for factor in qds_factors_elem.findall("QDS_FACTOR"):
                        factor_name = factor.get("name")
                        factor_value = factor.text
                        if factor_name and factor_value:
                            qds_factors.append(f"{factor_name}:{factor_value}")
                qds_factors_str = "; ".join(qds_factors)

                results.append(
                    {
                        "AssetID": asset_id,
                        "AssetIP": asset_ip,
                        "AssetName": asset_name,
                        "NetBIOS": netbios,
                        "OS": os_info,
                        "AssetTags": asset_tags,
                        "LastScanDateTime": last_scan_datetime,
                        "LastVMScannedDate": last_vm_scanned_date,
                        "UniqueVulnID": unique_vuln_id,
                        "QID": qid,
                        "VulnerabilityTitle": vuln_title,  # Added title
                        "Type": vuln_type,
                        "Severity": severity,
                        "Port": port,
                        "Protocol": protocol,
                        "SSL": ssl,
                        "Status": status,
                        "FirstFoundDateTime": first_found,
                        "LastFoundDateTime": last_found,
                        "LastTestDateTime": last_test,
                        "LastUpdateDateTime": last_update,
                        "TimesFound": times_found,
                        "Results": results_text,
                        "QDS": qds,
                        "QDSSeverity": qds_severity,
                        "QDSFactors": qds_factors_str,
                    }
                )

        return results

    except Exception as e:
        print(f"Error parsing Qualys XML: {e}")
        return []


def parse_datetime(date_str):
    """Parse datetime string from Qualys API"""
    if not date_str:
        return None
    try:
        # Handle different datetime formats from Qualys
        # Format: 2023-12-01T10:30:45Z or 2023-12-01T10:30:45
        if "T" in date_str:
            if date_str.endswith("Z"):
                return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            else:
                return datetime.fromisoformat(date_str)
        else:
            # Handle date-only format: 2023-12-01
            return datetime.strptime(date_str, "%Y-%m-%d")
    except Exception as e:
        print(f"Error parsing datetime '{date_str}': {e}")
        return None


def parse_int(int_str):
    """Parse integer string safely"""
    if not int_str:
        return None
    try:
        return int(int_str)
    except (ValueError, TypeError):
        return None


def parse_float(float_str):
    """Parse float string safely"""
    if not float_str:
        return None
    try:
        return float(float_str)
    except (ValueError, TypeError):
        return None


@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "Unified Security Dashboard API is running"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8058)
