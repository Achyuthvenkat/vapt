#!/usr/bin/env python3
"""
Standalone Qualys Data Import Script
This script fetches data from Qualys VMDR API and stores it in the database
"""

import requests
import xml.etree.ElementTree as ET
import os
import sys
from datetime import datetime
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from tqdm import tqdm
import pymysql

# Load environment variables
load_dotenv()

# Import database models
sys.path.append('.')
try:
    from main_server import QualysData, Base
except ImportError:
    print("❌ Error: Could not import database models from main_server.py")
    print("Make sure main_server.py is in the same directory")
    sys.exit(1)

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Qualys configuration
QUALYS_API_URL = os.getenv('QUALYS_API_URL')
USERNAME = os.getenv('USERNAME1')  
PASSWORD = os.getenv('PASSWORD')

# Request parameters
REQUEST_PARAMS = {
    'action': 'list',
    'output_format': 'XML',
    'truncation_limit': 1000,  # Higher limit for better performance
    'show_qds': '1',
    'show_qds_factors': '1',
    # Uncomment and modify these filters as needed:
    # 'status': 'Active,New,Re-Opened',
    # 'detection_updated_since': '2024-01-01T00:00:00Z',
    # 'vm_processed_after': '2024-01-01T00:00:00Z'
}

def check_configuration():
    """Check if all required configuration is present"""
    if not all([QUALYS_API_URL, USERNAME, PASSWORD]):
        print("❌ Missing Qualys configuration!")
        print("Please ensure the following environment variables are set:")
        print("- QUALYS_API_URL")
        print("- USERNAME1")
        print("- PASSWORD")
        return False
    
    # Test database connection
    try:
        engine.connect()
        print("✅ Database connection successful")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False
    
    return True

def fetch_qualys_detection_page(url=None, params=None):
    """Fetch a single page of Qualys detection data"""
    headers = {'X-Requested-With': 'requests'}
    
    try:
        if url:
            # Use provided URL for pagination
            response = requests.get(url, auth=(USERNAME, PASSWORD), headers=headers, timeout=300)
        else:
            # First request with parameters
            response = requests.post(
                QUALYS_API_URL,
                auth=(USERNAME, PASSWORD),
                data=params or REQUEST_PARAMS,
                headers=headers,
                timeout=300
            )
        
        if response.status_code != 200:
            print(f"❌ API call failed with status code {response.status_code}")
            print(f"Response: {response.text}")
            return None, None
        
        return response.text, response.status_code
        
    except Exception as e:
        print(f"❌ Error fetching Qualys data: {e}")
        return None, None

def parse_qualys_xml(xml_data):
    """Parse Qualys XML response and extract vulnerability data"""
    try:
        root = ET.fromstring(xml_data)
        results = []
        
        hosts = root.findall('.//HOST')
        
        for host in hosts:
            asset_id = host.findtext('ID')
            asset_ip = host.findtext('IP')
            asset_name = host.findtext('DNS')
            netbios = host.findtext('NETBIOS')
            os_info = host.findtext('OS')
            
            # Handle asset tags
            asset_tags_elems = host.findall('TAG_LIST/TAG')
            asset_tags = ','.join([tag.findtext('NAME') for tag in asset_tags_elems if tag.findtext('NAME')]) if asset_tags_elems else ''
            
            last_scan_datetime = host.findtext('LAST_SCAN_DATETIME')
            
            detections = host.findall('DETECTION_LIST/DETECTION')
            for det in detections:
                qid = det.findtext('QID')
                unique_vuln_id = det.findtext('UNIQUE_VULN_ID')
                vuln_type = det.findtext('TYPE')
                severity = det.findtext('SEVERITY')
                port = det.findtext('PORT')
                protocol = det.findtext('PROTOCOL')
                ssl = det.findtext('SSL')
                status = det.findtext('STATUS')
                first_found = det.findtext('FIRST_FOUND_DATETIME')
                last_found = det.findtext('LAST_FOUND_DATETIME')
                last_test = det.findtext('LAST_TEST_DATETIME')
                last_update = det.findtext('LAST_UPDATE_DATETIME')
                times_found = det.findtext('TIMES_FOUND')
                results_text = det.findtext('RESULTS')
                
                # QDS information
                qds_elem = det.find('QDS')
                qds = qds_elem.text if qds_elem is not None else ''
                qds_severity = qds_elem.get('severity') if qds_elem is not None else ''
                
                # QDS Factors
                qds_factors = []
                qds_factors_elem = det.find('QDS_FACTORS')
                if qds_factors_elem is not None:
                    for factor in qds_factors_elem.findall('QDS_FACTOR'):
                        factor_name = factor.get('name')
                        factor_value = factor.text
                        if factor_name and factor_value:
                            qds_factors.append(f"{factor_name}:{factor_value}")
                qds_factors_str = '; '.join(qds_factors)
                
                results.append({
                    'AssetID': asset_id,
                    'AssetIP': asset_ip,
                    'AssetName': asset_name,
                    'NetBIOS': netbios,
                    'OS': os_info,
                    'AssetTags': asset_tags,
                    'LastScanDateTime': last_scan_datetime,
                    'UniqueVulnID': unique_vuln_id,
                    'QID': qid,
                    'Type': vuln_type,
                    'Severity': severity,
                    'Port': port,
                    'Protocol': protocol,
                    'SSL': ssl,
                    'Status': status,
                    'FirstFoundDateTime': first_found,
                    'LastFoundDateTime': last_found,
                    'LastTestDateTime': last_test,
                    'LastUpdateDateTime': last_update,
                    'TimesFound': times_found,
                    'Results': results_text,
                    'QDS': qds,
                    'QDSSeverity': qds_severity,
                    'QDSFactors': qds_factors_str
                })
        
        return results
        
    except Exception as e:
        print(f"❌ Error parsing Qualys XML: {e}")
        return []

def handle_truncation(xml_data):
    """Check if response is truncated and return next URL"""
    try:
        root = ET.fromstring(xml_data)
        warning = root.find('.//WARNING')
        
        if warning is not None:
            code = warning.findtext('CODE')
            text = warning.findtext('TEXT')
            next_url = warning.findtext('URL')
            
            if code == '1980':  # Truncation warning
                print(f"⚠️ Response truncated: {text}")
                return next_url
                
    except Exception as e:
        print(f"Error checking truncation: {e}")
    
    return None

def parse_datetime(date_str):
    """Parse datetime string from Qualys"""
    if not date_str:
        return None
    try:
        if 'T' in date_str:
            if date_str.endswith('Z'):
                return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            else:
                return datetime.fromisoformat(date_str)
        else:
            return datetime.strptime(date_str, '%Y-%m-%d')
    except:
        return None

def parse_int(int_str):
    """Parse integer safely"""
    if not int_str:
        return None
    try:
        return int(int_str)
    except:
        return None

def parse_float(float_str):
    """Parse float safely"""
    if not float_str:
        return None
    try:
        return float(float_str)
    except:
        return None

def fetch_all_qualys_data():
    """Fetch all Qualys detection data handling pagination"""
    all_detections = []
    next_url = None
    page_count = 1
    
    print("🔍 Starting Qualys data fetch...")
    
    while True:
        print(f"📄 Fetching page {page_count}...")
        
        # Fetch current page
        if next_url:
            xml_data, status_code = fetch_qualys_detection_page(url=next_url)
        else:
            xml_data, status_code = fetch_qualys_detection_page(params=REQUEST_PARAMS)
        
        if not xml_data:
            print("❌ Failed to fetch data")
            break
        
        # Parse current page
        detections = parse_qualys_xml(xml_data)
        if detections:
            all_detections.extend(detections)
            print(f"✅ Page {page_count}: Found {len(detections)} detections")
        else:
            print(f"⚠️ Page {page_count}: No detections found")
        
        # Check for pagination
        next_url = handle_truncation(xml_data)
        if not next_url:
            print("✅ Reached end of data")
            break
        
        page_count += 1
        
        # Safety limit
        if page_count > 100:
            print("⚠️ Reached page limit (100), stopping")
            break
    
    print(f"📊 Total detections fetched: {len(all_detections)}")
    return all_detections

def save_to_database(detections, update_existing=False):
    """Save detections to database"""
    db = SessionLocal()
    
    try:
        print(f"💾 Saving {len(detections)} detections to database...")
        
        if not update_existing:
            # Clear existing data
            print("🗑️ Clearing existing Qualys data...")
            db.query(QualysData).delete()
            db.commit()
        
        new_records = 0
        updated_records = 0
        
        for detection in tqdm(detections, desc="Saving to database"):
            if update_existing:
                # Check if record exists
                existing = db.query(QualysData).filter(
                    QualysData.asset_id == detection.get('AssetID'),
                    QualysData.qid == detection.get('QID'),
                    QualysData.unique_vuln_id == detection.get('UniqueVulnID')
                ).first()
                
                if existing:
                    # Update existing record
                    existing.asset_ip = detection.get('AssetIP')
                    existing.asset_name = detection.get('AssetName')
                    existing.netbios = detection.get('NetBIOS')
                    existing.os = detection.get('OS')
                    existing.asset_tags = detection.get('AssetTags')
                    existing.last_scan_datetime = parse_datetime(detection.get('LastScanDateTime'))
                    existing.vuln_type = detection.get('Type')
                    existing.severity = parse_int(detection.get('Severity'))
                    existing.port = detection.get('Port')
                    existing.protocol = detection.get('Protocol')
                    existing.ssl = detection.get('SSL')
                    existing.status = detection.get('Status')
                    existing.first_found_datetime = parse_datetime(detection.get('FirstFoundDateTime'))
                    existing.last_found_datetime = parse_datetime(detection.get('LastFoundDateTime'))
                    existing.last_test_datetime = parse_datetime(detection.get('LastTestDateTime'))
                    existing.last_update_datetime = parse_datetime(detection.get('LastUpdateDateTime'))
                    existing.times_found = parse_int(detection.get('TimesFound'))
                    existing.results = detection.get('Results')
                    existing.qds = parse_float(detection.get('QDS'))
                    existing.qds_severity = detection.get('QDSSeverity')
                    existing.qds_factors = detection.get('QDSFactors')
                    updated_records += 1
                    continue
            
            # Create new record
            qualys_entry = QualysData(
                asset_id=detection.get('AssetID'),
                asset_ip=detection.get('AssetIP'),
                asset_name=detection.get('AssetName'),
                netbios=detection.get('NetBIOS'),
                os=detection.get('OS'),
                asset_tags=detection.get('AssetTags'),
                last_scan_datetime=parse_datetime(detection.get('LastScanDateTime')),
                unique_vuln_id=detection.get('UniqueVulnID'),
                qid=detection.get('QID'),
                vuln_type=detection.get('Type'),
                severity=parse_int(detection.get('Severity')),
                port=detection.get('Port'),
                protocol=detection.get('Protocol'),
                ssl=detection.get('SSL'),
                status=detection.get('Status'),
                first_found_datetime=parse_datetime(detection.get('FirstFoundDateTime')),
                last_found_datetime=parse_datetime(detection.get('LastFoundDateTime')),
                last_test_datetime=parse_datetime(detection.get('LastTestDateTime')),
                last_update_datetime=parse_datetime(detection.get('LastUpdateDateTime')),
                times_found=parse_int(detection.get('TimesFound')),
                results=detection.get('Results'),
                qds=parse_float(detection.get('QDS')),
                qds_severity=detection.get('QDSSeverity'),
                qds_factors=detection.get('QDSFactors')
            )
            db.add(qualys_entry)
            new_records += 1
        
        db.commit()
        
        if update_existing:
            print(f"✅ Database updated: {new_records} new records, {updated_records} updated records")
        else:
            print(f"✅ Database populated with {new_records} records")
        
        return new_records, updated_records
        
    except Exception as e:
        db.rollback()
        print(f"❌ Database error: {e}")
        return 0, 0
    finally:
        db.close()

def export_to_csv(detections, filename=None):
    """Export detections to CSV file"""
    if not filename:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"qualys_export_{timestamp}.csv"
    
    try:
        import pandas as pd
        
        # Convert to DataFrame
        df = pd.DataFrame(detections)
        
        # Rename columns for better readability
        column_mapping = {
            'AssetID': 'Asset ID',
            'AssetIP': 'Asset IP',
            'AssetName': 'Asset Name',
            'NetBIOS': 'NetBIOS',
            'OS': 'Operating System',
            'AssetTags': 'Asset Tags',
            'LastScanDateTime': 'Last Scan',
            'UniqueVulnID': 'Unique Vuln ID',
            'QID': 'QID',
            'Type': 'Vulnerability Type',
            'Severity': 'Severity',
            'Port': 'Port',
            'Protocol': 'Protocol',
            'SSL': 'SSL',
            'Status': 'Status',
            'FirstFoundDateTime': 'First Found',
            'LastFoundDateTime': 'Last Found',
            'LastTestDateTime': 'Last Test',
            'LastUpdateDateTime': 'Last Update',
            'TimesFound': 'Times Found',
            'Results': 'Results',
            'QDS': 'QDS Score',
            'QDSSeverity': 'QDS Severity',
            'QDSFactors': 'QDS Factors'
        }
        
        df.rename(columns=column_mapping, inplace=True)
        df.to_csv(filename, index=False)
        print(f"📄 Data exported to {filename}")
        return filename
        
    except Exception as e:
        print(f"❌ Export failed: {e}")
        return None

def show_summary(detections):
    """Show summary statistics"""
    if not detections:
        print("📊 No data to summarize")
        return
    
    print("\n📊 QUALYS DATA SUMMARY")
    print("=" * 50)
    
    # Basic counts
    total_detections = len(detections)
    unique_assets = len(set(d.get('AssetID') for d in detections if d.get('AssetID')))
    unique_qids = len(set(d.get('QID') for d in detections if d.get('QID')))
    
    print(f"Total Detections: {total_detections}")
    print(f"Unique Assets: {unique_assets}")
    print(f"Unique QIDs: {unique_qids}")
    
    # Severity breakdown
    severity_counts = {}
    qds_severity_counts = {}
    status_counts = {}
    
    for detection in detections:
        # Severity level
        severity = detection.get('Severity', 'Unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # QDS Severity
        qds_severity = detection.get('QDSSeverity', 'Unknown')
        qds_severity_counts[qds_severity] = qds_severity_counts.get(qds_severity, 0) + 1
        
        # Status
        status = detection.get('Status', 'Unknown')
        status_counts[status] = status_counts.get(status, 0) + 1
    
    print(f"\nSeverity Distribution:")
    for severity, count in sorted(severity_counts.items()):
        print(f"  {severity}: {count}")
    
    print(f"\nQDS Severity Distribution:")
    for qds_severity, count in sorted(qds_severity_counts.items()):
        print(f"  {qds_severity}: {count}")
    
    print(f"\nStatus Distribution:")
    for status, count in sorted(status_counts.items()):
        print(f"  {status}: {count}")
    
    print("=" * 50)

def main():
    """Main function"""
    print("🔐 Qualys Data Import Tool")
    print("=" * 40)
    
    # Check configuration
    if not check_configuration():
        print("❌ Configuration check failed")
        return
    
    # Ask user what to do
    print("\nWhat would you like to do?")
    print("1. Import fresh data (clear existing)")
    print("2. Update existing data (merge)")
    print("3. Export existing data to CSV")
    print("4. Show database summary")
    print("5. Test API connection")
    print("6. Exit")
    
    choice = input("\nEnter your choice (1-6): ").strip()
    
    if choice == '1':
        # Fresh import
        print("\n🔄 Starting fresh import...")
        detections = fetch_all_qualys_data()
        
        if detections:
            show_summary(detections)
            
            # Save to database
            new_records, _ = save_to_database(detections, update_existing=False)
            
            # Ask if user wants CSV export
            if input("\nExport to CSV? (y/n): ").lower() == 'y':
                export_to_csv(detections)
        else:
            print("❌ No data fetched")
    
    elif choice == '2':
        # Update existing
        print("\n🔄 Starting update import...")
        detections = fetch_all_qualys_data()
        
        if detections:
            show_summary(detections)
            new_records, updated_records = save_to_database(detections, update_existing=True)
        else:
            print("❌ No data fetched")
    
    elif choice == '3':
        # Export existing data
        print("\n📤 Exporting existing database data...")
        db = SessionLocal()
        try:
            # Get all records from database
            records = db.query(QualysData).all()
            
            if records:
                # Convert to dict format
                detections = []
                for record in records:
                    detections.append({
                        'AssetID': record.asset_id,
                        'AssetIP': record.asset_ip,
                        'AssetName': record.asset_name,
                        'NetBIOS': record.netbios,
                        'OS': record.os,
                        'AssetTags': record.asset_tags,
                        'LastScanDateTime': record.last_scan_datetime.isoformat() if record.last_scan_datetime else '',
                        'UniqueVulnID': record.unique_vuln_id,
                        'QID': record.qid,
                        'Type': record.vuln_type,
                        'Severity': record.severity,
                        'Port': record.port,
                        'Protocol': record.protocol,
                        'SSL': record.ssl,
                        'Status': record.status,
                        'FirstFoundDateTime': record.first_found_datetime.isoformat() if record.first_found_datetime else '',
                        'LastFoundDateTime': record.last_found_datetime.isoformat() if record.last_found_datetime else '',
                        'LastTestDateTime': record.last_test_datetime.isoformat() if record.last_test_datetime else '',
                        'LastUpdateDateTime': record.last_update_datetime.isoformat() if record.last_update_datetime else '',
                        'TimesFound': record.times_found,
                        'Results': record.results,
                        'QDS': record.qds,
                        'QDSSeverity': record.qds_severity,
                        'QDSFactors': record.qds_factors
                    })
                
                export_to_csv(detections)
                show_summary(detections)
            else:
                print("❌ No data found in database")
        finally:
            db.close()
    
    elif choice == '4':
        # Show summary
        print("\n📊 Database Summary...")
        db = SessionLocal()
        try:
            total_records = db.query(QualysData).count()
            critical_count = db.query(QualysData).filter(QualysData.qds_severity == 'CRITICAL').count()
            high_count = db.query(QualysData).filter(QualysData.qds_severity == 'HIGH').count()
            unique_assets = db.query(QualysData.asset_id).distinct().count()
            
            print(f"Total Records: {total_records}")
            print(f"Unique Assets: {unique_assets}")
            print(f"Critical Vulnerabilities: {critical_count}")
            print(f"High Vulnerabilities: {high_count}")
            
        except Exception as e:
            print(f"❌ Database error: {e}")
        finally:
            db.close()
    
    elif choice == '5':
        # Test API connection
        print("\n🔗 Testing Qualys API connection...")
        xml_data, status_code = fetch_qualys_detection_page(params={'action': 'list', 'output_format': 'XML', 'truncation_limit': 1})
        
        if xml_data:
            print("✅ API connection successful")
            # Try to parse a small sample
            detections = parse_qualys_xml(xml_data)
            print(f"Sample data: {len(detections)} detections found")
        else:
            print("❌ API connection failed")
    
    elif choice == '6':
        print("👋 Goodbye!")
        return
    
    else:
        print("❌ Invalid choice")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Interrupted by user")
    except Exception as e:
        print(f"💥 Unexpected error: {e}")
        import traceback
        traceback.print_exc()