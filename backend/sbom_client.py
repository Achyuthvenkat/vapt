import requests
import subprocess
import platform
import os
import re
import json
import socket
from packaging import version
from packageurl import PackageURL
from dotenv import load_dotenv
import pandas as pd
from tqdm import tqdm
from bs4 import BeautifulSoup
from pydantic import BaseModel
import asyncio
from fastapi import FastAPI, HTTPException
from main_server import analyze_packages_batch

load_dotenv()


class VersionResponse(BaseModel):
    latest_version: str


class PackageRequest(BaseModel):
    package_name: str
    package_type: str


class LicenseResponse(BaseModel):
    license: str


# Configuration
UNIFIED_SERVER_URL = os.getenv("UNIFIED_SERVER_URL")
hostname = socket.gethostname()
ip_address = socket.gethostbyname(hostname)


def check_server():
    """Check if unified server is running"""
    try:
        resp = requests.get(f"{UNIFIED_SERVER_URL}/", timeout=5)
        if resp.status_code == 200:
            print("✅ Unified server is up and running.")
            return True
    except:
        pass
    print("❌ Unified server is not reachable. Please start the server first.")
    return False


def is_outdated(installed_version, latest_version):
    """Check if installed version is outdated"""
    try:
        return version.parse(installed_version) < version.parse(latest_version)
    except:
        return False


# System detection functions (keeping original functions)
def detect_mysql_path():
    base_dirs = [r"C:/Program Files/MySQL", r"C:/Program Files (x86)/MySQL"]
    for base_dir in base_dirs:
        if os.path.exists(base_dir):
            for folder in os.listdir(base_dir):
                if folder.startswith("MySQL Server"):
                    bin_path = os.path.join(base_dir, folder, "bin")
                    if os.path.exists(os.path.join(bin_path, "mysql.exe")):
                        return bin_path
    return None


MYSQL_PATH = detect_mysql_path()


def get_os_version():
    return platform.platform()


def get_python_version():
    return platform.python_version()


def get_mysql_version():
    if not MYSQL_PATH:
        return "MySQL not found"
    try:
        output = (
            subprocess.check_output([os.path.join(MYSQL_PATH, "mysql"), "--version"])
            .decode()
            .strip()
        )
        match = re.search(r"Ver ([0-9]+\.[0-9]+\.[0-9]+)", output)
        if match:
            return match.group(1)
        else:
            return "Version not found"
    except Exception as e:
        return f"Not Found ({e})"


def get_java_version():
    try:
        output = subprocess.check_output(
            ["java", "-version"], stderr=subprocess.STDOUT
        ).decode()
        match = re.search(r'version "([^"]+)"', output)
        if match:
            version_str = match.group(1)
            if version_str.startswith("1."):
                version_str = version_str[2:]
            return version_str
        return output.split("\n")[0].strip()
    except:
        return "Not Found"


def get_node_version():
    try:
        output = subprocess.check_output(["node", "-v"]).decode().strip()
        return output.lstrip("v")
    except:
        return "Not Found"


def get_php_version():
    try:
        output = subprocess.check_output(
            ["php", "-v"], stderr=subprocess.STDOUT
        ).decode()
        match = re.search(r"PHP (\d+\.\d+\.\d+)", output)
        if match:
            return match.group(1)
        return output.split("\n")[0].strip()
    except Exception as e:
        return "Not Found"


def get_composer_version():
    try:
        output = subprocess.check_output(
            "composer -V", shell=True, stderr=subprocess.STDOUT, timeout=10
        ).decode()
        match = re.search(r"Composer version (\d+\.\d+\.\d+)", output)
        if match:
            return match.group(1)
        return output.split("\n")[0].strip()
    except Exception as e:
        return "Not Found"


def get_python_packages():
    packages = []
    try:
        output = subprocess.check_output(["pip", "list", "--format=json"]).decode()
        for pkg in json.loads(output):
            packages.append((pkg["name"], pkg["version"]))
    except Exception as e:
        print(f"Failed to get Python packages: {e}")
    return packages


def get_node_packages():
    try:
        npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
        output = subprocess.check_output(
            [npm_cmd, "list", "--json", "--depth=0", "--silent"],
            stderr=subprocess.DEVNULL,
        ).decode()

        data = json.loads(output)
        dependencies = data.get("dependencies", {})

        # return as list of (name, version) tuples
        packages = [
            (name, info.get("version", "")) for name, info in dependencies.items()
        ]
        return packages

    except Exception as e:
        print(f"Failed to get Node.js packages: {e}")
        return []


def get_java_packages():
    packages = []
    try:
        output = subprocess.check_output(
            [
                "mvn",
                "dependency:list",
                "-DincludeScope=runtime",
                "-DoutputAbsoluteArtifactFilename",
            ],
            stderr=subprocess.STDOUT,
        ).decode()

        for line in output.splitlines():
            if line.strip().startswith("[INFO]") and ":" in line:
                parts = line.strip().split()
                dep_line = parts[-1]
                dep_parts = dep_line.split(":")
                if len(dep_parts) >= 4:
                    group_id, artifact_id, packaging, version_ = dep_parts[:4]
                    packages.append((group_id, artifact_id, version_))
    except Exception as e:
        print(f"Failed to get Java packages: {e}")
    return packages


def get_php_packages():
    packages = []

    # Method 1: Try to read from composer.lock
    composer_lock_path = "composer.lock"
    if os.path.exists(composer_lock_path):
        try:
            with open(composer_lock_path, "r", encoding="utf-8") as f:
                composer_data = json.load(f)

            all_packages = composer_data.get("packages", []) + composer_data.get(
                "packages-dev", []
            )

            for package in all_packages:
                name = package.get("name", "")
                version = package.get("version", "").lstrip("v")
                if name and version:
                    packages.append((name, version))

        except Exception as e:
            print(f"Failed to read composer.lock: {e}")

    # Method 2: Fallback to composer show command
    if not packages:
        try:
            output = subprocess.check_output(
                ["composer", "show", "--format=json"], stderr=subprocess.STDOUT
            ).decode()

            composer_data = json.loads(output)
            installed = composer_data.get("installed", [])

            for package in installed:
                name = package.get("name", "")
                version = package.get("version", "").lstrip("v")
                if name and version:
                    packages.append((name, version))

        except Exception as e:
            print(f"Failed to get PHP packages via composer show: {e}")

    return packages


def fetch_composer_latest_version(package_name: str) -> str:
    """Fetch latest version of a Composer package from Packagist"""
    try:
        resp = requests.get(
            f"https://packagist.org/packages/{package_name}.json", timeout=5
        )
        if resp.status_code == 200:
            data = resp.json()
            package_data = data.get("package", {})
            versions = package_data.get("versions", {})

            if versions:
                # Get the latest stable version (exclude dev, alpha, beta, rc)
                stable_versions = []
                for version_key, version_data in versions.items():
                    if not any(
                        x in version_key.lower() for x in ["dev", "alpha", "beta", "rc"]
                    ):
                        # Clean version string
                        clean_version = version_key.lstrip("v")
                        if re.match(
                            r"^\d+\.\d+", clean_version
                        ):  # Basic version pattern
                            stable_versions.append(clean_version)

                if stable_versions:
                    # Sort by version and return the latest
                    try:
                        sorted_versions = sorted(
                            stable_versions,
                            key=lambda x: [int(i) for i in x.split(".")[:3]],
                            reverse=True,
                        )
                        return sorted_versions[0]
                    except:
                        # Fallback to string sorting if numeric sorting fails
                        return sorted(stable_versions, reverse=True)[0]

        return ""
    except Exception as e:
        print(f"Error fetching Composer version for {package_name}: {e}")
        return ""


def get_latest_version(package_request: PackageRequest):
    """
    Get the latest version of a package from various package registries

    - **package_name**: Name of the package
    - **package_type**: Type of package registry (pypi, npm, maven)
    """
    pkg_name = package_request.package_name
    pkg_type = package_request.package_type.lower()

    if pkg_type not in ["pypi", "npm", "maven", "composer"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid package_type. Must be one of: pypi, npm, maven, composer",
        )

    latest_version = ""
    try:
        if pkg_type == "pypi":
            resp = requests.get(f"https://pypi.org/pypi/{pkg_name}/json", timeout=5)
            if resp.status_code == 200:
                latest_version = resp.json()["info"]["version"]
            elif resp.status_code == 404:
                raise HTTPException(
                    status_code=404, detail=f"Package '{pkg_name}' not found on PyPI"
                )

        elif pkg_type == "npm":
            resp = requests.get(f"https://registry.npmjs.org/{pkg_name}", timeout=5)
            if resp.status_code == 200:
                latest_version = resp.json()["dist-tags"]["latest"]
            elif resp.status_code == 404:
                raise HTTPException(
                    status_code=404, detail=f"Package '{pkg_name}' not found on NPM"
                )

        elif pkg_type == "maven":
            if ":" not in pkg_name:
                raise HTTPException(
                    status_code=400,
                    detail="Maven package name must be in format 'groupId:artifactId'",
                )
            group_id, artifact_id = pkg_name.split(":")[:2]
            url = f'https://search.maven.org/solrsearch/select?q=g:"{group_id}"+AND+a:"{artifact_id}"&rows=1&wt=json'
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                docs = resp.json()["response"]["docs"]
                if docs:
                    latest_version = docs[0]["latestVersion"]
                else:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Package '{pkg_name}' not found on Maven Central",
                    )

        elif pkg_type == "composer":
            latest_version = fetch_composer_latest_version(pkg_name)
            if not latest_version:
                raise HTTPException(
                    status_code=404,
                    detail=f"Package '{pkg_name}' not found on Packagist",
                )

    except requests.RequestException as e:
        raise HTTPException(
            status_code=503, detail=f"Failed to fetch version information: {str(e)}"
        )
    except Exception as e:
        print(f"Error fetching latest version for {pkg_name}: {e}")
        raise HTTPException(
            status_code=500, detail="Internal server error while fetching version"
        )

    return VersionResponse(latest_version=latest_version)


def fetch_latest_version(package_name, package_type):
    """Fetch latest version from unified server"""
    try:
        package_data = PackageRequest(
            package_name=package_name, package_type=package_type
        )
        resp = get_latest_version(package_data)
        if resp:
            return resp.json().get("latest_version", "")
        return ""
    except:
        return ""


def fetch_license_from_libraries_io(package_name: str, package_type: str) -> str:
    """Fetch license from Libraries.io API as another fallback"""
    try:
        platform_mapping = {
            "pypi": "Pypi",
            "npm": "NPM",
            "maven": "Maven",
            "composer": "Packagist",
        }

        platform = platform_mapping.get(package_type.lower())
        if not platform:
            return ""

        url = f"https://libraries.io/api/{platform}/{package_name}"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            data = response.json()
            return data.get("normalized_licenses", [""])[0] or data.get("licenses", "")

    except Exception as e:
        print(f"Libraries.io API failed for {package_name}: {e}")

    return ""


def get_license(package_request: PackageRequest) -> LicenseResponse:
    """
    Get license information for a package from various package registries with multiple fallbacks

    - **package_name**: Name of the package
    - **package_type**: Type of package registry (pypi, npm, maven, composer)
    """
    pkg_name = package_request.package_name
    pkg_type = package_request.package_type.lower()

    if pkg_type not in ["pypi", "npm", "maven", "composer"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid package_type. Must be one of: pypi, npm, maven",
        )

    license_info = ""
    try:
        if pkg_type == "pypi":
            license_info = fetch_pypi_package_info_with_fallbacks(pkg_name)
            if not license_info:
                raise HTTPException(
                    status_code=404,
                    detail=f"License information not found for package '{pkg_name}' on PyPI",
                )

        elif pkg_type == "npm":
            resp = requests.get(f"https://registry.npmjs.org/{pkg_name}", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                license_info = data.get("license", "")

                # Fallback to GitHub
                if not license_info:
                    repo_info = data.get("repository", {})
                    if isinstance(repo_info, dict):
                        repo_url = repo_info.get("url", "")
                    else:
                        repo_url = str(repo_info) if repo_info else ""

                    if repo_url:
                        repo_url = repo_url.replace("git+", "").replace(".git", "")
                        if "github.com" in repo_url:
                            license_info = fetch_license_from_github(repo_url)

                # Libraries.io fallback
                if not license_info:
                    license_info = fetch_license_from_libraries_io(pkg_name, "npm")

            elif resp.status_code == 404:
                raise HTTPException(
                    status_code=404, detail=f"Package '{pkg_name}' not found on NPM"
                )

        elif pkg_type == "maven":
            if ":" not in pkg_name:
                raise HTTPException(
                    status_code=400,
                    detail="Maven package name must be in format 'groupId:artifactId'",
                )
            group_id, artifact_id = pkg_name.split(":")[:2]
            url = f'https://search.maven.org/solrsearch/select?q=g:"{group_id}"+AND+a:"{artifact_id}"&rows=1&wt=json'
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                docs = resp.json()["response"]["docs"]
                if docs:
                    licenses = docs[0].get("license", [])
                    if licenses:
                        license_info = ", ".join(licenses)
                    else:
                        # Libraries.io fallback for Maven
                        license_info = fetch_license_from_libraries_io(
                            pkg_name, "maven"
                        )
                else:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Package '{pkg_name}' not found on Maven Central",
                    )
        elif pkg_type == "composer":
            license_info = fetch_composer_package_info_with_fallbacks(pkg_name)
            if not license_info:
                raise HTTPException(
                    status_code=404,
                    detail=f"License information not found for package '{pkg_name}' on Packagist",
                )

    except HTTPException:
        raise  # Re-raise HTTP exceptions
    except requests.RequestException as e:
        raise HTTPException(
            status_code=503, detail=f"Failed to fetch license information: {str(e)}"
        )
    except Exception as e:
        print(f"Error fetching license for {pkg_name}: {e}")
        raise HTTPException(
            status_code=500, detail="Internal server error while fetching license"
        )

    return LicenseResponse(
        license=license_info if license_info else "License information not available"
    )


def fetch_license(package_name, package_type):
    """Fetch license from unified server"""
    try:
        package_data = PackageRequest(
            package_name=package_name, package_type=package_type
        )
        resp = get_license(package_data)
        if resp.status_code == 200:
            return resp.model_dump_json().get("license", "")
        return ""
    except:
        return ""


def extract_github_repo_from_url(url: str) -> str:
    """Extract GitHub repository path from various URL formats"""
    if not url:
        return ""

    # Handle different GitHub URL formats
    patterns = [
        r"github\.com[:/]([^/]+/[^/.]+)",
        r"github\.com/([^/]+/[^/]+)/?$",
        r"github\.com/([^/]+/[^/]+)/.*",
    ]

    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            repo_path = match.group(1)
            # Remove common suffixes
            repo_path = re.sub(r"\.git$", "", repo_path)
            repo_path = re.sub(r"/$", "", repo_path)
            return repo_path
    return ""


def fetch_pypi_package_info_with_fallbacks(package_name: str) -> str:
    """Enhanced PyPI license fetching with multiple fallbacks"""
    license_info = ""

    try:
        # Primary: PyPI JSON API
        resp = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=10)
        if resp.status_code != 200:
            return ""

        info = resp.json()["info"]

        # Method 1: License classifiers
        for classifier in info.get("classifiers", []):
            if classifier.startswith("License ::"):
                license_parts = classifier.split("::")
                if len(license_parts) >= 3:
                    license_info = license_parts[-1].strip()
                    if license_info and license_info != "Other/Proprietary License":
                        return license_info

        # Method 2: License fields
        license_info = info.get("license_expression") or info.get("license") or ""
        if license_info and license_info.strip():
            return license_info.strip()

        license_info = info.get("license") or ""
        if license_info and license_info.strip():
            return license_info.strip()

        # Method 3: Project URLs - GitHub
        project_urls = info.get("project_urls", {})
        github_urls = []

        # Collect all potential GitHub URLs
        for key, url in project_urls.items():
            if url and "github.com" in url.lower():
                github_urls.append(url)

        # Also check home_page and download_url
        for url in [info.get("home_page"), info.get("download_url")]:
            if url and "github.com" in url.lower():
                github_urls.append(url)

        # Try GitHub API for each URL
        for github_url in github_urls:
            repo_path = extract_github_repo_from_url(github_url)
            if repo_path:
                # Try GitHub API first
                github_license = fetch_license_from_github_api(repo_path)
                if github_license:
                    return github_license

                # Try raw license files

        # Method 4: Libraries.io fallback
        libraries_io_license = fetch_license_from_libraries_io(package_name, "pypi")

        if libraries_io_license:
            return libraries_io_license

        # Method 5: Try PyPI simple API for additional metadata
        simple_api_license = fetch_from_pypi_simple_api(package_name)

        if simple_api_license:
            return simple_api_license

    except Exception as e:
        print(f"Error in PyPI license fallbacks for {package_name}: {e}")

    return ""


def fetch_license_from_github_api(repo_path: str) -> str:
    """Fetch license information from GitHub API"""
    if not repo_path:
        return ""

    api_url = f"https://api.github.com/repos/{repo_path}/license"
    headers = {"Accept": "application/vnd.github.v3+json"}

    try:
        response = requests.get(api_url, headers=headers, timeout=5)
        if response.status_code == 200:
            license_info = response.json()
            if "license" in license_info and license_info["license"]:
                return license_info["license"]["spdx_id"]
    except Exception as e:
        print(f"GitHub API license fetch failed for {repo_path}: {e}")
    return ""


def fetch_license_from_github(repo_url: str) -> str:
    """Enhanced GitHub license fetching (keeping for backward compatibility)"""
    repo_path = extract_github_repo_from_url(repo_url)
    if not repo_path:
        return ""

    # Try API first
    api_license = fetch_license_from_github_api(repo_path)
    if api_license:
        return api_license

    # Try raw files
    return "Not found"


def fetch_composer_package_info_with_fallbacks(package_name: str) -> str:
    """Enhanced Composer/Packagist license fetching with multiple fallbacks"""
    license_info = ""

    try:
        # Primary: Packagist API
        resp = requests.get(
            f"https://packagist.org/packages/{package_name}.json", timeout=10
        )
        if resp.status_code != 200:
            return ""

        data = resp.json()
        package_data = data.get("package", {})

        # Method 1: Get latest version info
        versions = package_data.get("versions", {})
        if versions:
            # Get the latest non-dev version
            latest_version_key = None
            for version_key in sorted(versions.keys(), reverse=True):
                if not any(
                    x in version_key.lower() for x in ["dev", "alpha", "beta", "rc"]
                ):
                    latest_version_key = version_key
                    break

            if latest_version_key:
                version_info = versions[latest_version_key]
                license_info = version_info.get("license", [])
                if isinstance(license_info, list) and license_info:
                    license_info = ", ".join(license_info)
                elif isinstance(license_info, str) and license_info:
                    pass  # license_info is already a string
                else:
                    license_info = ""

        # Method 2: Check repository info for GitHub fallback
        if not license_info:
            repository = package_data.get("repository")
            if repository and "github.com" in repository.lower():
                github_license = fetch_license_from_github(repository)
                if github_license:
                    return github_license

        # Method 3: Libraries.io fallback
        if not license_info:
            libraries_io_license = fetch_license_from_libraries_io(
                package_name, "composer"
            )
            if libraries_io_license:
                return libraries_io_license

        return license_info if license_info else ""

    except Exception as e:
        print(f"Error in Composer license fallbacks for {package_name}: {e}")

    return ""


def fetch_from_pypi_simple_api(package_name: str) -> str:
    """Try PyPI simple API for additional package information"""
    try:
        url = f"https://pypi.org/simple/{package_name}/"
        headers = {"Accept": "application/vnd.pypi.simple.v1+json"}
        resp = requests.get(url, headers=headers, timeout=5)

        if resp.status_code == 200 and "application/json" in resp.headers.get(
            "content-type", ""
        ):
            data = resp.json()
            # This API might have different metadata structure
            # Implementation depends on what's available in the response
            pass

    except Exception as e:
        print(f"PyPI Simple API failed for {package_name}: {e}")

    return ""


def create_system_component_entry(
    name, installed_version, latest_version, license_info, component_type, download_url
):
    """Create a system component entry for vulnerability analysis"""
    return {
        "name": name,
        "version": installed_version,
        "type": component_type,
        "latest": latest_version,
        "license": license_info,
        "purl": f"pkg:generic/{name.lower()}@{installed_version}",
        "dist_url": download_url,
        "vulnerabilities": "",
    }


# Web scraping functions for latest versions (keeping from original)
def get_latest_python_version():
    try:
        url = "https://www.python.org/downloads/"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, "html.parser")
        download_button = soup.find("a", class_="button")
        if download_button:
            button_text = download_button.get_text()
            version_match = re.search(r"Python (\d+\.\d+\.\d+)", button_text)
            if version_match:
                return version_match.group(1)

        return "Version not found"

    except Exception as e:
        return f"Error fetching data: {e}"


def get_latest_nodejs_version():
    try:
        url = "https://nodejs.org/en/"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, "html.parser")
        # download_buttons = soup.find_all("a", class_=re.compile(r"home-downloadbutton"))
        # for button in download_buttons:
        #     text = button.get_text()
        #     version_match = re.search(r"v?(\d+\.\d+\.\d+)", text)
        #     if version_match:
        #         return version_match.group(1)
        # return "Version not found"
        latest_release = soup.find("span", string=re.compile(r"Latest Release"))
        version = latest_release.find_previous("span").text

        return version

    except Exception as e:
        return f"Error fetching data: {e}"


def get_java_from_oracle():
    try:
        url = "https://www.oracle.com/java/technologies/downloads/"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, "html.parser")

        version_patterns = [
            r"Java\s*(\d+)",
            r"JDK\s*(\d+)",
            r"Java\s*SE\s*(\d+)",
            r"(\d+\.\d+\.\d+)",
        ]

        for heading in soup.find_all(["h1", "h2", "h3", "span", "div"]):
            text = heading.get_text()
            for pattern in version_patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    return f"Java {match.group(1)}"

        return "Version not found on Oracle site"

    except Exception as e:
        return f"Error fetching from Oracle: {e}"


def get_mysql_from_docker_hub():
    try:
        api_url = (
            "https://hub.docker.com/v2/repositories/library/mysql/tags?page_size=100"
        )
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()

        data = response.json()

        versions = set()
        version_pattern = r"^(\d+\.\d+\.\d+)"

        for tag_info in data.get("results", []):
            tag_name = tag_info.get("name", "")
            match = re.match(version_pattern, tag_name)
            if match:
                versions.add(match.group(1))

        if versions:
            sorted_versions = sorted(
                versions, key=lambda x: [int(i) for i in x.split(".")], reverse=True
            )
            return sorted_versions[0]

        return "No versions found on Docker Hub"

    except Exception as e:
        return f"Docker Hub API Error: {e}"


def get_latest_php_version():
    try:
        url = "https://www.php.net/downloads.php"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, "html.parser")

        version_elements = soup.find_all(string=re.compile(r"\d+\.\d+\.\d+"))
        for element in version_elements:
            version_match = re.search(r"(\d+\.\d+\.\d+)", str(element))
            if version_match:
                return version_match.group(1)

        download_links = soup.find_all("a", href=re.compile(r"php-\d+\.\d+\.\d+"))
        for link in download_links:
            href = link.get("href", "")
            version_match = re.search(r"php-(\d+\.\d+\.\d+)", href)
            if version_match:
                return version_match.group(1)

        return "Version not found"

    except Exception as e:
        return f"Error fetching PHP version: {e}"


def get_latest_composer_version():
    try:
        url = "https://api.github.com/repos/composer/composer/releases/latest"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        data = response.json()
        tag_name = data.get("tag_name", "").lstrip("v")
        return tag_name if tag_name else "Version not found"

    except Exception as e:
        return f"Error fetching Composer version: {e}"


def generate_and_send_sbom():
    """Generate SBOM data and send to unified server"""
    if not check_server():
        return

    print(f"🏠 Generating SBOM for hostname: {hostname}")

    packages = []
    system_components = []

    # Get current system versions
    python_installed = get_python_version()
    java_installed = get_java_version()
    node_installed = get_node_version()
    mysql_installed = get_mysql_version()
    php_installed = get_php_version()
    composer_installed = get_composer_version()

    print("🔍 Fetching latest versions for system components...")

    # Fetch latest versions using web scraping
    python_latest = get_latest_python_version()
    print(f"  Python: {python_installed} -> {python_latest}")

    nodejs_latest = get_latest_nodejs_version()
    print(f"  Node.js: {node_installed} -> {nodejs_latest}")

    java_latest = get_java_from_oracle()
    print(f"  Java: {java_installed} -> {java_latest}")

    mysql_latest = get_mysql_from_docker_hub()
    print(f"  MySQL: {mysql_installed} -> {mysql_latest}")

    php_latest = get_latest_php_version()
    print(f"  PHP: {php_installed} -> {php_latest}")

    composer_latest = get_latest_composer_version()
    print(f"  Composer: {composer_installed} -> {composer_latest}")

    # Create system component entries
    if python_installed and python_installed != "Not Found":
        system_components.append(
            create_system_component_entry(
                "Python",
                python_installed,
                python_latest,
                "Python Software Foundation License",
                "Runtime",
                f"https://www.python.org/downloads/",
            )
        )

    if node_installed and node_installed != "Not Found":
        system_components.append(
            create_system_component_entry(
                "Node.js",
                node_installed,
                nodejs_latest,
                "MIT License",
                "Runtime",
                f"https://nodejs.org/dist/v{node_installed}/",
            )
        )

    if java_installed and java_installed != "Not Found":
        system_components.append(
            create_system_component_entry(
                "Java",
                java_installed,
                java_latest,
                "Oracle Binary Code License Agreement / OpenJDK GPL v2",
                "Runtime",
                f"https://www.oracle.com/java/technologies/downloads/",
            )
        )

    if (
        mysql_installed
        and "Not Found" not in mysql_installed
        and "MySQL not found" not in mysql_installed
    ):
        system_components.append(
            create_system_component_entry(
                "MySQL",
                mysql_installed,
                mysql_latest,
                "GPL v2 / Commercial License",
                "Database",
                f"https://dev.mysql.com/downloads/",
            )
        )

    if php_installed and php_installed != "Not Found":
        system_components.append(
            create_system_component_entry(
                "PHP",
                php_installed,
                php_latest,
                "PHP License",
                "Runtime",
                f"https://www.php.net/downloads.php",
            )
        )

    if composer_installed and composer_installed != "Not Found":
        system_components.append(
            create_system_component_entry(
                "Composer",
                composer_installed,
                composer_latest,
                "MIT License",
                "Package Manager",
                f"https://getcomposer.org/download/",
            )
        )

    # Collect package information
    print("🔍 Collecting package information...")

    print("  Fetching Python packages...")
    py_pkgs = get_python_packages()
    for name, installed in tqdm(py_pkgs, desc="Processing Python Packages"):
        latest = fetch_latest_version(name, "pypi")
        license_ = fetch_license(name, "pypi")
        purl = PackageURL(type="pypi", name=name.lower(), version=installed)
        dist_url = f"https://pypi.org/project/{name}/{installed}/"
        packages.append(
            {
                "name": name,
                "version": installed,
                "type": "LIBRARY",
                "latest": latest,
                "license": license_,
                "purl": str(purl),
                "dist_url": dist_url,
                "vulnerabilities": "",
            }
        )

    print("  Fetching Node.js packages...")
    node_pkgs = get_node_packages()
    for name, installed in tqdm(node_pkgs, desc="Processing Node Packages"):
        latest = fetch_latest_version(name, "npm")
        license_ = fetch_license(name, "npm")
        purl = PackageURL(type="npm", name=name, version=installed)
        dist_url = f"https://www.npmjs.com/package/{name}/v/{installed}"
        packages.append(
            {
                "name": name,
                "version": installed,
                "type": "LIBRARY",
                "latest": latest,
                "license": license_,
                "purl": str(purl),
                "dist_url": dist_url,
                "vulnerabilities": "",
            }
        )

    print("  Fetching Java packages...")
    java_pkgs = get_java_packages()
    for group_id, artifact_id, installed in tqdm(
        java_pkgs, desc="Processing Java Packages"
    ):
        name = f"{group_id}:{artifact_id}"
        latest = fetch_latest_version(name, "maven")
        license_ = fetch_license(name, "maven")
        purl = PackageURL(
            type="maven", namespace=group_id, name=artifact_id, version=installed
        )
        dist_url = f"https://search.maven.org/artifact/{group_id}/{artifact_id}/{installed}/jar"
        packages.append(
            {
                "name": name,
                "version": installed,
                "type": "LIBRARY",
                "latest": latest,
                "license": license_,
                "purl": str(purl),
                "dist_url": dist_url,
                "vulnerabilities": "",
            }
        )

    print("  Fetching PHP packages...")
    php_pkgs = get_php_packages()
    for name, installed in tqdm(php_pkgs, desc="Processing PHP Packages"):
        latest = fetch_latest_version(name, "composer")
        license_ = fetch_license(name, "composer")
        purl = PackageURL(type="composer", name=name, version=installed)
        dist_url = f"https://packagist.org/packages/{name}#{installed}"
        packages.append(
            {
                "name": name,
                "version": installed,
                "type": "LIBRARY",
                "latest": latest,
                "license": license_,
                "purl": str(purl),
                "dist_url": dist_url,
                "vulnerabilities": "",
            }
        )

    # Combine all components
    all_components = system_components + packages

    print(f"🔍 Analyzing {len(all_components)} components locally using AI...")

    # Send data to unified server
    try:
        analyzed_packages = asyncio.run(
            analyze_packages_batch(all_components, concurrency=10)
        )
        print(
            f"✅ Completed vulnerability analysis for {len(analyzed_packages)} components"
        )
    except Exception as e:
        print(f"❌ Error during batch analysis: {e}")
        return

    print(f"📤 Sending analyzed data to unified server for bulk database insertion...")

    try:
        # Create the request payload with analyzed data
        payload = {
            "hostname": hostname,
            "analyzed_packages": analyzed_packages,  # Send already analyzed data
        }

        response = requests.post(
            f"{UNIFIED_SERVER_URL}/api/sbom/bulk-insert",  # New endpoint for bulk insert
            json=payload,
            timeout=60,  # Shorter timeout since no analysis on server
        )

        if response.status_code == 200:
            result = response.json()
            print(f"✅ Successfully sent SBOM data to server!")
            print(f"   {result.get('message', '')}")
        else:
            print(f"❌ Failed to send SBOM data: {response.status_code}")
            print(f"   {response.text}")

    except Exception as e:
        print(f"❌ Error sending SBOM data: {e}")

    print(f"🏁 SBOM generation and analysis completed for {hostname}")


if __name__ == "__main__":
    generate_and_send_sbom()
