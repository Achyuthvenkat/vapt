import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Download, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Server, 
  Package, 
  Filter,
  Search,
  RefreshCw,
  Eye,
  Database
} from 'lucide-react';

const API_BASE_URL = 'http://localhost:8000/api';

const SecurityDashboard = () => {
  const [activeTab, setActiveTab] = useState('sbom');
  const [sbomData, setSbomData] = useState([]);
  const [qualysData, setQualysData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedHostname, setSelectedHostname] = useState('');
  const [showCriticalOnly, setShowCriticalOnly] = useState(true);

  // Fetch SBOM data
  const fetchSbomData = async (hostname = '') => {
    setLoading(true);
    try {
      const url = hostname ? `${API_BASE_URL}/sbom/data?hostname=${hostname}` : `${API_BASE_URL}/sbom/data`;
      const response = await fetch(url);
      const result = await response.json();
      if (result.status === 'success') {
        setSbomData(result.data);
      }
    } catch (error) {
      console.error('Error fetching SBOM data:', error);
    }
    setLoading(false);
  };

  // Fetch Qualys data
  const fetchQualysData = async (criticalOnly = true) => {
    setLoading(true);
    try {
      const url = `${API_BASE_URL}/qualys/data?critical_only=${criticalOnly}`;
      const response = await fetch(url);
      const result = await response.json();
      if (result.status === 'success') {
        setQualysData(result.data);
      }
    } catch (error) {
      console.error('Error fetching Qualys data:', error);
    }
    setLoading(false);
  };

  // Import Qualys data
  const importQualysData = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/qualys/import`, {
        method: 'POST'
      });
      const result = await response.json();
      if (result.status === 'success') {
        alert(`Successfully imported ${result.data} vulnerability records`);
        fetchQualysData(showCriticalOnly);
      }
    } catch (error) {
      console.error('Error importing Qualys data:', error);
      alert('Failed to import Qualys data');
    }
    setLoading(false);
  };

  // Download Excel files
  const downloadSbomExcel = async () => {
    try {
      const url = selectedHostname ? 
        `${API_BASE_URL}/sbom/export?hostname=${selectedHostname}` : 
        `${API_BASE_URL}/sbom/export`;
      window.open(url, '_blank');
    } catch (error) {
      console.error('Error downloading SBOM Excel:', error);
    }
  };

  const downloadQualysExcel = async () => {
    try {
      window.open(`${API_BASE_URL}/qualys/export`, '_blank');
    } catch (error) {
      console.error('Error downloading Qualys Excel:', error);
    }
  };

  useEffect(() => {
    if (activeTab === 'sbom') {
      fetchSbomData();
    } else if (activeTab === 'qualys') {
      fetchQualysData(showCriticalOnly);
    }
  }, [activeTab]);

  // Filter functions
  const getUniqueHostnames = () => {
    const hostnames = [...new Set(sbomData.map(item => item.hostname))];
    return hostnames.sort();
  };

  const getFilteredSbomData = () => {
    let filtered = sbomData;
    
    if (selectedHostname) {
      filtered = filtered.filter(item => item.hostname === selectedHostname);
    }
    
    if (searchTerm) {
      filtered = filtered.filter(item => 
        item.package_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.vulnerabilities.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }
    
    return filtered;
  };

  const getFilteredQualysData = () => {
    let filtered = qualysData;
    
    if (searchTerm) {
      filtered = filtered.filter(item => 
        (item.asset_name && item.asset_name.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (item.asset_ip && item.asset_ip.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (item.qid && item.qid.toString().includes(searchTerm))
      );
    }
    
    return filtered;
  };

  // Get host-specific data
  const getHostOverview = () => {
    const hostnames = getUniqueHostnames();
    return hostnames.map(hostname => {
      const hostData = sbomData.filter(item => item.hostname === hostname);
      const totalPackages = hostData.length;
      
      // Count vulnerabilities by severity
      const critical = hostData.filter(item => 
        item.vulnerabilities && item.vulnerabilities.toLowerCase().includes('critical')
      ).length;
      
      const high = hostData.filter(item => 
        item.vulnerabilities && item.vulnerabilities.toLowerCase().includes('high') && 
        !item.vulnerabilities.toLowerCase().includes('critical')
      ).length;
      
      const medium = hostData.filter(item => 
        item.vulnerabilities && item.vulnerabilities.toLowerCase().includes('medium') && 
        !item.vulnerabilities.toLowerCase().includes('critical') &&
        !item.vulnerabilities.toLowerCase().includes('high')
      ).length;
      
      // Count license issues
      const licenseIssues = hostData.filter(item => 
        item.verdict && item.verdict.includes('Requires Legal Review')
      ).length;
      
      // Get last scanned (you might need to adjust this based on your data structure)
      const lastScanned = hostData.length > 0 ? new Date().toLocaleDateString() + ', ' + new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}) : 'Never';
      
      // Get IP address if available in your data
      const ipAddress = hostData.length > 0 ? (hostData[0].ip_address || '192.168.1.100') : 'Unknown';
      
      return {
        hostname,
        ipAddress,
        totalPackages,
        critical,
        high,
        medium,
        licenseIssues,
        lastScanned
      };
    });
  };

  const getSeverityBadge = (verdict) => {
    if (verdict && verdict.includes('Requires Legal Review')) {
      return <span className="px-2 py-1 bg-yellow-100 text-yellow-800 rounded-full text-xs">⚠️ Legal Review</span>;
    } else if (verdict && verdict.includes('Allowed for Enterprise')) {
      return <span className="px-2 py-1 bg-green-100 text-green-800 rounded-full text-xs">✅ Allowed</span>;
    }
    return <span className="px-2 py-1 bg-gray-100 text-gray-800 rounded-full text-xs">Unknown</span>;
  };

  const getVulnerabilityBadge = (vulnerabilities) => {
    if (!vulnerabilities || vulnerabilities.includes('No known vulnerabilities')) {
      return <span className="px-2 py-1 bg-green-100 text-green-800 rounded-full text-xs">✅ No Issues</span>;
    } else if (vulnerabilities.toLowerCase().includes('critical')) {
      return <span className="px-2 py-1 bg-red-100 text-red-800 rounded-full text-xs">🚨 Critical</span>;
    } else if (vulnerabilities.toLowerCase().includes('high')) {
      return <span className="px-2 py-1 bg-orange-100 text-orange-800 rounded-full text-xs">⚠️ High</span>;
    } else if (vulnerabilities.toLowerCase().includes('medium')) {
      return <span className="px-2 py-1 bg-yellow-100 text-yellow-800 rounded-full text-xs">⚠️ Medium</span>;
    }
    return <span className="px-2 py-1 bg-blue-100 text-blue-800 rounded-full text-xs">ℹ️ Info</span>;
  };

  const QualysSeverityBadge = ({ severity }) => {
    const severityColors = {
      'CRITICAL': 'bg-red-100 text-red-800',
      'HIGH': 'bg-orange-100 text-orange-800',
      'MEDIUM': 'bg-yellow-100 text-yellow-800',
      'LOW': 'bg-blue-100 text-blue-800',
      'INFO': 'bg-gray-100 text-gray-800'
    };
    
    const colorClass = severityColors[severity] || 'bg-gray-100 text-gray-800';
    
    return (
      <span className={`px-2 py-1 rounded-full text-xs ${colorClass}`}>
        {severity}
      </span>
    );
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-blue-600" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">
                  {activeTab === 'sbom' ? 'SBOM Security Dashboard' : 'Security Dashboard'}
                </h1>
                <p className="text-sm text-gray-600">
                  {activeTab === 'sbom' ? 'Software Bill of Materials & Vulnerability Management' : 'SBOM Vulnerability Analysis & Qualys Management'}
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-sm text-gray-500">
                Last Updated: {new Date().toLocaleDateString()} {new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
              </div>
              <button
                onClick={() => {
                  if (activeTab === 'sbom') fetchSbomData(selectedHostname);
                  else fetchQualysData(showCriticalOnly);
                }}
                disabled={loading}
                className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
                <span>Refresh</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-6">
        <div className="flex space-x-1 bg-gray-100 p-1 rounded-lg w-fit">
          <button
            onClick={() => setActiveTab('sbom')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-colors ${
              activeTab === 'sbom' 
                ? 'bg-white text-blue-600 shadow-sm' 
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            <Package className="h-4 w-4" />
            <span>SBOM Analysis</span>
          </button>
          <button
            onClick={() => setActiveTab('qualys')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-colors ${
              activeTab === 'qualys' 
                ? 'bg-white text-blue-600 shadow-sm' 
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            <Database className="h-4 w-4" />
            <span>Qualys Vulnerabilities</span>
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'sbom' && (
          <div className="space-y-6">
            {/* SBOM Stats - Horizontal Layout */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <Server className="h-8 w-8 text-blue-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">Total Hosts</p>
                    <p className="text-2xl font-semibold text-gray-900">{getUniqueHostnames().length}</p>
                  </div>
                </div>
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <Package className="h-8 w-8 text-green-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">Total Packages</p>
                    <p className="text-2xl font-semibold text-gray-900">{getFilteredSbomData().length}</p>
                  </div>
                </div>
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <AlertTriangle className="h-8 w-8 text-red-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">Critical Vulnerabilities</p>
                    <p className="text-2xl font-semibold text-gray-900">
                      {getFilteredSbomData().filter(item => 
                        item.vulnerabilities && item.vulnerabilities.toLowerCase().includes('critical')
                      ).length}
                    </p>
                  </div>
                </div>
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <XCircle className="h-8 w-8 text-yellow-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">License Concerns</p>
                    <p className="text-2xl font-semibold text-gray-900">
                      {getFilteredSbomData().filter(item => 
                        item.verdict && item.verdict.includes('Requires Legal Review')
                      ).length}
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Hosts Overview Section */}
            <div className="bg-white rounded-lg shadow">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">Hosts Overview</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Host Information
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Packages
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Vulnerabilities
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        License Issues
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Last Scanned
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {loading ? (
                      <tr>
                        <td colSpan="6" className="px-6 py-12 text-center">
                          <div className="flex items-center justify-center">
                            <RefreshCw className="h-6 w-6 animate-spin text-gray-400 mr-2" />
                            <span className="text-gray-500">Loading SBOM data...</span>
                          </div>
                        </td>
                      </tr>
                    ) : getHostOverview().length === 0 ? (
                      <tr>
                        <td colSpan="6" className="px-6 py-12 text-center text-gray-500">
                          No SBOM data found. Run the SBOM client on your machines to populate data.
                        </td>
                      </tr>
                    ) : (
                      getHostOverview().map((host, index) => (
                        <tr key={index} className="hover:bg-gray-50">
                          <td className="px-6 py-4">
                            <div>
                              <div className="text-sm font-medium text-blue-600">{host.hostname}</div>
                              <div className="text-sm text-gray-500">{host.ipAddress}</div>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm font-medium text-gray-900">{host.totalPackages}</div>
                          </td>
                          <td className="px-6 py-4">
                            <div className="flex flex-wrap gap-1">
                              {host.critical > 0 && (
                                <span className="px-2 py-1 bg-red-100 text-red-800 rounded text-xs">
                                  {host.critical} Critical
                                </span>
                              )}
                              {host.high > 0 && (
                                <span className="px-2 py-1 bg-orange-100 text-orange-800 rounded text-xs">
                                  {host.high} High
                                </span>
                              )}
                              {host.medium > 0 && (
                                <span className="px-2 py-1 bg-yellow-100 text-yellow-800 rounded text-xs">
                                  {host.medium} Medium
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            {host.licenseIssues > 0 ? (
                              <span className="px-2 py-1 bg-yellow-100 text-yellow-800 rounded text-xs">
                                {host.licenseIssues} Issues
                              </span>
                            ) : (
                              <span className="text-sm text-gray-500">No Issues</span>
                            )}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {host.lastScanned}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex space-x-2">
                              <button
                                onClick={() => {
                                  setSelectedHostname(host.hostname);
                                  fetchSbomData(host.hostname);
                                }}
                                className="flex items-center space-x-1 px-3 py-1 bg-blue-100 text-blue-700 rounded text-sm hover:bg-blue-200"
                              >
                                <Eye className="h-3 w-3" />
                                <span>View Details</span>
                              </button>
                              <button
                                onClick={() => {
                                  const originalHostname = selectedHostname;
                                  setSelectedHostname(host.hostname);
                                  downloadSbomExcel();
                                  setSelectedHostname(originalHostname);
                                }}
                                className="flex items-center space-x-1 px-3 py-1 bg-green-100 text-green-700 rounded text-sm hover:bg-green-200"
                              >
                                <Download className="h-3 w-3" />
                                <span>Download</span>
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Package Details Table (shown when a host is selected) */}
            {selectedHostname && (
              <div className="space-y-4">
                {/* Controls for detailed view */}
                <div className="bg-white rounded-lg shadow p-6">
                  <div className="flex flex-wrap items-center justify-between gap-4">
                    <div className="flex items-center space-x-4">
                      <div className="relative">
                        <Search className="h-4 w-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                        <input
                          type="text"
                          placeholder="Search packages or vulnerabilities..."
                          className="pl-10 pr-4 py-2 border border-gray-300 rounded-lg w-80"
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                        />
                      </div>
                      <button
                        onClick={() => {
                          setSelectedHostname('');
                          setSearchTerm('');
                        }}
                        className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700"
                      >
                        Back to Overview
                      </button>
                    </div>
                    <button
                      onClick={downloadSbomExcel}
                      className="flex items-center space-x-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
                    >
                      <Download className="h-4 w-4" />
                      <span>Download Excel</span>
                    </button>
                  </div>
                </div>

                {/* Detailed Package Table */}
                <div className="bg-white rounded-lg shadow overflow-hidden">
                  <div className="px-6 py-4 border-b border-gray-200">
                    <h3 className="text-lg font-medium text-gray-900">
                      Package Details - {selectedHostname}
                    </h3>
                    <p className="text-sm text-gray-600">
                      Detailed vulnerability and license information for packages on this host
                    </p>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Package
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Version
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            License
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Vulnerabilities
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            License Status
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Suggestions
                          </th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {getFilteredSbomData().map((item, index) => (
                          <tr key={index} className="hover:bg-gray-50">
                            <td className="px-6 py-4 whitespace-nowrap">
                              <div>
                                <div className="text-sm font-medium text-blue-600">{item.package_name}</div>
                                <div className="text-xs text-gray-500">{item.package_type}</div>
                              </div>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <div className="text-sm text-gray-900">{item.installed_version}</div>
                              {item.latest_version && item.latest_version !== item.installed_version && (
                                <div className="text-xs text-green-600">Latest: {item.latest_version}</div>
                              )}
                            </td>
                            <td className="px-6 py-4">
                              <div className="text-sm text-gray-900 max-w-xs truncate" title={item.license}>
                                {item.license || 'Unknown'}
                              </div>
                            </td>
                            <td className="px-6 py-4">
                              <div className="space-y-1">
                                {getVulnerabilityBadge(item.vulnerabilities)}
                                {item.vulnerabilities && item.vulnerabilities.length > 50 && (
                                  <div className="text-xs text-gray-600 max-w-xs">
                                    {item.vulnerabilities.substring(0, 100)}...
                                  </div>
                                )}
                              </div>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              {getSeverityBadge(item.verdict)}
                            </td>
                            <td className="px-6 py-4">
                              <div className="text-sm text-gray-900 max-w-xs">
                                {item.suggestions && item.suggestions.length > 50 
                                  ? `${item.suggestions.substring(0, 100)}...`
                                  : item.suggestions
                                }
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'qualys' && (
          <div className="space-y-6">
            {/* Qualys Controls */}
            <div className="bg-white rounded-lg shadow p-6">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center space-x-4">
                  <div className="relative">
                    <Search className="h-4 w-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search assets, IPs, or QIDs..."
                      className="pl-10 pr-4 py-2 border border-gray-300 rounded-lg w-80"
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                    />
                  </div>
                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id="criticalOnly"
                      checked={showCriticalOnly}
                      onChange={(e) => {
                        setShowCriticalOnly(e.target.checked);
                        fetchQualysData(e.target.checked);
                      }}
                      className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                    />
                    <label htmlFor="criticalOnly" className="text-sm text-gray-700">
                      Show Critical Only
                    </label>
                  </div>
                </div>
                <div className="flex space-x-3">
                  <button
                    onClick={importQualysData}
                    disabled={loading}
                    className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                  >
                    <Database className="h-4 w-4" />
                    <span>Import Data</span>
                  </button>
                  <button
                    onClick={downloadQualysExcel}
                    className="flex items-center space-x-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
                  >
                    <Download className="h-4 w-4" />
                    <span>Download All</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Qualys Stats */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <Server className="h-8 w-8 text-blue-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">Total Assets</p>
                    <p className="text-2xl font-semibold text-gray-900">
                      {[...new Set(getFilteredQualysData().map(item => item.asset_id))].length}
                    </p>
                  </div>
                </div>
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <AlertTriangle className="h-8 w-8 text-red-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">Critical Vulns</p>
                    <p className="text-2xl font-semibold text-gray-900">
                      {getFilteredQualysData().filter(item => item.qds_severity === 'CRITICAL').length}
                    </p>
                  </div>
                </div>
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <Eye className="h-8 w-8 text-orange-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">High Vulns</p>
                    <p className="text-2xl font-semibold text-gray-900">
                      {getFilteredQualysData().filter(item => item.qds_severity === 'HIGH').length}
                    </p>
                  </div>
                </div>
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <CheckCircle className="h-8 w-8 text-green-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">Total Detections</p>
                    <p className="text-2xl font-semibold text-gray-900">{getFilteredQualysData().length}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Qualys Table */}
            <div className="bg-white rounded-lg shadow overflow-hidden">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">Qualys Vulnerability Detections</h3>
                <p className="text-sm text-gray-600">
                  {showCriticalOnly ? 'Showing critical vulnerabilities only' : 'Showing all vulnerability detections'}
                </p>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Asset
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        QID
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Severity
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        QDS Score
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Port/Protocol
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Status
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Last Found
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {loading ? (
                      <tr>
                        <td colSpan="7" className="px-6 py-12 text-center">
                          <div className="flex items-center justify-center">
                            <RefreshCw className="h-6 w-6 animate-spin text-gray-400 mr-2" />
                            <span className="text-gray-500">Loading Qualys data...</span>
                          </div>
                        </td>
                      </tr>
                    ) : getFilteredQualysData().length === 0 ? (
                      <tr>
                        <td colSpan="7" className="px-6 py-12 text-center text-gray-500">
                          No Qualys data found. Click "Import Data" to fetch vulnerability data.
                        </td>
                      </tr>
                    ) : (
                      getFilteredQualysData().map((item, index) => (
                        <tr key={index} className="hover:bg-gray-50">
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div>
                              <div className="text-sm font-medium text-gray-900">
                                {item.asset_name || 'Unknown'}
                              </div>
                              <div className="text-sm text-gray-500">{item.asset_ip}</div>
                              <div className="text-xs text-gray-400">ID: {item.asset_id}</div>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm font-medium text-blue-600">{item.qid}</div>
                            <div className="text-xs text-gray-500">{item.vuln_type}</div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <QualysSeverityBadge severity={item.qds_severity} />
                            <div className="text-xs text-gray-500 mt-1">Level: {item.severity}</div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm font-medium text-gray-900">
                              {item.qds ? parseFloat(item.qds).toFixed(1) : 'N/A'}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm text-gray-900">
                              {item.port && item.protocol ? `${item.port}/${item.protocol}` : 'N/A'}
                            </div>
                            {item.ssl && <div className="text-xs text-green-600">SSL</div>}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`px-2 py-1 text-xs rounded-full ${
                              item.status === 'Active' ? 'bg-red-100 text-red-800' :
                              item.status === 'New' ? 'bg-orange-100 text-orange-800' :
                              item.status === 'Fixed' ? 'bg-green-100 text-green-800' :
                              'bg-gray-100 text-gray-800'
                            }`}>
                              {item.status}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {item.last_found_datetime ? 
                              new Date(item.last_found_datetime).toLocaleDateString() : 
                              'Unknown'
                            }
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default SecurityDashboard;