"""
app.py - TOR-Unveil Dashboard (CSV-based workflow)
Main Streamlit application using CSV files for data storage
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os
import json
import base64
from io import StringIO
import sys

# Import our CSV-based modules
sys.path.append('modules')
from tor_map import TorNetworkMapper
from pcap_parser import PCAPAnalyzer
from correlator import CorrelationEngine

# 🔹 NEW: import newly added modules
from path_reconstructor import PathReconstructor
from report import ForensicReportGenerator
from visualization import NetworkVisualizer

# Page configuration
st.set_page_config(
    page_title="TOR-Unveil Forensic System",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E3A8A;
        text-align: center;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #3B82F6;
        margin-top: 1.5rem;
        margin-bottom: 1rem;
    }
    .metric-card {
        background-color: #F8FAFC;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #3B82F6;
        margin-bottom: 1rem;
    }
    .success-box {
        background-color: #D1FAE5;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #10B981;
        margin: 1rem 0;
    }
    .warning-box {
        background-color: #FEF3C7;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #F59E0B;
        margin: 1rem 0;
    }
    .info-box {
        background-color: #E0F2FE;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #0EA5E9;
        margin: 1rem 0;
    }
    .stProgress > div > div > div > div {
        background-color: #3B82F6;
    }
    .filter-card {
        background-color: #F1F5F9;
        padding: 1.5rem;
        border-radius: 10px;
        border: 1px solid #E2E8F0;
        margin-bottom: 1.5rem;
    }
    .filter-title {
        font-weight: 600;
        color: #475569;
        margin-bottom: 1rem;
        font-size: 1.1rem;
    }
    .csv-status {
        font-size: 0.9rem;
        color: #6B7280;
        font-family: monospace;
    }
</style>
""", unsafe_allow_html=True)

# (REST OF YOUR FILE CONTINUES UNCHANGED)
# ⛔ NOTHING BELOW THIS WAS MODIFIED

# Initialize session state variables
def init_session_state():
    """Initialize session state variables for CSV workflow"""
    if 'tor_nodes_df' not in st.session_state:
        st.session_state.tor_nodes_df = None
    if 'flows_df' not in st.session_state:
        st.session_state.flows_df = None
    if 'correlation_results' not in st.session_state:
        st.session_state.correlation_results = None
    if 'correlation_stats' not in st.session_state:
        st.session_state.correlation_stats = {}
    if 'tor_metrics' not in st.session_state:
        st.session_state.tor_metrics = {}
    if 'flow_stats' not in st.session_state:
        st.session_state.flow_stats = {}
    if 'csv_files_ready' not in st.session_state:
        st.session_state.csv_files_ready = False
    if 'last_refresh' not in st.session_state:
        st.session_state.last_refresh = None
    if 'current_tab' not in st.session_state:
        st.session_state.current_tab = "Dashboard"

init_session_state()

# Helper functions
def get_table_download_link(df, filename="data.csv", text="Download CSV"):
    """Generate a link to download a dataframe as CSV"""
    csv = df.to_csv(index=False)
    b64 = base64.b64encode(csv.encode()).decode()
    href = f'<a href="data:file/csv;base64,{b64}" download="{filename}">{text}</a>'
    return href

def check_csv_files():
    """Check if CSV files exist and are valid"""
    data_dir = "data"
    files_exist = {
        'tor_nodes.csv': os.path.exists(os.path.join(data_dir, 'tor_nodes.csv')),
        'pcap_flows.csv': os.path.exists(os.path.join(data_dir, 'pcap_flows.csv')),
        'correlation_results.csv': os.path.exists(os.path.join(data_dir, 'correlation_results.csv'))
    }
    
    return files_exist

def load_csv_files():
    """Load data from CSV files"""
    data_dir = "data"
    
    # Load Tor nodes
    tor_nodes_path = os.path.join(data_dir, "tor_nodes.csv")
    if os.path.exists(tor_nodes_path):
        try:
            st.session_state.tor_nodes_df = pd.read_csv(tor_nodes_path)
            # Calculate metrics
            if not st.session_state.tor_nodes_df.empty:
                mapper = TorNetworkMapper()
                st.session_state.tor_metrics = mapper._calculate_metrics(st.session_state.tor_nodes_df)
        except Exception as e:
            st.error(f"Error loading Tor nodes CSV: {e}")
    
    # Load flows
    flows_path = os.path.join(data_dir, "pcap_flows.csv")
    if os.path.exists(flows_path):
        try:
            st.session_state.flows_df = pd.read_csv(flows_path)
            # Calculate statistics
            if not st.session_state.flows_df.empty:
                analyzer = PCAPAnalyzer()
                st.session_state.flow_stats = analyzer.get_flow_statistics(st.session_state.flows_df)
        except Exception as e:
            st.error(f"Error loading flows CSV: {e}")
    
    # Load correlation results
    results_path = os.path.join(data_dir, "correlation_results.csv")
    if os.path.exists(results_path):
        try:
            st.session_state.correlation_results = pd.read_csv(results_path)
            if not st.session_state.correlation_results.empty:
                engine = CorrelationEngine()
                st.session_state.correlation_stats = engine._calculate_correlation_stats(st.session_state.correlation_results)
        except Exception as e:
            st.error(f"Error loading correlation results: {e}")
    
    # Update status
    files_exist = check_csv_files()
    st.session_state.csv_files_ready = any(files_exist.values())

def refresh_tor_data():
    """Refresh Tor network data"""
    with st.spinner("Fetching latest Tor network data..."):
        try:
            mapper = TorNetworkMapper()
            df, metrics = mapper.get_tor_data(force_refresh=True)
            
            if not df.empty:
                st.session_state.tor_nodes_df = df
                st.session_state.tor_metrics = metrics
                st.session_state.last_refresh = datetime.now()
                return True
            else:
                st.error("Failed to fetch Tor network data")
                return False
        except Exception as e:
            st.error(f"Error: {e}")
            return False

def analyze_pcap_file(uploaded_file):
    """Analyze uploaded PCAP file"""
    with st.spinner("Analyzing PCAP file..."):
        try:
            # Save uploaded file temporarily
            temp_path = "temp_upload.pcap"
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            # Analyze PCAP
            analyzer = PCAPAnalyzer()
            df, stats = analyzer.analyze_and_export(temp_path)
            
            if not df.empty:
                st.session_state.flows_df = df
                st.session_state.flow_stats = stats
                return True
            else:
                st.error("No flows extracted from PCAP")
                return False
        except Exception as e:
            st.error(f"Error analyzing PCAP: {e}")
            return False
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)

def run_correlation():
    """Run correlation engine"""
    with st.spinner("Running correlation engine..."):
        try:
            engine = CorrelationEngine()
            
            # Load data into engine
            engine.tor_nodes_df = st.session_state.tor_nodes_df
            engine.flows_df = st.session_state.flows_df
            
            # Run correlation
            results = engine.run_correlation()
            
            if not results.empty:
                st.session_state.correlation_results = results
                st.session_state.correlation_stats = engine.correlation_stats
                return True
            else:
                st.warning("No correlations found")
                return False
        except Exception as e:
            st.error(f"Error running correlation: {e}")
            return False

def reset_all_data():
    """Reset all session data"""
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    init_session_state()
    
    # Clear CSV files
    data_dir = "data"
    csv_files = ['tor_nodes.csv', 'pcap_flows.csv', 'correlation_results.csv']
    for file in csv_files:
        file_path = os.path.join(data_dir, file)
        if os.path.exists(file_path):
            os.remove(file_path)

# Main dashboard
def main():
    """Main dashboard application"""
    
    # Header
    st.markdown('<h1 class="main-header">🔍 TOR-Unveil Forensic System</h1>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-box">
    <strong style='color:black;'>CSV-Based Workflow:</strong> 
    <p style='color:black;'>A forensic pipeline that correlates network captures with Tor nodes using CSV files for data storage.
    All data is saved to CSV files in the 'data' directory for persistence and analysis.</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Check and load CSV files on startup
    if not st.session_state.csv_files_ready:
        load_csv_files()
    
    # Sidebar
    with st.sidebar:
        st.markdown("## ⚙️ Configuration")
        
        # CSV Status
        st.markdown("### 📁 CSV File Status")
        files_exist = check_csv_files()
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Tor Data", 
                     "✅" if files_exist['tor_nodes.csv'] else "❌",
                     "CSV Ready" if files_exist['tor_nodes.csv'] else "Missing")
        
        with col2:
            st.metric("Flow Data", 
                     "✅" if files_exist['pcap_flows.csv'] else "❌",
                     "CSV Ready" if files_exist['pcap_flows.csv'] else "Missing")
        
        with col3:
            st.metric("Results", 
                     "✅" if files_exist['correlation_results.csv'] else "❌",
                     "CSV Ready" if files_exist['correlation_results.csv'] else "Missing")
        
        # Data Management
        st.markdown("### 🔄 Data Management")
        
        # Tor Network Data
        if st.button("🔄 Refresh Tor Data", use_container_width=True):
            if refresh_tor_data():
                st.success(f"Loaded {len(st.session_state.tor_nodes_df)} Tor nodes")
                st.rerun()
        
        # PCAP Upload
        st.markdown("### 📁 PCAP Analysis")
        uploaded_file = st.file_uploader(
            "Upload network capture",
            type=['pcap', 'pcapng', 'cap'],
            help="Upload a PCAP/PCAPNG file for analysis"
        )
        
        if uploaded_file is not None:
            if st.button("🔍 Analyze PCAP", use_container_width=True):
                if analyze_pcap_file(uploaded_file):
                    st.success(f"Analyzed {len(st.session_state.flows_df)} flows")
                    st.rerun()
        
       

        
        # Data Pipeline
        st.markdown("### ⚡ Quick Pipeline")
        if st.button("▶️ Run Complete Pipeline", use_container_width=True):
            progress_bar = st.progress(0)
            
            # Step 1: Tor Data
            progress_bar.progress(25)
            if refresh_tor_data():
                # Step 2: Use existing or sample flows
                progress_bar.progress(50)
                if st.session_state.flows_df is None:
                    # Create sample flows if none exist
                    analyzer = PCAPAnalyzer()
                    st.session_state.flows_df = analyzer._create_sample_flows()
                
                # Step 3: Correlation
                progress_bar.progress(75)
                if run_correlation():
                    progress_bar.progress(100)
                    st.success("Pipeline completed successfully!")
                    st.rerun()
                else:
                    progress_bar.progress(100)
                    st.error("Correlation failed")
            else:
                progress_bar.progress(100)
                st.error("Failed to fetch Tor data")
        
        # Reset button
        st.markdown("---")
        if st.button("🗑️ Reset All Data", use_container_width=True):
            reset_all_data()
            st.success("All data reset")
            st.rerun()
        
        # Last refresh time
        if st.session_state.last_refresh:
            st.caption(f"Last refresh: {st.session_state.last_refresh.strftime('%H:%M:%S')}")
        
        # Status indicators
        st.markdown("### 📊 Current Status")
        col1, col2 = st.columns(2)
        with col1:
            tor_count = len(st.session_state.tor_nodes_df) if st.session_state.tor_nodes_df is not None else 0
            st.metric("Tor Nodes", tor_count)
        
        with col2:
            flow_count = len(st.session_state.flows_df) if st.session_state.flows_df is not None else 0
            st.metric("Flows", flow_count)
    
    # Main content area
    tab1, tab2, tab3, tab4 = st.tabs([
        "📈 Dashboard", 
        "🌐 Tor Network", 
        "📊 PCAP Analysis", 
        "🔗 Correlation Results"
    ])
    
    # Tab 1: Dashboard
    with tab1:
        st.markdown('<h2 class="sub-header">System Overview</h2>', unsafe_allow_html=True)
        
        # Overview metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Tor Network Size",
                f"{st.session_state.tor_metrics.get('total_relays', 0):,}",
                f"{st.session_state.tor_metrics.get('guard_count', 0)} Guards"
            )
        
        with col2:
            st.metric(
                "Network Bandwidth",
                f"{st.session_state.tor_metrics.get('total_bandwidth_gbps', 0):.1f} Gbps",
                f"{st.session_state.tor_metrics.get('country_count', 0)} Countries"
            )
        
        with col3:
            st.metric(
                "PCAP Analysis",
                f"{st.session_state.flow_stats.get('total_flows', 0):,}",
                f"{st.session_state.flow_stats.get('suspected_tor_flows', 0)} Tor-like"
            )
        
        with col4:
            avg_score = st.session_state.correlation_stats.get('avg_total_score', 0)
            confidence = "🟢 High" if avg_score >= 0.7 else "🟡 Medium" if avg_score >= 0.5 else "🔴 Low"
            st.metric(
                "Avg Correlation",
                f"{avg_score:.3f}",
                confidence
            )
        
        # CSV File Status
        st.markdown("### 📁 CSV File Status")
        files_exist = check_csv_files()
        
        status_col1, status_col2, status_col3 = st.columns(3)
        
        with status_col1:
            st.markdown("""
            <div class="metric-card">
            <h4 style='color:black;'>Tor Nodes CSV</h4>
            <p style='color:black;' class="csv-status">data/tor_nodes.csv</p>
            <p style='color:black;'>Status: <strong>{}</strong></p>
            <p style='color:black;'>Records: {}</p>
            </div>
            """.format(
                "✅ Available" if files_exist['tor_nodes.csv'] else "❌ Missing",
                len(st.session_state.tor_nodes_df) if st.session_state.tor_nodes_df is not None else 0
            ), unsafe_allow_html=True)
        
        with status_col2:
            st.markdown("""
            <div class="metric-card">
            <h4 style='color:black;'>PCAP Flows CSV</h4>
            <p style='color:black;' class="csv-status">data/pcap_flows.csv</p>
            <p style='color:black;'>Status: <strong>{}</strong></p>
            <p style='color:black;'>Records: {}</p>
            </div>
            """.format(
                "✅ Available" if files_exist['pcap_flows.csv'] else "❌ Missing",
                len(st.session_state.flows_df) if st.session_state.flows_df is not None else 0
            ), unsafe_allow_html=True)
        
        with status_col3:
            st.markdown("""
            <div class="metric-card">
            <h4 style='color:black;'>Correlation CSV</h4>
            <p style='color:black;' class="csv-status">data/correlation_results.csv</p>
            <p style='color:black;'>Status: <strong>{}</strong></p>
            <p style='color:black;'>Records: {}</p>
            </div>
            """.format(
                "✅ Available" if files_exist['correlation_results.csv'] else "❌ Missing",
                len(st.session_state.correlation_results) if st.session_state.correlation_results is not None else 0
            ), unsafe_allow_html=True)
        
        # Download all data
        st.markdown("### 📥 Download Data")
        download_col1, download_col2, download_col3 = st.columns(3)
        
        with download_col1:
            if st.session_state.tor_nodes_df is not None and not st.session_state.tor_nodes_df.empty:
                st.markdown(get_table_download_link(
                    st.session_state.tor_nodes_df,
                    filename="tor_nodes.csv",
                    text="📥 Download Tor Nodes CSV"
                ), unsafe_allow_html=True)
        
        with download_col2:
            if st.session_state.flows_df is not None and not st.session_state.flows_df.empty:
                st.markdown(get_table_download_link(
                    st.session_state.flows_df,
                    filename="pcap_flows.csv",
                    text="📥 Download Flows CSV"
                ), unsafe_allow_html=True)
        
        with download_col3:
            if st.session_state.correlation_results is not None and not st.session_state.correlation_results.empty:
                st.markdown(get_table_download_link(
                    st.session_state.correlation_results,
                    filename="correlation_results.csv",
                    text="📥 Download Results CSV"
                ), unsafe_allow_html=True)
        
        # Quick start guide
        st.markdown("### 🚀 CSV-Based Workflow")
        guide_col1, guide_col2, guide_col3 = st.columns(3)
        
        with guide_col1:
            st.markdown("""
            <div class="metric-card">
            <h4 style='color:black;'>1. Load/Refresh Data</h4>
            <p style='color:black;'>Click "Refresh Tor Data" to fetch current Tor nodes. 
            All data is saved to CSV files in the 'data' directory.</p>
            </div>
            """, unsafe_allow_html=True)
        
        with guide_col2:
            st.markdown("""
            <div class="metric-card">
            <h4 style='color:black;'>2. Analyze PCAP</h4>
            <p style='color:black;'>Upload a PCAP file or use existing flow data. 
            Flow data is saved to pcap_flows.csv for persistent storage.</p>
            </div>
            """, unsafe_allow_html=True)
        
        with guide_col3:
            st.markdown("""
            <div class="metric-card">
            <h4 style='color:black;'>3. Run Correlation</h4>
            <p style='color:black;'>Click "Run Correlation" to analyze matches between flows and Tor nodes.
            Results are saved to correlation_results.csv.</p>
            </div>
            """, unsafe_allow_html=True)
    
    # Tab 2: Tor Network
    with tab2:
        st.markdown('<h2 class="sub-header">Tor Network Analysis</h2>', unsafe_allow_html=True)
        
        if st.session_state.tor_nodes_df is None or st.session_state.tor_nodes_df.empty:
            st.info("👈 Click 'Refresh Tor Data' in the sidebar to load Tor network data")
        else:
            # Tor data visualization
            st.markdown("### 📊 Tor Network Visualization")
            
            # Create visualization tabs
            viz_tab1, viz_tab2, viz_tab3 = st.tabs(["Geographic", "Role Distribution", "Performance"])
            
            with viz_tab1:
                if 'country_name' in st.session_state.tor_nodes_df.columns:
                    country_counts = st.session_state.tor_nodes_df['country_name'].value_counts().reset_index()
                    country_counts.columns = ['Country', 'Node Count']
                    
                    fig = px.bar(
                        country_counts.head(10),
                        x='Country',
                        y='Node Count',
                        title="Top 10 Countries by Tor Node Count",
                        color='Node Count',
                        color_continuous_scale='Blues'
                    )
                    st.plotly_chart(fig, use_container_width=True)
            
            with viz_tab2:
                if 'role' in st.session_state.tor_nodes_df.columns:
                    role_counts = st.session_state.tor_nodes_df['role'].value_counts().reset_index()
                    role_counts.columns = ['Role', 'Count']
                    
                    fig = px.pie(
                        role_counts,
                        values='Count',
                        names='Role',
                        title="Tor Node Role Distribution",
                        hole=0.3
                    )
                    st.plotly_chart(fig, use_container_width=True)
            
            with viz_tab3:
                if 'observed_bandwidth_mbps' in st.session_state.tor_nodes_df.columns:
                    fig = px.histogram(
                        st.session_state.tor_nodes_df,
                        x='observed_bandwidth_mbps',
                        nbins=20,
                        title="Tor Node Bandwidth Distribution (Mbps)",
                        labels={'observed_bandwidth_mbps': 'Bandwidth (Mbps)'},
                        color_discrete_sequence=['#3B82F6']
                    )
                    st.plotly_chart(fig, use_container_width=True)
            
            # Tor data table
            st.markdown("### 📋 Tor Node Details")
            
            # Display table with pagination
            display_df = st.session_state.tor_nodes_df.copy()
            
            # Select columns for display
            display_cols = ['nickname', 'ip_address', 'role', 'country_name', 
                          'observed_bandwidth_mbps', 'uptime_days']
            
            available_cols = [col for col in display_cols if col in display_df.columns]
            
            if available_cols:
                display_df = display_df[available_cols].head(100)  # Limit display
                
                st.dataframe(
                    display_df.rename(columns={
                        'nickname': 'Name',
                        'ip_address': 'IP Address',
                        'role': 'Role',
                        'country_name': 'Country',
                        'observed_bandwidth_mbps': 'Bandwidth (Mbps)',
                        'uptime_days': 'Uptime (Days)'
                    }),
                    use_container_width=True,
                    height=400
                )
    
    # Tab 3: PCAP Analysis
    with tab3:
        st.markdown('<h2 class="sub-header">PCAP Flow Analysis</h2>', unsafe_allow_html=True)
        
        if st.session_state.flows_df is None or st.session_state.flows_df.empty:
            st.info("👈 Upload a PCAP file and click 'Analyze PCAP' to begin analysis")
        else:
            # Flow statistics
            st.markdown("### 📊 Flow Statistics")
            
            stats_col1, stats_col2, stats_col3, stats_col4 = st.columns(4)
            
            with stats_col1:
                st.metric("Total Flows", st.session_state.flow_stats.get('total_flows', 0))
            
            with stats_col2:
                st.metric("Suspected Tor", st.session_state.flow_stats.get('suspected_tor_flows', 0))
            
            with stats_col3:
                st.metric("Total Packets", st.session_state.flow_stats.get('total_packets', 0))
            
            with stats_col4:
                st.metric("Total Data", f"{st.session_state.flow_stats.get('total_bytes', 0) / 1_000_000:.1f} MB")
            
            # Time range
            if 'time_range' in st.session_state.flow_stats:
                time_range = st.session_state.flow_stats['time_range']
                st.markdown(f"**Capture Time Range:** {time_range.get('start', 'N/A')} to {time_range.get('end', 'N/A')}")
            
            # Flow visualizations
            st.markdown("### 📈 Flow Analysis")
            
            if not st.session_state.flows_df.empty:
                viz_col1, viz_col2 = st.columns(2)
                
                with viz_col1:
                    # Port distribution
                    if 'dst_port' in st.session_state.flows_df.columns:
                        port_counts = st.session_state.flows_df['dst_port'].value_counts().head(10).reset_index()
                        port_counts.columns = ['Port', 'Count']
                        
                        fig = px.bar(
                            port_counts,
                            x='Port',
                            y='Count',
                            title="Top 10 Destination Ports",
                            color='Count',
                            color_continuous_scale='Viridis'
                        )
                        st.plotly_chart(fig, use_container_width=True)
                
                with viz_col2:
                    # Tor confidence distribution
                    if 'tor_confidence' in st.session_state.flows_df.columns:
                        fig = px.histogram(
                            st.session_state.flows_df,
                            x='tor_confidence',
                            nbins=20,
                            title="Tor Confidence Score Distribution",
                            labels={'tor_confidence': 'Tor Confidence Score'},
                            color_discrete_sequence=['#10B981']
                        )
                        st.plotly_chart(fig, use_container_width=True)
            
            # Flow table
            st.markdown("### 📋 Detected Flows")
            
            # Display table with pagination
            display_df = st.session_state.flows_df.copy()
            
            # Select columns for display
            flow_display_cols = ['flow_id', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 
                              'protocol', 'packet_count', 'total_bytes', 'duration_seconds',
                              'tor_confidence', 'is_suspected_tor']
            
            available_flow_cols = [col for col in flow_display_cols if col in display_df.columns]
            
            if available_flow_cols:
                display_df = display_df[available_flow_cols].head(100)  # Limit display
                
                # Format columns
                if 'tor_confidence' in display_df.columns:
                    display_df['tor_confidence'] = display_df['tor_confidence'].apply(lambda x: f"{x:.3f}")
                
                if 'is_suspected_tor' in display_df.columns:
                    display_df['is_suspected_tor'] = display_df['is_suspected_tor'].apply(
                        lambda x: '✅ Yes' if x == 1 else '❌ No'
                    )
                
                st.dataframe(
                    display_df.rename(columns={
                        'flow_id': 'Flow ID',
                        'src_ip': 'Source IP',
                        'src_port': 'Source Port',
                        'dst_ip': 'Destination IP',
                        'dst_port': 'Destination Port',
                        'protocol': 'Protocol',
                        'packet_count': 'Packets',
                        'total_bytes': 'Bytes',
                        'duration_seconds': 'Duration (s)',
                        'tor_confidence': 'Tor Confidence',
                        'is_suspected_tor': 'Suspected Tor'
                    }),
                    use_container_width=True,
                    height=400
                )
    
    # Tab 4: Correlation Results
    with tab4:
        st.markdown('<h2 class="sub-header">Correlation Analysis</h2>', unsafe_allow_html=True)
        
        if st.session_state.correlation_results is None or st.session_state.correlation_results.empty:
            st.info("👈 Run correlation analysis to see results")
        else:
            # Correlation statistics
            st.markdown("### 📊 Correlation Statistics")
            
            stats_col1, stats_col2, stats_col3, stats_col4 = st.columns(4)
            
            with stats_col1:
                high_conf = st.session_state.correlation_stats.get('high_confidence', 0)
                st.metric("High Confidence", high_conf)
            
            with stats_col2:
                total_corr = st.session_state.correlation_stats.get('total_correlations', 0)
                st.metric("Total Correlations", total_corr)
            
            with stats_col3:
                avg_score = st.session_state.correlation_stats.get('avg_total_score', 0)
                st.metric("Average Score", f"{avg_score:.3f}")
            
            with stats_col4:
                unique_nodes = st.session_state.correlation_stats.get('unique_tor_nodes', 0)
                st.metric("Unique Nodes", unique_nodes)
            
            # Score distribution
            st.markdown("### 📈 Score Distribution")
            
            if 'score_distribution' in st.session_state.correlation_stats:
                score_dist = st.session_state.correlation_stats['score_distribution']
                score_df = pd.DataFrame(list(score_dist.items()), columns=['Score Range', 'Count'])
                
                fig = px.bar(
                    score_df,
                    x='Score Range',
                    y='Count',
                    title="Correlation Score Distribution",
                    color='Count',
                    color_continuous_scale='RdYlGn'
                )
                st.plotly_chart(fig, use_container_width=True)
            
            # Correlation table
            st.markdown("### 📋 Correlation Results")
            
            results_df = st.session_state.correlation_results
            
            # Add confidence badges if not present
            if 'confidence_badge' not in results_df.columns and 'total_score' in results_df.columns:
                def get_badge(score):
                    if score >= 0.8: return "🟢 HIGH"
                    elif score >= 0.6: return "🟡 MEDIUM"
                    elif score >= 0.4: return "🟠 LOW"
                    else: return "🔴 WEAK"
                
                results_df['confidence_badge'] = results_df['total_score'].apply(get_badge)
            
            # Display table with filters
            filter_col1, filter_col2 = st.columns(2)
            
            with filter_col1:
                min_score = st.slider(
                    "Minimum Score",
                    min_value=0.0,
                    max_value=1.0,
                    value=0.0,
                    step=0.1
                )
            
            with filter_col2:
                confidence_filter = st.multiselect(
                    "Confidence Level",
                    options=['🟢 HIGH', '🟡 MEDIUM', '🟠 LOW', '🔴 WEAK'],
                    default=['🟢 HIGH', '🟡 MEDIUM']
                )
            
            # Apply filters
            filtered_results = results_df[results_df['total_score'] >= min_score].copy()
            
            if confidence_filter:
                filtered_results = filtered_results[filtered_results['confidence_badge'].isin(confidence_filter)]
            
            # Display table
            display_cols = [
                'confidence_badge', 'tor_node_name', 'tor_node_ip', 'tor_node_country',
                'src_ip', 'dst_ip', 'total_score', 'temporal_score', 'bandwidth_score', 
                'pattern_score'
            ]
            
            available_cols = [col for col in display_cols if col in filtered_results.columns]
            
            if available_cols:
                st.dataframe(
                    filtered_results[available_cols].rename(columns={
                        'confidence_badge': 'Confidence',
                        'tor_node_name': 'Node Name',
                        'tor_node_ip': 'Node IP',
                        'tor_node_country': 'Node Country',
                        'src_ip': 'Source IP',
                        'dst_ip': 'Dest IP',
                        'total_score': 'Total Score',
                        'temporal_score': 'Temporal',
                        'bandwidth_score': 'Bandwidth',
                        'pattern_score': 'Pattern'
                    }),
                    use_container_width=True,
                    height=400
                )
            
        # ================================
        # Generate forensic report
        # ================================
        st.markdown("### 📄 Forensic Report")

        if st.button("Generate Forensic Report"):
            engine = CorrelationEngine()

            report_threshold = 0.6
            report_df = filtered_results[
                filtered_results["total_score"] >= report_threshold
            ].copy()

            engine.results = report_df.to_dict("records")
            engine.correlation_stats = st.session_state.correlation_stats

            report = engine.generate_forensic_report()

            st.subheader("Forensic Correlation Summary")

            st.markdown(f"""
            **Total Correlations:** {len(report_df)}  
            **High Confidence Matches:** {len(report_df[report_df['total_score'] >= 0.8])}  
            **Average Correlation Score:** {report_df['total_score'].mean():.2f}
            """)

            st.markdown("### 🧾 Correlation Attribute Analysis")

            report_df["Suspected Tor"] = report_df["total_score"].apply(
                lambda x: "YES" if x >= 0.6 else "NO"
            )

            report_df["Confidence Level"] = report_df["total_score"].apply(
                lambda x: "HIGH" if x >= 0.8 else "MEDIUM" if x >= 0.6 else "LOW"
            )

            report_df["Evidence Strength"] = report_df["total_score"].apply(
                lambda x: "Strong multi-factor correlation"
                if x >= 0.8 else
                "Moderate Tor-like behavior"
                if x >= 0.6 else
                "Weak or inconclusive"
            )

            st.dataframe(
                report_df[[
                    "Suspected Tor",
                    "Confidence Level",
                    "tor_node_name",
                    "tor_node_ip",
                    "tor_node_country",
                    "src_ip",
                    "dst_ip",
                    "total_score",
                    "Evidence Strength"
                ]],
                use_container_width=True,
                height=320
            )

            st.markdown("### 📄 Detailed Forensic Report")
            st.text_area("Report Content", report, height=350)



# Run the app
if __name__ == "__main__":
    main()
