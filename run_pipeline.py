import sys
import os

# Add modules directory to path
sys.path.append('modules')


from modules.path_reconstructor import PathReconstructor
from modules.visualization import NetworkVisualizer
from modules.report import ReportGenerator
from tor_map import TorNetworkMapper
from pcap_parser import PCAPAnalyzer
from correlator import CorrelationEngine


def run_complete_pipeline(pcap_file=None):
    """
    Run the complete TOR-Unveil pipeline
    1. Fetch Tor network data
    2. Analyze PCAP file
    3. Run correlation
    4. Generate report
    """
    print("="*60)
    print("🔍 TOR-UNVEIL FORENSIC PIPELINE")
    print("="*60)
    
    # Step 1: Fetch Tor network data
    print("\n📥 STEP 1: Fetching Tor network data...")
    tor_mapper = TorNetworkMapper()
    tor_df, tor_metrics = tor_mapper.get_tor_data(force_refresh=False)
    
    if tor_df.empty:
        print("❌ Failed to get Tor network data")
        return False
    
    print(f"✅ Tor data: {len(tor_df)} nodes loaded")
    print(f"   Guard nodes: {tor_metrics.get('guard_count', 0)}")
    print(f"   Exit nodes: {tor_metrics.get('exit_count', 0)}")
    
    # Step 2: Analyze PCAP file
    print("\n📊 STEP 2: Analyzing network traffic...")
    pcap_analyzer = PCAPAnalyzer()
    
    if pcap_file and os.path.exists(pcap_file):
        print(f"📂 Analyzing PCAP: {pcap_file}")
        flows_df, flow_stats = pcap_analyzer.analyze_and_export(pcap_file)
    else:
        print("⚠️ No PCAP file provided, using existing flow data")
        flows_df = pcap_analyzer.load_from_csv()
        flow_stats = pcap_analyzer.get_flow_statistics(flows_df)
    
    if flows_df.empty:
        print("❌ Failed to get flow data")
        return False
    
    print(f"✅ Flow data: {len(flows_df)} flows loaded")
    print(f"   Suspected Tor flows: {flow_stats.get('suspected_tor_flows', 0)}")
    print(f"   Total packets: {flow_stats.get('total_packets', 0):,}")
    
    # Step 3: Run correlation
    print("\n🔗 STEP 3: Running correlation engine...")
    correlation_engine = CorrelationEngine()
    correlation_engine.tor_nodes_df = tor_df
    correlation_engine.flows_df = flows_df
    
    results_df = correlation_engine.run_correlation()
    
    if results_df.empty:
        print("❌ No correlations found")
        return False

    # Step 4: Reconstruct Tor paths
    print("\n🧭 STEP 4: Reconstructing Tor paths...")
    path_reconstructor = PathReconstructor()
    paths_df = path_reconstructor.reconstruct_paths(
        correlation_df=results_df,
        tor_nodes_df=tor_df
    )

    print(f"✅ Reconstructed {len(paths_df)} possible Tor paths")

    # Step 5: Prepare visualization data
    print("\n📊 STEP 5: Preparing network visualization...")
    visualizer = NetworkVisualizer()
    graph_data = visualizer.build_graph(paths_df)

    print("✅ Network graph data prepared")

    # Step 6: Generate forensic report
    print("\n📄 STEP 6: Generating forensic report...")
    reporter = ReportGenerator()
    report_file = reporter.generate(
        tor_nodes_df=tor_df,
        flows_df=flows_df,
        correlation_df=results_df,
        paths_df=paths_df
    )

    print(f"✅ Forensic report generated: {report_file}")
    
    print(f"✅ Correlation complete: {len(results_df)} matches found")
    print(f"   High confidence: {correlation_engine.correlation_stats.get('high_confidence', 0)}")
    print(f"   Average score: {correlation_engine.correlation_stats.get('avg_total_score', 0):.3f}")
    
    # Step 4: Generate report
    print("\n📄 STEP 4: Generating forensic report...")
    report_file = correlation_engine.export_report()
    
    print(f"\n🎉 PIPELINE COMPLETE!")
    print("-"*40)
    print(f"📁 Data files:")
    print(f"   Tor nodes: data/tor_nodes.csv")
    print(f"   Network flows: data/pcap_flows.csv")
    print(f"   Correlation results: data/correlation_results.csv")
    print(f"   Forensic report: {report_file}")
    
    # Show summary
    top_results = results_df.head(5)
    if not top_results.empty:
        print(f"\n🏆 TOP CORRELATIONS:")
        for idx, row in top_results.iterrows():
            print(f"   {idx+1}. {row['tor_node_name']} → Score: {row['total_score']:.3f}")
    
    return True


def check_dependencies():
    """Check if required modules are installed"""
    print("🔍 Checking dependencies...")
    
    missing_deps = []
    
    try:
        import pandas
        print("✅ pandas")
    except ImportError:
        missing_deps.append("pandas")
    
    try:
        import numpy
        print("✅ numpy")
    except ImportError:
        missing_deps.append("numpy")
    
    try:
        import requests
        print("✅ requests")
    except ImportError:
        missing_deps.append("requests")
    
    # Scapy is optional
    try:
        import scapy
        print("✅ scapy (optional)")
    except ImportError:
        print("⚠️  scapy not installed (PCAP analysis will use sample data)")
    
    if missing_deps:
        print(f"\n❌ Missing dependencies: {', '.join(missing_deps)}")
        print("   Install with: pip install " + " ".join(missing_deps))
        return False
    
    return True


def main():
    """Main function"""
    
    # Check dependencies
    if not check_dependencies():
        return
    
    # Parse command line arguments
    pcap_file = None
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
        if not os.path.exists(pcap_file):
            print(f"❌ PCAP file not found: {pcap_file}")
            pcap_file = None
    
    # Run pipeline
    print("\n" + "="*60)
    success = run_complete_pipeline(pcap_file)
    
    if success:
        print("\n✅ Pipeline executed successfully!")
    else:
        print("\n❌ Pipeline failed")


if __name__ == "__main__":
    main()
