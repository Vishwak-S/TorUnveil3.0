"""
correlator.py - Correlation engine using CSV data
"""
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict,Tuple, List, Optional
import os
import json

class CorrelationEngine:
    """
    Correlation engine that matches PCAP flows with Tor nodes
    Uses weighted scoring: temporal (50%), bandwidth (30%), pattern (20%)
    Reads data from CSV files
    """
    
    def __init__(self, data_dir="data"):
        self.data_dir = data_dir
        self.tor_nodes_csv = os.path.join(data_dir, "tor_nodes.csv")
        self.pcap_flows_csv = os.path.join(data_dir, "pcap_flows.csv")
        
        self.tor_nodes_df = None
        self.flows_df = None
        self.results = []
        self.correlation_stats = {}
        
        # Ensure data directory exists
        os.makedirs(data_dir, exist_ok=True)
    
    def load_data_from_csv(self) -> bool:
        """
        Load data from CSV files
        Returns: True if successful, False otherwise
        """
        print("📂 Loading data from CSV files...")
        
        try:
            # Load Tor nodes
            if os.path.exists(self.tor_nodes_csv):
                self.tor_nodes_df = pd.read_csv(self.tor_nodes_csv)
                print(f"✅ Loaded {len(self.tor_nodes_df)} Tor nodes from {self.tor_nodes_csv}")
            else:
                print(f"⚠️ Tor nodes CSV not found: {self.tor_nodes_csv}")
                print("   Creating sample Tor data...")
                self._create_sample_tor_data()
            
            # Load PCAP flows
            if os.path.exists(self.pcap_flows_csv):
                self.flows_df = pd.read_csv(self.pcap_flows_csv)
                print(f"✅ Loaded {len(self.flows_df)} flows from {self.pcap_flows_csv}")
            else:
                print(f"⚠️ PCAP flows CSV not found: {self.pcap_flows_csv}")
                print("   Creating sample flow data...")
                self._create_sample_flow_data()
            
            # Basic data validation
            if self.tor_nodes_df.empty:
                print("❌ No Tor nodes data available")
                return False
            
            if self.flows_df.empty:
                print("❌ No flow data available")
                return False
            
            print(f"📊 Data loaded: {len(self.tor_nodes_df)} Tor nodes, {len(self.flows_df)} flows")
            return True
            
        except Exception as e:
            print(f"❌ Error loading data: {e}")
            return False
    
    def _create_sample_tor_data(self):
        """Create sample Tor data if CSV doesn't exist"""
        sample_data = []
        for i in range(50):
            sample_data.append({
                'fingerprint': f'ABCD{i:04d}',
                'fingerprint_short': f'ABCD{i:04d}'[:8],
                'nickname': f'TorNode{i}',
                'ip_address': f'185.220.101.{i % 255}',
                'role': 'Guard' if i < 20 else 'Exit' if i < 40 else 'Relay',
                'country_name': 'Germany' if i % 3 == 0 else 'United States' if i % 3 == 1 else 'Netherlands',
                'observed_bandwidth_mbps': 10 * (i + 1),
                'uptime_days': 30 + i,
                'is_guard': 1 if i < 20 else 0,
                'is_exit': 1 if 20 <= i < 40 else 0,
                'is_stable': 1,
                'is_fast': 1,
                'first_seen': (datetime.now() - timedelta(days=30)).isoformat(),
                'last_seen': datetime.now().isoformat()
            })
        
        self.tor_nodes_df = pd.DataFrame(sample_data)
        print(f"📝 Created {len(self.tor_nodes_df)} sample Tor nodes")
    
    def _create_sample_flow_data(self):
        """Create sample flow data if CSV doesn't exist"""
        sample_data = []
        base_time = datetime.now().timestamp()
        
        for i in range(20):
            dst_port = 443 if i % 3 == 0 else 9001 if i % 3 == 1 else 80
            tor_ip = f"185.220.101.{i % 10 + 1}" if dst_port in [443, 9001] else f"8.8.8.{i % 10 + 1}"
            
            sample_data.append({
                'flow_id': f'flow_{i:04d}',
                'src_ip': f'192.168.1.{i % 50 + 1}',
                'dst_ip': tor_ip,
                'src_port': 40000 + i,
                'dst_port': dst_port,
                'protocol': 'TCP',
                'start_time': base_time - (i * 60),
                'duration_seconds': 10 + (i * 2),
                'packet_count': 50 + (i * 10),
                'total_bytes': (50 + (i * 10)) * 586,
                'avg_packet_size': 586,
                'tor_confidence': 0.7 if dst_port in [443, 9001] else 0.2,
                'is_suspected_tor': 1 if dst_port in [443, 9001] else 0,
                'tor_evidence': 'Tor port match' if dst_port in [443, 9001] else 'Regular traffic'
            })
        
        self.flows_df = pd.DataFrame(sample_data)
        print(f"📝 Created {len(self.flows_df)} sample flows")
    
    def run_correlation(self, focus_on_suspected_tor=True) -> pd.DataFrame:
        """
        Main correlation algorithm
        Args:
            focus_on_suspected_tor: If True, only correlate flows marked as suspected Tor
        Returns:
            DataFrame with correlation results
        """
        print("\n🚀 Starting correlation engine...")
        print("="*60)
        
        # Load data if not already loaded
        if self.tor_nodes_df is None or self.flows_df is None:
            if not self.load_data_from_csv():
                print("❌ Failed to load data")
                return pd.DataFrame()
        
        # Filter flows if needed
        if focus_on_suspected_tor and 'is_suspected_tor' in self.flows_df.columns:
            target_flows = self.flows_df[self.flows_df['is_suspected_tor'] == 1].copy()
            print(f"🔍 Focusing on {len(target_flows)} suspected Tor flows")
        else:
            target_flows = self.flows_df.copy()
            print(f"🔍 Analyzing all {len(target_flows)} flows")
        
        if len(target_flows) == 0:
            print("⚠️ No flows to analyze")
            return pd.DataFrame()
        
        # Get Guard nodes for correlation (most relevant for entry nodes)
        guard_nodes = self.tor_nodes_df[
            (self.tor_nodes_df['is_guard'] == 1) | 
            (self.tor_nodes_df['role'].str.contains('Guard'))
        ].copy()
        
        print(f"🎯 Targeting {len(guard_nodes)} Guard nodes")
        
        # Run correlation for each flow
        all_results = []
        
        for flow_idx, flow in target_flows.iterrows():
            flow_results = self._correlate_flow_with_nodes(flow, guard_nodes)
            all_results.extend(flow_results)
            
            # Show progress
            if (flow_idx + 1) % 5 == 0 or (flow_idx + 1) == len(target_flows):
                print(f"   Processed {flow_idx + 1}/{len(target_flows)} flows")
        
        # Convert to DataFrame
        if all_results:
            results_df = pd.DataFrame(all_results)
            
            # Sort by total score
            results_df = results_df.sort_values('total_score', ascending=False)
            
            # Add confidence badges
            results_df['confidence_badge'] = results_df['total_score'].apply(self._get_confidence_badge)
            
            # Calculate statistics
            self.correlation_stats = self._calculate_correlation_stats(results_df)
            
            # Store results
            self.results = results_df.to_dict('records')
            
            print(f"\n✅ Correlation complete!")
            print(f"📈 Generated {len(results_df)} correlations")
            print(f"🏆 Top score: {results_df['total_score'].max():.3f}")
            print(f"📊 Average score: {results_df['total_score'].mean():.3f}")
            
            # Save results to CSV
            results_csv = os.path.join(self.data_dir, "correlation_results.csv")
            results_df.to_csv(results_csv, index=False)
            print(f"💾 Saved results to {results_csv}")
            
            return results_df
        else:
            print("❌ No correlations found")
            return pd.DataFrame()
    
    def _correlate_flow_with_nodes(self, flow: pd.Series, nodes_df: pd.DataFrame) -> List[Dict]:
        """Correlate a single flow with multiple Tor nodes"""
        flow_results = []
        
        # Pre-filter nodes for this flow
        candidate_nodes = self._prefilter_nodes_for_flow(flow, nodes_df)
        
        if len(candidate_nodes) == 0:
            return []
        
        # Score each candidate node
        for node_idx, node in candidate_nodes.iterrows():
            scores = self._calculate_scores(flow, node)
            
            # Only include if total score > 0
            if scores['total_score'] > 0:
                result = {
                    'flow_id': flow.get('flow_id', 'unknown'),
                    'src_ip': flow.get('src_ip', ''),
                    'dst_ip': flow.get('dst_ip', ''),
                    'src_port': flow.get('src_port', 0),
                    'dst_port': flow.get('dst_port', 0),
                    'tor_node_ip': node.get('ip_address', ''),
                    'tor_node_name': node.get('nickname', ''),
                    'tor_node_role': node.get('role', ''),
                    'tor_node_country': node.get('country_name', ''),
                    'tor_node_as': node.get('as_name', ''),
                    'flow_duration_seconds': flow.get('duration_seconds', 0),
                    'flow_packet_count': flow.get('packet_count', 0),
                    'flow_total_bytes': flow.get('total_bytes', 0),
                    'flow_tor_confidence': flow.get('tor_confidence', 0),
                    
                    # Individual scores
                    'temporal_score': scores['temporal_score'],
                    'bandwidth_score': scores['bandwidth_score'],
                    'pattern_score': scores['pattern_score'],
                    
                    # Final score
                    'total_score': scores['total_score'],
                    
                    # Evidence summary
                    'evidence_summary': scores['evidence_summary'],
                    
                    # Timestamps
                    'correlation_time': datetime.now().isoformat(),
                }
                
                flow_results.append(result)
        
        # Return top N results for this flow
        return sorted(flow_results, key=lambda x: x['total_score'], reverse=True)[:5]
    
    def _prefilter_nodes_for_flow(self, flow: pd.Series, nodes_df: pd.DataFrame) -> pd.DataFrame:
        """Pre-filter nodes to reduce computation"""
        candidates = nodes_df.copy()
        
        # 1. IP-based filtering (exact match with destination IP)
        dst_ip = flow.get('dst_ip', '')
        if dst_ip:
            ip_matches = candidates[candidates['ip_address'] == dst_ip]
            if len(ip_matches) > 0:
                # Direct IP match is strongest evidence
                print(f"   Found direct IP match for {dst_ip}")
                return ip_matches
        
        # 2. Country-based filtering (if we have geographical hints)
        # Note: This is simplified - real implementation would use GeoIP
        
        # 3. Return limited candidates for performance
        return candidates.head(20)
    
    def _calculate_scores(self, flow: pd.Series, node: pd.Series) -> Dict[str, float]:
        """Calculate all scores for a flow-node pair"""
        
        # 1. Temporal matching (50% weight)
        temporal_score, temporal_evidence = self._calculate_temporal_score(flow, node)
        
        # 2. Bandwidth feasibility (30% weight)
        bandwidth_score, bandwidth_evidence = self._calculate_bandwidth_score(flow, node)
        
        # 3. Pattern similarity (20% weight)
        pattern_score, pattern_evidence = self._calculate_pattern_score(flow, node)
        
        # Calculate weighted scores
        temporal_weighted = temporal_score * 0.5
        bandwidth_weighted = bandwidth_score * 0.3
        pattern_weighted = pattern_score * 0.2
        
        # Total score
        total_score = temporal_weighted + bandwidth_weighted + pattern_weighted
        
        # Evidence summary
        evidence_parts = []
        if temporal_evidence:
            evidence_parts.append(f"Temporal: {temporal_evidence}")
        if bandwidth_evidence:
            evidence_parts.append(f"Bandwidth: {bandwidth_evidence}")
        if pattern_evidence:
            evidence_parts.append(f"Pattern: {pattern_evidence}")
        
        evidence_summary = " | ".join(evidence_parts) if evidence_parts else "Limited evidence"
        
        return {
            'temporal_score': round(temporal_score, 3),
            'bandwidth_score': round(bandwidth_score, 3),
            'pattern_score': round(pattern_score, 3),
            'temporal_weighted': round(temporal_weighted, 3),
            'bandwidth_weighted': round(bandwidth_weighted, 3),
            'pattern_weighted': round(pattern_weighted, 3),
            'total_score': round(total_score, 3),
            'evidence_summary': evidence_summary,
        }
    
    def _calculate_temporal_score(self, flow: pd.Series, node: pd.Series) -> Tuple[float, str]:
        """Calculate temporal matching score (0-1)"""
        
        # Method 1: Direct IP match (strongest evidence)
        if flow.get('dst_ip', '') == node.get('ip_address', ''):
            return 1.0, "IP exact match"
        
        # Method 2: Check if node was recently active
        if 'last_seen' in node and pd.notna(node['last_seen']):
            try:
                # Simplified: assume recent if we have data
                return 0.7, "Node recently active"
            except:
                pass
        
        # Method 3: Node uptime
        if 'uptime_days' in node and node['uptime_days'] > 30:
            score = min(0.6, node['uptime_days'] / 365)
            return score, f"Long uptime ({node['uptime_days']} days)"
        
        # Default: minimal score
        return 0.1, "No strong temporal evidence"
    
    def _calculate_bandwidth_score(self, flow: pd.Series, node: pd.Series) -> Tuple[float, str]:
        """Calculate bandwidth feasibility score (0-1)"""
        
        # Get flow bandwidth requirements (simplified)
        flow_bps = flow.get('total_bytes', 0) * 8 / flow.get('duration_seconds', 1)
        
        # Get node capacity (convert Mbps to bps)
        node_bw_bps = node.get('observed_bandwidth_mbps', 0) * 1_000_000
        if node_bw_bps <= 0:
            node_bw_bps = 10_000_000  # 10 Mbps default
        
        # Calculate ratio
        if node_bw_bps > 0:
            utilization_ratio = flow_bps / node_bw_bps
            
            # Score based on utilization (lower is better)
            if utilization_ratio <= 0.1:
                score = 1.0
                evidence = f"Node has 10x capacity ({utilization_ratio:.1%} utilization)"
            elif utilization_ratio <= 0.5:
                score = 0.8
                evidence = f"Node has 2x capacity ({utilization_ratio:.1%} utilization)"
            elif utilization_ratio <= 1.0:
                score = 0.5
                evidence = f"Node matches capacity ({utilization_ratio:.1%} utilization)"
            elif utilization_ratio <= 2.0:
                score = 0.2
                evidence = f"Flow exceeds capacity ({utilization_ratio:.1%} utilization)"
            else:
                score = 0.0
                evidence = f"Flow greatly exceeds capacity ({utilization_ratio:.1%} utilization)"
        else:
            score = 0.3
            evidence = "Unknown node capacity"
        
        # Adjust for high-bandwidth nodes
        if node_bw_bps > 10_000_000:  # > 10 Mbps
            score = min(1.0, score * 1.2)
            evidence += ", high-capacity node"
        
        return min(1.0, score), evidence
    
    def _calculate_pattern_score(self, flow: pd.Series, node: pd.Series) -> Tuple[float, str]:
        """Calculate pattern similarity score (0-1)"""
        
        score = 0.0
        evidence_parts = []
        
        # 1. Check if flow fingerprint suggests Tor traffic
        flow_tor_confidence = flow.get('tor_confidence', 0)
        if flow_tor_confidence > 0.7:
            score += 0.4
            evidence_parts.append(f"High Tor confidence ({flow_tor_confidence:.2f})")
        elif flow_tor_confidence > 0.4:
            score += 0.2
            evidence_parts.append(f"Medium Tor confidence ({flow_tor_confidence:.2f})")
        
        # 2. Check if node is a known Guard
        node_role = node.get('role', '')
        if 'Guard' in node_role:
            score += 0.3
            evidence_parts.append(f"Guard node")
        
        # 3. Check if flow uses common Tor ports
        dst_port = flow.get('dst_port', 0)
        if dst_port in [443, 9001]:
            score += 0.2
            evidence_parts.append(f"Tor port {dst_port}")
        
        # 4. Check packet size patterns
        avg_packet_size = flow.get('avg_packet_size', 0)
        if 580 < avg_packet_size < 600:  # Standard Tor cell size
            score += 0.1
            evidence_parts.append("Standard cell size")
        
        evidence = ", ".join(evidence_parts) if evidence_parts else "Limited pattern evidence"
        
        return min(1.0, score), evidence
    
    def _get_confidence_badge(self, score: float) -> str:
        """Convert score to confidence badge"""
        if score >= 0.8:
            return "🟢 HIGH"
        elif score >= 0.6:
            return "🟡 MEDIUM"
        elif score >= 0.4:
            return "🟠 LOW"
        else:
            return "🔴 WEAK"
    
    def _calculate_correlation_stats(self, results_df: pd.DataFrame) -> Dict:
        """Calculate statistics about correlation results"""
        if results_df.empty:
            return {}
        
        stats = {
            'total_correlations': len(results_df),
            'high_confidence': len(results_df[results_df['total_score'] >= 0.8]),
            'medium_confidence': len(results_df[results_df['total_score'] >= 0.6]),
            'low_confidence': len(results_df[results_df['total_score'] >= 0.4]),
            'weak_confidence': len(results_df[results_df['total_score'] < 0.4]),
            'avg_total_score': results_df['total_score'].mean(),
            'avg_temporal_score': results_df['temporal_score'].mean(),
            'avg_bandwidth_score': results_df['bandwidth_score'].mean(),
            'avg_pattern_score': results_df['pattern_score'].mean(),
            'unique_tor_nodes': results_df['tor_node_ip'].nunique(),
            'unique_flows': results_df['flow_id'].nunique(),
            'top_countries': results_df['tor_node_country'].value_counts().head(5).to_dict(),
        }
        
        # Calculate score distribution
        score_bins = [0, 0.2, 0.4, 0.6, 0.8, 1.01]
        score_labels = ['0-0.2', '0.2-0.4', '0.4-0.6', '0.6-0.8', '0.8-1.0']
        
        results_df['score_bin'] = pd.cut(
            results_df['total_score'],
            bins=score_bins,
            labels=score_labels,
            right=False
        )
        stats['score_distribution'] = results_df['score_bin'].value_counts().to_dict()
        
        return stats
    
    def get_top_correlations(self, n: int = 20) -> pd.DataFrame:
        """Get top N correlations"""
        if hasattr(self, 'results') and self.results:
            results_df = pd.DataFrame(self.results)
            return results_df.head(n)
        
        # Try to load from CSV
        results_csv = os.path.join(self.data_dir, "correlation_results.csv")
        if os.path.exists(results_csv):
            results_df = pd.read_csv(results_csv)
            return results_df.head(n)
        
        return pd.DataFrame()
    
    def generate_forensic_report(self) -> str:
        """Generate a comprehensive forensic report"""
        if not self.results:
            # Try to load from CSV
            results_csv = os.path.join(self.data_dir, "correlation_results.csv")
            if os.path.exists(results_csv):
                results_df = pd.read_csv(results_csv)
                self.results = results_df.to_dict('records')
                if self.correlation_stats == {}:
                    self.correlation_stats = self._calculate_correlation_stats(results_df)
            else:
                return "No correlation results available."
        
        report = []
        report.append("=" * 70)
        report.append("TOR-UNVEIL FORENSIC CORRELATION REPORT")
        report.append("=" * 70)
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append(f"Total Correlations: {len(self.results)}")
        report.append(f"Data Source: {self.data_dir}/")
        report.append("")
        
        # Summary statistics
        if self.correlation_stats:
            report.append("SUMMARY STATISTICS")
            report.append("-" * 40)
            report.append(f"High Confidence Correlations: {self.correlation_stats.get('high_confidence', 0)}")
            report.append(f"Medium Confidence Correlations: {self.correlation_stats.get('medium_confidence', 0)}")
            report.append(f"Average Total Score: {self.correlation_stats.get('avg_total_score', 0):.3f}")
            report.append(f"Unique Tor Nodes Involved: {self.correlation_stats.get('unique_tor_nodes', 0)}")
            report.append(f"Unique Flows Correlated: {self.correlation_stats.get('unique_flows', 0)}")
            report.append("")
        
        # Top correlations
        top_results = self.get_top_correlations(10)
        if not top_results.empty:
            report.append("TOP 10 CORRELATIONS")
            report.append("-" * 40)
            
            for idx, row in top_results.iterrows():
                report.append(f"{idx + 1}. {row['tor_node_name']} ({row['tor_node_ip']})")
                report.append(f"   Flow: {row['src_ip']}:{row['src_port']} → {row['dst_ip']}:{row['dst_port']}")
                report.append(f"   Score: {row['total_score']:.3f} ({row.get('confidence_badge', 'N/A')})")
                report.append(f"   Evidence: {row.get('evidence_summary', 'N/A')}")
                report.append("")
        
        # Methodology
        report.append("METHODOLOGY")
        report.append("-" * 40)
        report.append("Weighted Scoring Model:")
        report.append("  • Temporal Matching: 50% (IP/timestamp alignment)")
        report.append("  • Bandwidth Feasibility: 30% (capacity analysis)")
        report.append("  • Pattern Similarity: 20% (Tor traffic fingerprints)")
        report.append("")
        report.append("Data Sources:")
        report.append(f"  • Tor Nodes: {self.tor_nodes_csv}")
        report.append(f"  • Network Flows: {self.pcap_flows_csv}")
        report.append("")
        
        # Limitations
        report.append("LIMITATIONS AND DISCLAIMERS")
        report.append("-" * 40)
        report.append("1. Correlation does not imply causation")
        report.append("2. Scores represent likelihood, not certainty")
        report.append("3. Tor network is dynamic; nodes change frequently")
        report.append("4. Results should be corroborated with other evidence")
        report.append("5. Always follow legal and ethical guidelines")
        
        report.append("=" * 70)
        
        return "\n".join(report)
    
    def export_report(self, output_file: str = None) -> str:
        """Export forensic report to file"""
        if output_file is None:
            output_file = os.path.join(self.data_dir, "forensic_report.txt")
        
        report = self.generate_forensic_report()
        
        with open(output_file, 'w') as f:
            f.write(report)
        
        print(f"📄 Saved forensic report to {output_file}")
        return output_file

# Helper function for backward compatibility
def run_correlation(data_dir="data") -> pd.DataFrame:
    """Legacy interface for backward compatibility"""
    engine = CorrelationEngine(data_dir)
    return engine.run_correlation()

def test_correlation_module():
    """Test the correlation engine module"""
    print("🧪 Testing correlation engine module...")
    print("="*60)
    
    # Test with sample data
    engine = CorrelationEngine()
    
    # First, ensure we have data
    if not engine.load_data_from_csv():
        print("❌ Failed to load data")
        return False
    
    # Run correlation
    results = engine.run_correlation()
    
    if not results.empty:
        print("\n📊 CORRELATION RESULTS:")
        print("-"*60)
        print(f"Total correlations found: {len(results)}")
        print(f"Top score: {results['total_score'].max():.3f}")
        print(f"Average score: {results['total_score'].mean():.3f}")
        
        # Show top 3 correlations
        print("\n🏆 TOP 3 CORRELATIONS:")
        print("-"*40)
        top_3 = results.head(3)
        for idx, row in top_3.iterrows():
            print(f"{idx + 1}. {row['tor_node_name']} ({row['tor_node_ip']})")
            print(f"   Flow: {row['src_ip']}:{row['src_port']} → {row['dst_ip']}:{row['dst_port']}")
            print(f"   Score: {row['total_score']:.3f} ({row['confidence_badge']})")
            print(f"   Evidence: {row['evidence_summary']}")
            print()
        
        # Generate report
        print("📄 FORENSIC REPORT (first 20 lines):")
        print("-"*40)
        report = engine.generate_forensic_report()
        report_lines = report.split('\n')[:20]
        for line in report_lines:
            print(line)
        
        # Export report
        engine.export_report()
        
        print("\n✅ Correlation engine module test PASSED!")
        return True
    else:
        print("❌ Correlation engine module test FAILED - no results")
        return False

if __name__ == "__main__":
    # Run test
    test_correlation_module()
