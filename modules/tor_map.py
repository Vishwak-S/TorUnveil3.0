"""
tor_map.py - Tor network mapper with CSV export
"""
import pandas as pd
import requests
import json
from datetime import datetime
import os
from typing import Tuple, Dict

class TorNetworkMapper:
    """Fetch Tor network data and export to CSV"""
    
    def __init__(self, output_dir="data"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.csv_path = os.path.join(output_dir, "tor_nodes.csv")
    
    def fetch_tor_data(self, limit=200) -> pd.DataFrame:
        """Fetch Tor relay data from Onionoo API"""
        print("🌐 Fetching Tor network data...")
        
        try:
            url = f"https://onionoo.torproject.org/details?limit={limit}"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            relays = data.get('relays', [])
            
            print(f"✅ Fetched {len(relays)} Tor relays")
            return self._process_relays(relays)
            
        except Exception as e:
            print(f"❌ Error fetching Tor data: {e}")
            return self._create_sample_tor_data()
    
    def _process_relays(self, relays: list) -> pd.DataFrame:
        """Process raw relay data"""
        processed = []
        
        for relay in relays:
            try:
                # Extract IP address
                ip_address = ""
                or_addresses = relay.get('or_addresses', [])
                if or_addresses:
                    addr = or_addresses[0]
                    if ':' in addr and '[' not in addr:
                        ip_address = addr.split(':')[0]
                
                # Determine role
                flags = relay.get('flags', [])
                if 'Guard' in flags and 'Exit' in flags:
                    role = 'Guard+Exit'
                elif 'Guard' in flags:
                    role = 'Guard'
                elif 'Exit' in flags:
                    role = 'Exit'
                else:
                    role = 'Relay'
                
                record = {
                    'fingerprint': relay.get('fingerprint', ''),
                    'fingerprint_short': relay.get('fingerprint', '')[:8],
                    'nickname': relay.get('nickname', 'Unknown'),
                    'ip_address': ip_address,
                    'role': role,
                    'country_name': relay.get('country_name', 'Unknown'),
                    'country_code': relay.get('country', ''),
                    'as_name': relay.get('as_name', ''),
                    'observed_bandwidth_bps': relay.get('observed_bandwidth', 0),
                    'advertised_bandwidth_bps': relay.get('advertised_bandwidth', 0),
                    'first_seen': relay.get('first_seen', ''),
                    'last_seen': relay.get('last_seen', ''),
                    'flags': ','.join(flags),
                    'is_guard': 1 if 'Guard' in flags else 0,
                    'is_exit': 1 if 'Exit' in flags else 0,
                    'is_stable': 1 if 'Stable' in flags else 0,
                    'is_fast': 1 if 'Fast' in flags else 0,
                    'fetched_at': datetime.now().isoformat()
                }
                
                # Convert bandwidth to Mbps for easier reading
                record['observed_bandwidth_mbps'] = round(record['observed_bandwidth_bps'] / 1_000_000, 2)
                record['advertised_bandwidth_mbps'] = round(record['advertised_bandwidth_bps'] / 1_000_000, 2)
                
                # Calculate uptime days
                if record['first_seen'] and record['last_seen']:
                    try:
                        first = datetime.fromisoformat(record['first_seen'].replace('Z', '+00:00'))
                        last = datetime.fromisoformat(record['last_seen'].replace('Z', '+00:00'))
                        record['uptime_days'] = (last - first).days
                    except:
                        record['uptime_days'] = 0
                else:
                    record['uptime_days'] = 0
                
                processed.append(record)
                
            except Exception as e:
                print(f"⚠️ Error processing relay: {e}")
                continue
        
        return pd.DataFrame(processed)
    
    def _create_sample_tor_data(self) -> pd.DataFrame:
        """Create sample data if API fails"""
        print("⚠️ Creating sample Tor data for testing")
        
        sample_data = []
        for i in range(50):
            sample_data.append({
                'fingerprint': f'ABCD{i:04d}',
                'fingerprint_short': f'ABCD{i:04d}'[:8],
                'nickname': f'TorNode{i}',
                'ip_address': f'185.220.101.{i % 255}',
                'role': 'Guard' if i < 20 else 'Exit' if i < 40 else 'Relay',
                'country_name': 'Germany' if i % 3 == 0 else 'United States' if i % 3 == 1 else 'Netherlands',
                'country_code': 'DE' if i % 3 == 0 else 'US' if i % 3 == 1 else 'NL',
                'as_name': f'AS{i:04d} Network',
                'observed_bandwidth_bps': 10_000_000 * (i + 1),
                'advertised_bandwidth_bps': 10_000_000 * (i + 1),
                'observed_bandwidth_mbps': 10 * (i + 1),
                'advertised_bandwidth_mbps': 10 * (i + 1),
                'first_seen': (datetime.now() - pd.Timedelta(days=30)).isoformat(),
                'last_seen': datetime.now().isoformat(),
                'flags': 'Fast,Stable,Running',
                'is_guard': 1 if i < 20 else 0,
                'is_exit': 1 if 20 <= i < 40 else 0,
                'is_stable': 1,
                'is_fast': 1,
                'uptime_days': 30 + i,
                'fetched_at': datetime.now().isoformat()
            })
        
        return pd.DataFrame(sample_data)
    
    def export_to_csv(self, df: pd.DataFrame = None) -> str:
        """Export Tor data to CSV file"""
        if df is None:
            df = self.fetch_tor_data()
        
        if df.empty:
            print("⚠️ No data to export")
            return ""
        
        # Save to CSV
        df.to_csv(self.csv_path, index=False)
        print(f"💾 Exported {len(df)} Tor nodes to {self.csv_path}")
        
        return self.csv_path
    
    def load_from_csv(self) -> pd.DataFrame:
        """Load Tor data from CSV file"""
        try:
            df = pd.read_csv(self.csv_path)
            print(f"📂 Loaded {len(df)} Tor nodes from {self.csv_path}")
            return df
        except FileNotFoundError:
            print(f"❌ CSV file not found: {self.csv_path}")
            return pd.DataFrame()
    
    def get_tor_data(self, force_refresh=False) -> Tuple[pd.DataFrame, Dict]:
        """Main method to get Tor data (load from CSV or fetch fresh)"""
        if not force_refresh:
            df = self.load_from_csv()
            if not df.empty:
                return df, self._calculate_metrics(df)
        
        # Fetch fresh data
        df = self.fetch_tor_data()
        if not df.empty:
            self.export_to_csv(df)
            return df, self._calculate_metrics(df)
        
        return pd.DataFrame(), {}
    
    def _calculate_metrics(self, df: pd.DataFrame) -> Dict:
        """Calculate dashboard metrics"""
        if df.empty:
            return {}
        
        return {
            'total_relays': len(df),
            'guard_count': df['is_guard'].sum(),
            'exit_count': df['is_exit'].sum(),
            'total_bandwidth_gbps': round(df['observed_bandwidth_bps'].sum() / 1_000_000_000, 2),
            'country_count': df['country_name'].nunique(),
            'avg_bandwidth_mbps': round(df['observed_bandwidth_mbps'].mean(), 2)
        }

# Helper function for backward compatibility
def get_tor_map(use_cache=True) -> Tuple[pd.DataFrame, Dict]:
    mapper = TorNetworkMapper()
    return mapper.get_tor_data(force_refresh=not use_cache)

if __name__ == "__main__":
    # Test the module
    mapper = TorNetworkMapper()
    df, metrics = mapper.get_tor_data()
    
    if not df.empty:
        print(f"\n📊 Tor Data Metrics:")
        print(f"   Total Relays: {metrics.get('total_relays', 0)}")
        print(f"   Guard Nodes: {metrics.get('guard_count', 0)}")
        print(f"   Exit Nodes: {metrics.get('exit_count', 0)}")
        print(f"   Total Bandwidth: {metrics.get('total_bandwidth_gbps', 0)} Gbps")
        
        print(f"\n📄 Sample data saved to: {mapper.csv_path}")
        print(f"📋 First few rows:")
        print(df[['nickname', 'ip_address', 'role', 'country_name', 'observed_bandwidth_mbps']].head())

