#!/usr/bin/env python3
import sqlite3
import sys
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta

try:
    from netaddr import EUI
    HAS_MAC_LOOKUP = True
except ImportError:
    HAS_MAC_LOOKUP = False
    print("Warning: netaddr not installed. Install with: pip3 install netaddr")

# Helper functions
def format_duration(seconds):
    """Format duration in seconds to human-readable string"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    elif seconds < 86400:
        return f"{seconds/3600:.1f}h"
    else:
        return f"{seconds/86400:.1f}d"

def bucket_signal_strength(signal):
    """Bucket signal strength into ranges"""
    if signal is None:
        return None
    if signal >= -30:
        return "-30 to -30"
    elif signal >= -50:
        return "-30 to -50"
    elif signal >= -70:
        return "-50 to -70"
    elif signal >= -90:
        return "-70 to -90"
    else:
        return "-90 or weaker"

def estimate_distance(signal_dbm, tx_power=0):
    """Estimate distance in meters from signal strength (rough approximation)"""
    if signal_dbm is None:
        return None
    # Free space path loss approximation: FSPL = 20*log10(d) + 20*log10(f) + 32.44
    # Simplified: distance ≈ 10^((tx_power - signal_dbm - 32.44) / 20) * (2400/1000)
    # Using a simpler model: distance = 10^((tx_power - signal_dbm) / 20) * 0.1
    if tx_power == 0:
        # Assume default TX power if not provided
        tx_power = 0
    # Rough estimate: every 6dB doubles/halves distance
    path_loss = tx_power - signal_dbm
    distance_m = 10 ** (path_loss / 20) * 0.1
    return max(0.1, min(100, distance_m))  # Cap between 0.1m and 100m

if len(sys.argv) < 2:
    print("Usage: python3 analyze_kismet_final.py <kismet_file.kismet>")
    sys.exit(1)

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

print("=" * 60)
print("KISMET BLUETOOTH WARWALKING SUMMARY")
print("=" * 60)

# Total devices
cursor.execute("SELECT COUNT(*) FROM devices")
total_all = cursor.fetchone()[0]
print(f"\n📱 Total Devices (all types): {total_all}")

# Devices by type
cursor.execute("SELECT type, COUNT(*) FROM devices GROUP BY type ORDER BY COUNT(*) DESC")
types = cursor.fetchall()
print("\n📊 Device Types:")
for dtype, count in types:
    print(f"   {dtype}: {count}")

# Bluetooth-specific analysis
bt_types = ['BTLE', 'BT', 'BR/EDR']
bt_filter = " OR ".join([f"type='{t}'" for t in bt_types])

cursor.execute(f"SELECT COUNT(*) FROM devices WHERE {bt_filter}")
bt_total = cursor.fetchone()[0]
print(f"\n🔵 Bluetooth Devices: {bt_total}")

# Get comprehensive device details for Bluetooth
cursor.execute(f"SELECT devmac, type, device, first_time, last_time, strongest_signal, bytes_data FROM devices WHERE {bt_filter}")
bt_devices = cursor.fetchall()

# Data structures for analysis
named_devices = []
manufacturers = []
device_data = []
service_uuids = []
solicitation_uuids = []
tx_powers = []
path_losses = []
packet_counts = []
data_sizes = []
signal_buckets = defaultdict(int)
device_persistence = []
discovery_by_hour = defaultdict(int)
btle_devices = []
bredr_devices = []
trackable_devices = []
devices_with_services = 0
devices_with_names = 0

for mac, dtype, device_blob, first_time, last_time, signal, bytes_data in bt_devices:
    device_info = {
        'mac': mac,
        'type': dtype,
        'first_time': first_time,
        'last_time': last_time,
        'signal': signal,
        'bytes_data': bytes_data or 0,
        'name': None,
        'manufacturer': None,
        'service_uuids': [],
        'solicitation_uuids': [],
        'tx_power': None,
        'path_loss': None,
        'packet_count': 0,
        'trackable': False
    }
    
    if device_blob:
        try:
            device = json.loads(device_blob)
            
            # Extract device name
            name = None
            if 'kismet.device.base.name' in device:
                name = device['kismet.device.base.name']
            elif 'kismet.device.base.commonname' in device:
                name = device['kismet.device.base.commonname']
            
            if name and name != mac:
                device_info['name'] = name
                named_devices.append((mac, name))
                devices_with_names += 1
            
            # Extract manufacturer
            oui = mac[:8].upper()
            manufacturers.append(oui)
            if HAS_MAC_LOOKUP:
                try:
                    mac_obj = EUI(oui.replace(':', '-') + '-00-00-00')
                    device_info['manufacturer'] = mac_obj.oui.registration().org
                except:
                    device_info['manufacturer'] = "Unknown/Private"
            
            # Extract BTLE-specific data
            if 'bluetooth.device' in device:
                bt_data = device['bluetooth.device']
                
                if 'bluetooth.device.service_uuid_vec' in bt_data:
                    uuids = bt_data['bluetooth.device.service_uuid_vec']
                    if isinstance(uuids, list) and len(uuids) > 0:
                        device_info['service_uuids'] = uuids
                        service_uuids.extend(uuids)
                        devices_with_services += 1
                
                if 'bluetooth.device.solicitation_uuid_vec' in bt_data:
                    uuids = bt_data['bluetooth.device.solicitation_uuid_vec']
                    if isinstance(uuids, list) and len(uuids) > 0:
                        device_info['solicitation_uuids'] = uuids
                        solicitation_uuids.extend(uuids)
                
                if 'bluetooth.device.txpower' in bt_data:
                    tx_power = bt_data['bluetooth.device.txpower']
                    if tx_power != 0:
                        device_info['tx_power'] = tx_power
                        tx_powers.append(tx_power)
                
                if 'bluetooth.device.pathloss' in bt_data:
                    path_loss = bt_data['bluetooth.device.pathloss']
                    if path_loss != 0:
                        device_info['path_loss'] = path_loss
                        path_losses.append(path_loss)
            
            # Extract packet count
            if 'kismet.device.base.packets.total' in device:
                device_info['packet_count'] = device.get('kismet.device.base.packets.total', 0)
                packet_counts.append(device_info['packet_count'])
            
            # Determine if device is trackable
            if device_info['name'] or len(device_info['service_uuids']) > 0:
                device_info['trackable'] = True
                trackable_devices.append(mac)
            
        except (json.JSONDecodeError, KeyError) as e:
            pass
    
    # Categorize by type
    if dtype == 'BTLE':
        btle_devices.append(device_info)
    elif dtype in ['BT', 'BR/EDR']:
        bredr_devices.append(device_info)
    
    # Signal strength bucketing
    if signal is not None:
        bucket = bucket_signal_strength(signal)
        if bucket:
            signal_buckets[bucket] += 1
    
    # Device persistence
    if first_time and last_time:
        persistence = last_time - first_time
        device_persistence.append(persistence)
        device_info['persistence'] = persistence
        
        # Discovery by hour
        first_dt = datetime.fromtimestamp(first_time)
        hour_key = first_dt.strftime('%Y-%m-%d %H:00')
        discovery_by_hour[hour_key] += 1
    
    # Collect data sizes
    if bytes_data and bytes_data > 0:
        data_sizes.append(bytes_data)
    
    device_data.append(device_info)

print(f"\n🏷️  Named Devices: {len(named_devices)} ({len(named_devices)/bt_total*100:.1f}% of BT)")
print(f"   Anonymous Devices: {bt_total - len(named_devices)} ({(bt_total-len(named_devices))/bt_total*100:.1f}%)")

if named_devices:
    print("\n📝 Sample Device Names:")
    for mac, name in named_devices[:10]:
        print(f"   {name} ({mac})")

# Top manufacturers
if manufacturers:
    mfg_counts = Counter(manufacturers)
    print("\n🏭 Top 10 MAC Prefixes (Manufacturers):")
    for oui, count in mfg_counts.most_common(10):
        manufacturer = "Unknown"
        if HAS_MAC_LOOKUP:
            try:
                mac_obj = EUI(oui.replace(':', '-') + '-00-00-00')
                manufacturer = mac_obj.oui.registration().org
            except:
                manufacturer = "Unknown/Private"
        print(f"   {oui}: {count} devices - {manufacturer}")

# Signal strength stats
cursor.execute(f"SELECT AVG(strongest_signal), MIN(strongest_signal), MAX(strongest_signal) FROM devices WHERE ({bt_filter}) AND strongest_signal IS NOT NULL")
sig_stats = cursor.fetchone()
if sig_stats[0]:
    print(f"\n📡 Signal Strength:")
    print(f"   Average: {sig_stats[0]:.1f} dBm")
    print(f"   Weakest: {sig_stats[1]:.1f} dBm")
    print(f"   Strongest: {sig_stats[2]:.1f} dBm")

# GPS/Location data
cursor.execute(f"SELECT COUNT(*) FROM devices WHERE ({bt_filter}) AND (avg_lat IS NOT NULL AND avg_lat != 0)")
devices_with_gps = cursor.fetchone()[0]
print(f"\n🌍 Location Data:")
print(f"   Devices with GPS: {devices_with_gps} ({devices_with_gps/bt_total*100:.1f}%)")
print(f"   Devices without GPS: {bt_total - devices_with_gps} ({(bt_total-devices_with_gps)/bt_total*100:.1f}%)")

# If there's GPS data, show the bounding box
if devices_with_gps > 0:
    cursor.execute(f"SELECT MIN(min_lat), MAX(max_lat), MIN(min_lon), MAX(max_lon) FROM devices WHERE ({bt_filter}) AND avg_lat IS NOT NULL AND avg_lat != 0")
    bbox = cursor.fetchone()
    if bbox[0]:
        print(f"\n📍 Geographic Coverage:")
        print(f"   Latitude range: {bbox[0]:.6f} to {bbox[1]:.6f}")
        print(f"   Longitude range: {bbox[2]:.6f} to {bbox[3]:.6f}")
        
        # Calculate approximate distance
        lat_diff = abs(bbox[1] - bbox[0])
        lon_diff = abs(bbox[3] - bbox[2])
        # Rough distance calculation (1 degree lat ≈ 111km, lon varies)
        dist_km = ((lat_diff * 111) ** 2 + (lon_diff * 85) ** 2) ** 0.5
        print(f"   Approximate coverage area: {dist_km:.2f} km diagonal")

# Time range
cursor.execute(f"SELECT MIN(first_time), MAX(last_time) FROM devices WHERE {bt_filter}")
time_range = cursor.fetchone()
if time_range[0]:
    start = datetime.fromtimestamp(time_range[0])
    end = datetime.fromtimestamp(time_range[1])
    duration = end - start
    print(f"\n⏰ Scan Duration:")
    print(f"   Start: {start.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   End: {end.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   Duration: {duration}")

# ============================================================================
# NEW ENHANCED ANALYSIS SECTIONS
# ============================================================================

# 1. Device Discovery Patterns Over Time
if discovery_by_hour:
    print(f"\n📈 Device Discovery Patterns:")
    total_hours = len(discovery_by_hour)
    if total_hours > 0:
        avg_per_hour = bt_total / total_hours
        print(f"   Average discovery rate: {avg_per_hour:.1f} devices/hour")
        
        # Peak discovery times
        sorted_hours = sorted(discovery_by_hour.items(), key=lambda x: x[1], reverse=True)
        print(f"\n   Peak Discovery Times (Top 5):")
        for hour, count in sorted_hours[:5]:
            print(f"      {hour}: {count} devices")
        
        # Hourly breakdown
        if total_hours <= 24:
            print(f"\n   Hourly Breakdown:")
            for hour, count in sorted(discovery_by_hour.items()):
                pct = (count / bt_total * 100) if bt_total > 0 else 0
                print(f"      {hour}: {count} devices ({pct:.1f}%)")

# 2. Device Persistence Analysis
if device_persistence:
    avg_persistence = sum(device_persistence) / len(device_persistence)
    min_persistence = min(device_persistence)
    max_persistence = max(device_persistence)
    
    # Devices seen once vs multiple times
    one_time_devices = sum(1 for p in device_persistence if p == 0)
    persistent_devices = len(device_persistence) - one_time_devices
    
    print(f"\n⏳ Device Persistence Analysis:")
    print(f"   Average visibility duration: {format_duration(avg_persistence)}")
    print(f"   Shortest duration: {format_duration(min_persistence)}")
    print(f"   Longest duration: {format_duration(max_persistence)}")
    print(f"   One-time sightings: {one_time_devices} ({one_time_devices/len(device_persistence)*100:.1f}%)")
    print(f"   Persistent devices: {persistent_devices} ({persistent_devices/len(device_persistence)*100:.1f}%)")
    
    # Longest-lived devices
    device_data_sorted = sorted([d for d in device_data if 'persistence' in d], 
                               key=lambda x: x.get('persistence', 0), reverse=True)
    if device_data_sorted:
        print(f"\n   Longest-Lived Devices (Top 5):")
        for dev in device_data_sorted[:5]:
            name = dev.get('name') or dev.get('mac', 'Unknown')
            duration = format_duration(dev.get('persistence', 0))
            print(f"      {str(name)[:40]}: {duration}")

# 3. BTLE-Specific Analysis
print(f"\n📱 BTLE vs BR/EDR Breakdown:")
print(f"   BTLE (Bluetooth Low Energy): {len(btle_devices)} ({len(btle_devices)/bt_total*100:.1f}%)")
print(f"   BR/EDR (Classic Bluetooth): {len(bredr_devices)} ({len(bredr_devices)/bt_total*100:.1f}%)")

if service_uuids:
    service_counter = Counter(service_uuids)
    print(f"\n   Service UUIDs Analysis:")
    print(f"      Devices with services: {devices_with_services} ({devices_with_services/bt_total*100:.1f}%)")
    print(f"      Total service UUIDs found: {len(service_uuids)}")
    print(f"      Unique service UUIDs: {len(service_counter)}")
    if service_counter:
        print(f"\n      Most Common Service UUIDs (Top 10):")
        for uuid, count in service_counter.most_common(10):
            print(f"         {uuid}: {count} devices")

if solicitation_uuids:
    solicitation_counter = Counter(solicitation_uuids)
    print(f"\n   Solicitation UUIDs Analysis:")
    print(f"      Total solicitation UUIDs: {len(solicitation_uuids)}")
    print(f"      Unique solicitation UUIDs: {len(solicitation_counter)}")
    if solicitation_counter:
        print(f"\n      Most Common Solicitation UUIDs (Top 5):")
        for uuid, count in solicitation_counter.most_common(5):
            print(f"         {uuid}: {count} devices")

if tx_powers:
    avg_tx_power = sum(tx_powers) / len(tx_powers)
    min_tx_power = min(tx_powers)
    max_tx_power = max(tx_powers)
    print(f"\n   TX Power Analysis:")
    print(f"      Devices with TX power data: {len(tx_powers)}")
    print(f"      Average TX power: {avg_tx_power:.1f} dBm")
    print(f"      Range: {min_tx_power:.1f} to {max_tx_power:.1f} dBm")

if path_losses:
    avg_path_loss = sum(path_losses) / len(path_losses)
    min_path_loss = min(path_losses)
    max_path_loss = max(path_losses)
    print(f"\n   Path Loss Analysis:")
    print(f"      Devices with path loss data: {len(path_losses)}")
    print(f"      Average path loss: {avg_path_loss:.1f} dB")
    print(f"      Range: {min_path_loss:.1f} to {max_path_loss:.1f} dB")

# 4. Security/Privacy Metrics
print(f"\n🔒 Security & Privacy Metrics:")
print(f"   Trackable devices: {len(trackable_devices)} ({len(trackable_devices)/bt_total*100:.1f}%)")
print(f"   Devices with names: {devices_with_names} ({devices_with_names/bt_total*100:.1f}%)")
print(f"   Devices with service UUIDs: {devices_with_services} ({devices_with_services/bt_total*100:.1f}%)")
print(f"   Anonymous devices: {bt_total - devices_with_names} ({(bt_total-devices_with_names)/bt_total*100:.1f}%)")

# Device naming patterns
if named_devices:
    name_prefixes = Counter()
    name_suffixes = Counter()
    for mac, name in named_devices:
        if len(name) >= 3:
            name_prefixes[name[:3].upper()] += 1
            name_suffixes[name[-3:].upper()] += 1
    
    if name_prefixes:
        print(f"\n   Common Name Prefixes (Top 5):")
        for prefix, count in name_prefixes.most_common(5):
            print(f"      {prefix}...: {count} devices")
    
    if name_suffixes:
        print(f"\n   Common Name Suffixes (Top 5):")
        for suffix, count in name_suffixes.most_common(5):
            print(f"      ...{suffix}: {count} devices")

# 5. Signal Strength Distribution
if signal_buckets:
    print(f"\n📊 Signal Strength Distribution:")
    total_signals = sum(signal_buckets.values())
    for bucket in ["-30 to -30", "-30 to -50", "-50 to -70", "-70 to -90", "-90 or weaker"]:
        if bucket in signal_buckets:
            count = signal_buckets[bucket]
            pct = (count / total_signals * 100) if total_signals > 0 else 0
            bar = "█" * int(pct / 2)  # Simple bar chart
            print(f"   {bucket:15s}: {count:4d} devices ({pct:5.1f}%) {bar}")
    
    # Signal strength by device type
    if device_data:
        btle_signals = [d['signal'] for d in btle_devices if d['signal'] is not None]
        bredr_signals = [d['signal'] for d in bredr_devices if d['signal'] is not None]
        
        if btle_signals:
            avg_btle = sum(btle_signals) / len(btle_signals)
            print(f"\n   Signal Strength by Type:")
            print(f"      BTLE average: {avg_btle:.1f} dBm")
        if bredr_signals:
            avg_bredr = sum(bredr_signals) / len(bredr_signals)
            if btle_signals:
                print(f"      BR/EDR average: {avg_bredr:.1f} dBm")
            else:
                print(f"\n   Signal Strength by Type:")
                print(f"      BR/EDR average: {avg_bredr:.1f} dBm")
    
    # Range analysis
    all_signals = [d['signal'] for d in device_data if d['signal'] is not None]
    if all_signals:
        avg_signal = sum(all_signals) / len(all_signals)
        min_signal = min(all_signals)
        max_signal = max(all_signals)
        print(f"\n   Estimated Range Analysis:")
        avg_dist = estimate_distance(avg_signal)
        min_dist = estimate_distance(max_signal)  # Stronger signal = closer
        max_dist = estimate_distance(min_signal)   # Weaker signal = farther
        if avg_dist:
            print(f"      Average estimated distance: {avg_dist:.1f}m")
        if min_dist and max_dist:
            print(f"      Estimated range: {min_dist:.1f}m to {max_dist:.1f}m")

# 6. Additional Statistics
if packet_counts:
    avg_packets = sum(packet_counts) / len(packet_counts)
    total_packets = sum(packet_counts)
    max_packets = max(packet_counts)
    print(f"\n📦 Packet Statistics:")
    print(f"   Total packets: {total_packets:,}")
    print(f"   Average packets per device: {avg_packets:.1f}")
    print(f"   Maximum packets from single device: {max_packets:,}")
    
    # Find and display details about highest packet device
    max_packet_device = max(device_data, key=lambda d: d.get('packet_count', 0))
    if max_packet_device and max_packet_device.get('packet_count', 0) > 0:
        print(f"\n   Highest Packet Device Details:")
        name = max_packet_device.get('name') or max_packet_device.get('mac', 'Unknown')
        print(f"      Name/MAC: {name}")
        print(f"      MAC Address: {max_packet_device.get('mac', 'Unknown')}")
        print(f"      Type: {max_packet_device.get('type', 'Unknown')}")
        print(f"      Packets: {max_packet_device.get('packet_count', 0):,}")
        if max_packet_device.get('manufacturer'):
            print(f"      Manufacturer: {max_packet_device.get('manufacturer')}")
        if max_packet_device.get('signal') is not None:
            print(f"      Signal Strength: {max_packet_device.get('signal'):.1f} dBm")
        if max_packet_device.get('persistence'):
            print(f"      Visibility Duration: {format_duration(max_packet_device.get('persistence', 0))}")
        if max_packet_device.get('service_uuids'):
            print(f"      Service UUIDs: {len(max_packet_device.get('service_uuids', []))} services")
            if len(max_packet_device.get('service_uuids', [])) <= 5:
                for uuid in max_packet_device.get('service_uuids', []):
                    print(f"         - {uuid}")
        if max_packet_device.get('bytes_data', 0) > 0:
            print(f"      Data Transferred: {max_packet_device.get('bytes_data', 0):,} bytes ({max_packet_device.get('bytes_data', 0)/1024:.2f} KB)")
    
    # Devices by packet count
    high_packet_devices = sum(1 for p in packet_counts if p > 100)
    low_packet_devices = sum(1 for p in packet_counts if p <= 10)
    print(f"\n   Activity Distribution:")
    print(f"      High activity devices (>100 packets): {high_packet_devices}")
    print(f"      Low activity devices (≤10 packets): {low_packet_devices}")
    
    # Top 5 highest packet devices
    device_data_sorted_by_packets = sorted([d for d in device_data if d.get('packet_count', 0) > 0], 
                                          key=lambda x: x.get('packet_count', 0), reverse=True)
    if device_data_sorted_by_packets:
        print(f"\n   Top 5 Highest Packet Devices:")
        for i, dev in enumerate(device_data_sorted_by_packets[:5], 1):
            name = dev.get('name') or dev.get('mac', 'Unknown')
            packets = dev.get('packet_count', 0)
            print(f"      {i}. {str(name)[:40]}: {packets:,} packets")

# Data size statistics
if data_sizes:
    total_data = sum(data_sizes)
    avg_data = total_data / len(data_sizes)
    max_data = max(data_sizes)
    print(f"\n💾 Data Size Statistics:")
    print(f"   Total data: {total_data:,} bytes ({total_data/1024/1024:.2f} MB)")
    print(f"   Average data per device: {avg_data:.0f} bytes")
    print(f"   Maximum data from single device: {max_data:,} bytes ({max_data/1024:.2f} KB)")

# Manufacturer diversity
if manufacturers:
    unique_manufacturers = len(set(manufacturers))
    print(f"\n🏭 Manufacturer Diversity:")
    print(f"   Unique manufacturer OUIs: {unique_manufacturers}")
    print(f"   Average devices per manufacturer: {len(manufacturers)/unique_manufacturers:.1f}")

# Device density
if time_range[0] and bt_total > 0:
    duration_seconds = (time_range[1] - time_range[0])
    if duration_seconds > 0:
        devices_per_minute = (bt_total / duration_seconds) * 60
        print(f"\n📊 Device Density:")
        print(f"   Devices per minute: {devices_per_minute:.2f}")
        if devices_with_gps > 0:
            # Rough density calculation if we have GPS data
            bbox = cursor.execute(f"SELECT MIN(min_lat), MAX(max_lat), MIN(min_lon), MAX(max_lon) FROM devices WHERE ({bt_filter}) AND avg_lat IS NOT NULL AND avg_lat != 0").fetchone()
            if bbox[0]:
                lat_diff = abs(bbox[1] - bbox[0])
                lon_diff = abs(bbox[3] - bbox[2])
                # Rough area calculation (simplified)
                area_km2 = lat_diff * 111 * lon_diff * 85  # Very rough approximation
                if area_km2 > 0:
                    density = devices_with_gps / area_km2
                    print(f"   Devices per km² (GPS devices): {density:.2f}")

print("\n" + "=" * 60)

conn.close()