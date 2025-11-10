#!/usr/bin/env python3
import sqlite3
import sys
import json
from collections import Counter
from datetime import datetime

try:
    from netaddr import EUI
    HAS_MAC_LOOKUP = True
except ImportError:
    HAS_MAC_LOOKUP = False
    print("Warning: netaddr not installed. Install with: sudo apt install python3-netaddr")

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

# Get device details for Bluetooth
cursor.execute(f"SELECT devmac, type, device FROM devices WHERE {bt_filter}")
bt_devices = cursor.fetchall()

named_devices = []
manufacturers = []

for mac, dtype, device_blob in bt_devices:
    if device_blob:
        try:
            device = json.loads(device_blob)
            
            # Try to extract device name
            name = None
            if 'kismet.device.base.name' in device:
                name = device['kismet.device.base.name']
            elif 'kismet.device.base.commonname' in device:
                name = device['kismet.device.base.commonname']
            
            # Only count as "named" if the name is different from MAC address
            if name and name != mac:
                named_devices.append((mac, name))
            
            # Extract manufacturer from MAC OUI
            oui = mac[:8].upper()
            manufacturers.append(oui)
            
        except (json.JSONDecodeError, KeyError):
            pass

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

print("\n" + "=" * 60)

conn.close()