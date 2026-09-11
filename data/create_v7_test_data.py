import json
from datetime import datetime, timedelta
import os


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OUTPUT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "test_v7_security_events.json"
)


start_time = datetime.now()

events = []


# ============================================================
# Stage 1: Failed Login Attempts
# ============================================================

for i in range(10):

    events.append({
        "event_id": 4625,
        "timestamp": (
            start_time +
            timedelta(seconds=i * 5)
        ).isoformat(),

        "username": "testuser",

        "source_ip": "192.168.1.100"
    })


# ============================================================
# Stage 2: Successful Login
# ============================================================

events.append({

    "event_id": 4624,

    "timestamp": (
        start_time +
        timedelta(seconds=55)
    ).isoformat(),

    "username": "testuser",

    "source_ip": "192.168.1.100"
})


# ============================================================
# Stage 3: PowerShell Process Creation
# ============================================================

events.append({

    "event_id": 4688,

    "timestamp": (
        start_time +
        timedelta(seconds=70)
    ).isoformat(),

    "username": "testuser",

    "source_ip": "192.168.1.100",

    "process_name": "powershell.exe"
})


# ============================================================
# Stage 4: New Windows Service
# ============================================================

events.append({

    "event_id": 7045,

    "timestamp": (
        start_time +
        timedelta(seconds=90)
    ).isoformat(),

    "username": "testuser",

    "source_ip": "192.168.1.100",

    "service_name": "TestPersistenceService"
})


# ============================================================
# Save Dataset
# ============================================================

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        events,
        file,
        indent=4
    )


print("=" * 65)
print("V7 Safe Test Dataset Created")
print("=" * 65)
print()
print(f"Events generated: {len(events)}")
print()
print("Attack Simulation:")
print("10 Failed Logins")
print("        ↓")
print("Successful Login")
print("        ↓")
print("PowerShell Execution")
print("        ↓")
print("New Windows Service")
print()
print(f"Saved to:")
print(OUTPUT_FILE)
print()
print("NOTE: These are simulated security events.")
print("No real attack was performed.")