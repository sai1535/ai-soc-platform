import json
from datetime import datetime, timedelta

OUTPUT_FILE = "test_security_events.json"

# Create 10 simulated failed-login events
events = []

start_time = datetime.now()

for i in range(10):

    event_time = start_time + timedelta(seconds=i * 5)

    event = {
        "event_id": 4625,
        "timestamp": event_time.isoformat(),
        "computer": "DESKTOP-SOC-TEST",
        "event_type": "Failed Logon",
        "event_data": {
            "TargetUserName": "testuser",
            "TargetDomainName": "DESKTOP-SOC-TEST",
            "IpAddress": "192.168.1.100",
            "LogonType": "2",
            "Status": "0xC000006D",
            "SubStatus": "0xC000006A",
            "AuthenticationPackageName": "Negotiate"
        }
    }

    events.append(event)


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


print("=" * 60)
print("SOC Test Dataset Generator")
print("=" * 60)

print(f"\nCreated {len(events)} simulated failed-login events.")

print(f"User: testuser")
print(f"Source IP: 192.168.1.100")
print(f"Event ID: 4625")
print(f"Time span: 45 seconds")

print(f"\nSaved to:")
print(f"{OUTPUT_FILE}")