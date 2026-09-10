import win32evtlog
import xml.etree.ElementTree as ET
import json
import os


LOG_NAME = "Security"


def parse_event(event):
    """Convert a Windows Event Log event into a Python dictionary."""

    xml_data = win32evtlog.EvtRender(
        event,
        win32evtlog.EvtRenderEventXml
    )

    root = ET.fromstring(xml_data)

    # Windows Event XML uses namespaces.
    # This finds elements regardless of the namespace prefix.
    system = next(
        element for element in root
        if element.tag.endswith("System")
    )

    event_id_element = next(
        element for element in system
        if element.tag.endswith("EventID")
    )

    computer_element = next(
        element for element in system
        if element.tag.endswith("Computer")
    )

    time_created_element = next(
        element for element in system
        if element.tag.endswith("TimeCreated")
    )

    event_data = {}

    event_data_element = next(
        (
            element
            for element in root
            if element.tag.endswith("EventData")
        ),
        None
    )

    if event_data_element is not None:
        for data in event_data_element:
            name = data.attrib.get("Name")

            if name:
                event_data[name] = data.text

    return {
        "event_id": int(event_id_element.text),
        "computer": (
            computer_element.text
            if computer_element is not None
            else None
        ),
        "timestamp": (
            time_created_element.attrib.get("SystemTime")
            if time_created_element is not None
            else None
        ),
        "event_data": event_data
    }


def collect_security_events():

    query = """
    <QueryList>
        <Query Id="0">
            <Select Path="Security">
                *[System[
                    (EventID=4624 or EventID=4625)
                ]]
            </Select>
        </Query>
    </QueryList>
    """

    query_handle = win32evtlog.EvtQuery(
        LOG_NAME,
        win32evtlog.EvtQueryReverseDirection,
        query
    )

    events = []

    while True:

        returned_events = win32evtlog.EvtNext(
            query_handle,
            10
        )

        if not returned_events:
            break

        for event in returned_events:

            try:
                parsed_event = parse_event(event)
                events.append(parsed_event)

            except Exception as error:
                print("Error parsing event:", error)

    return events


if __name__ == "__main__":

    print("=" * 60)
    print("AI-Assisted SOC - Windows Security Event Collector")
    print("=" * 60)

    print("\nReading Windows Security events...")

    events = collect_security_events()

    print(f"\nEvents collected: {len(events)}")

    for event in events[:10]:

        print("\n------------------------------")
        print("Event ID:", event["event_id"])
        print("Computer:", event["computer"])
        print("Timestamp:", event["timestamp"])

        if event["event_id"] == 4624:
            print("Type: Successful Logon")

        elif event["event_id"] == 4625:
            print("Type: Failed Logon")

    output_file = "../data/security_events.json"

    os.makedirs("../data", exist_ok=True)

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            events,
            file,
            indent=4
        )

    print("\nEvents saved to:")
    print(output_file)