def detect_ssh_brute_force(failures_by_ip, threshold=5, window_seconds=300):
    findings = []
    for ip, failed_events in failures_by_ip.items():
        sorted_events = sorted(
            failed_events,
            key=lambda event: event["timestamp"]
        )

        left = 0

        for right, current_event in enumerate(sorted_events):
            while (
                current_event["timestamp"]
                - sorted_events[left]["timestamp"]
            ).total_seconds() > window_seconds:
                left += 1

            count = right - left + 1

            if count >= threshold:
                evidence = sorted_events[left:right + 1]

                findings.append({
                    "ip": ip,
                    "count": count,
                    "start": evidence[0]["timestamp"],
                    "end": evidence[-1]["timestamp"],
                    "lines": [
                        event["line_number"]
                        for event in evidence
                    ],
                })
                break
    return findings
