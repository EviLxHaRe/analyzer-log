import sys
import re
from datetime import datetime

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

# Проверка на нужное колличество аргументов
if len(sys.argv) != 2:
    print("Укажи файл для анализа")
    sys.exit(1)

file = sys.argv[1]
events = {
    "failed_password": [],
    "accepted_password": [],
    "accepted_key": [],
}
ssh_pattern = re.compile(
    r"(?:Failed password|Accepted password|Accepted publickey) "
    r"for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+)"
) # регулярное выражение для извлечения пользователя и его ip
failures_by_ip = {}

with open(file, encoding="utf-8") as log_file:
    for line_number, line in enumerate(log_file, start=1):
        if "Failed password" in line:
            event_type = "failed_password"
        elif "Accepted password" in line:
            event_type = "accepted_password"
        elif "Accepted publickey" in line:
            event_type = "accepted_key"
        else:
            continue

        match = ssh_pattern.search(line)

        if match is None:
            print(f"Ошибка в парсинге строки {line_number}")
            continue

        timestamp_text = line.split()[0]

        try:
            timestamp = datetime.fromisoformat(timestamp_text)
        except ValueError:
            print(f"Не удалось разобрать время: строка {line_number}")
            continue

        if timestamp.tzinfo is None:
            print(f"Нет часового пояса: строка {line_number}")
            continue

        events[event_type].append({
            "line_number": line_number,
            "text": line.strip(),
            "user": match.group("user"),
            "ip": match.group("ip"),
            "timestamp": timestamp,
        })


# Вычисления для итогово результата
for event in events["failed_password"]: # обработка неправильных паролей
    ip = event["ip"]
    if ip not in failures_by_ip:
        failures_by_ip[ip] = []
    failures_by_ip[ip].append(event)
findings = detect_ssh_brute_force(failures_by_ip)

# Вывод
print("-" * 100)
print(f"Краткий отчет:")
print(f"Неудачных входов: {len(events['failed_password'])}")
print(f"Успешных входов по паролю: {len(events['accepted_password'])}")
print(f"Успешных входов по ключу: {len(events['accepted_key'])}")
print("-" * 100)
print(f"Подробные логи:")
for event in events["failed_password"]:
    print(
        f"Строка {event['line_number']}: "
        f"время={event['timestamp'].isoformat()}, "
        f"пользователь={event['user']}, "
        f"IP={event['ip']}"
    )
print("-" * 100)
for ip, failed_events in failures_by_ip.items():
    print(f"IP: {ip}    |    Ошибок: {len(failed_events)}")
print("-" * 100)
print("Обнаружения:")
if findings:
    for finding in findings:
        print(f"Возможный перебор SSH-пароля: {finding['ip']}")
        print(f"Ошибок в окне: {finding['count']}")
        print(f"Строки: {finding['lines']}")
        print(
            f"Период: {finding['start'].isoformat()} "
            f"— {finding['end'].isoformat()}"
        )
else:
    print("Признаков перебора SSH-пароля не найдено.")
