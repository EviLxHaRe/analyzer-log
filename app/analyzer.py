import sys
import re

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

        events[event_type].append({
            "line_number": line_number,
            "text": line.strip(),
            "user": match.group("user"),
            "ip": match.group("ip"),
        })


for event in events["failed_password"]: # обработка неправильных паролей
    ip = event["ip"]

    if ip not in failures_by_ip:
        failures_by_ip[ip] = []

    failures_by_ip[ip].append(event)


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
        f"пользователь={event['user']}, IP={event['ip']}"
    )
print("-" * 100)
for ip, failed_events in failures_by_ip.items():
    line_numbers = [
        event["line_number"]
        for event in failed_events
    ]

    print(f"IP: {ip}")
    print(f"Ошибок: {len(failed_events)}")
    print(f"Строки: {line_numbers}")
