import os
import requests
import hashlib
import json

API_KEY = os.getenv("VT_API_KEY")
if not API_KEY:
    raise ValueError("API ключ не найден! Задайте переменную окружения VT_API_KEY.")

def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
file_path = input("Введите путь к файлу для проверки: ")
if not os.path.isfile(file_path):
    print("Файл не найден.Проверьте путь и попробуйте снова.")
    exit(1)
FILE_HASH = calculate_file_hash(file_path)
url = f"https://www.virustotal.com/api/v3/files/{FILE_HASH}"


headers = {
    "x-apikey": API_KEY
}

response = requests.get(url, headers=headers)
if response.status_code == 200:
    print("Запрос выполнен успешно.")
    data = response.json()
    print(json.dumps(data, indent=4))
    
    stats = data["data"]["attributes"]["last_analysis_stats"]
    
    print("Статистика сканирования файла:")
    print(f"Вредоносных детектов: {stats['malicious']}")
    print(f"Подозрительных: {stats['suspicious']}")
    print(f"Безопасных: {stats['harmless']}")
    print(f"Неопределенных: {stats['undetected']}")

elif response.status_code == 404:
    print("Файл не найден в базе VirusTotal.")
else:
    print(f"Ошибка: {response.status_code}")
    print(response.text)