import requests
import os
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("API_KEY")
if not api_key:
    print("API_KEY не найден")
    exit()

city = input("Введите город: ").strip()
if not city:
    print("Город не введен")
    exit()

url = "https://api.openweathermap.org/data/2.5/weather"
params = {
    "q": city,
    "appid": api_key,
    "units": "metric",
    "lang": "ru"
}

response = requests.get(url, params=params)

if response.status_code == 200:
    data = response.json()
    temperature = data["main"]["temp"]
    description = data["weather"][0]["description"]

    print(f"Город: {city}")
    print(f"Температура: {temperature} °C")
    print(f"Погода: {description}")

elif response.status_code == 401:
    print("Ошибка авторизации. Проверь API ключ")

elif response.status_code == 404:
    print("Город не найден")

else:
    print("Ошибка запроса:", response.status_code)
