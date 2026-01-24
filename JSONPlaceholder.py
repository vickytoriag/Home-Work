import requests

url = "https://jsonplaceholder.typicode.com/posts"

try:
    response = requests.get(url)
    response.raise_for_status()
    posts = response.json()
except requests.RequestException as e:
    print("Ошибка при выполнении запроса:", e)
    exit()

for i, post in enumerate(posts[:5], start=1):
    print(f"Пост {i}")
    print("Заголовок:", post["title"])
    print("Тело:", post["body"])
    print()
