# Nebula Cloud Backend

[🇬🇧 EN version](../../README.md)

Бэкенд приложение для облачного хранилища данных на Django.

## Технологический стек

- **Django** 6.0
- **Django REST Framework** 3.15
- **PostgreSQL**
- **JWT** (djangorestframework-simplejwt)
- **Swagger/OpenAPI** (drf-spectacular)

## Структура проекта

```
backend/
├── core/              # Основные настройки проекта
│   ├── settings.py    # Настройки Django
│   ├── urls.py        # Корневые URL
│   ├── wsgi.py        # WSGI конфигурация
│   ├── asgi.py        # ASGI конфигурация
│   ├── utils.py       # Утилиты
│   └── logging_config.py  # Настройки логирования
├── users/             # Приложение пользователей
│   └── services/      # Бизнес-логика
│   ├── serializers/   # Сериализаторы
│   ├── views/         # Views
│   ├── models.py      # Модель UserAccount
│   ├── urls.py        # URL маршруты
│   ├── permissions.py # Права доступа
│   ├── validators.py  # Валидаторы
│   ├── throttles.py   # Ограничение частоты запросов
│   ├── signals.py     # Сигналы
│   ├── managers.py    # Менеджеры
├── storage/           # Приложение файлового хранилища
│   ├── serializers/   # Сериализаторы
│   ├── views/         # Views
│   ├── models.py      # Модель File
│   ├── urls.py        # URL маршруты
│   ├── permissions.py # Права доступа
│   └── utils.py       # Утилиты
└── docs/              # Документация
```

## Быстрый старт

См. [INSTALLATION.md](INSTALLATION.md) для получения инструкций по установке.

## Конфигурация

См. [CONFIGURATION.md](CONFIGURATION.md)

## API Документация

После запуска сервера документация (сгенерирована с помощью Swagger/OpenAPI) доступна по адресам:

- **Swagger UI**: http://localhost:8000/api/docs/
- **OpenAPI Schema**: http://localhost:8000/api/schema/

Также документация доступа [тут](API.md)

## Тестирование

См. [TESTING.md](TESTING.md) для получения инструкций по запуску тестов.

## Основные функции

### Аутентификация

- Регистрация новых пользователей
- Вход по логину/паролю
- Выход с блокировкой токена
- Обновление access токена

### Управление пользователями

- Просмотр и редактирование профиля
- Смена пароля
- Деактивация аккаунта
- Просмотр статистики хранилища

### Файловое хранилище

- Загрузка файлов
- Скачивание файлов
- Переименование файлов
- Добавление комментариев
- Публичные ссылки на файлы
- Просмотр истории скачиваний

## Лицензия

MIT
