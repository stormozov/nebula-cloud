# Тестирование

[🇬🇧 EN version](../en/TESTING.md)

## Запуск тестов

### Все тесты

```bash
pytest
```

### С покрытием кода

```bash
pytest --cov --cov-report=html
```

Отчёт будет доступен в директории `htmlcov/`

### С покрытием в терминале

```bash
pytest --cov --cov-report=term-missing
```

### Конкретный тест

```bash
pytest storage/tests/test_models.py
pytest storage/tests/test_models.py::TestFileCreation::test_file_creation_with_required_fields
```

### С детальным выводом

```bash
pytest -v
pytest -vv
```

## Структура тестов

### Users app

```
users/tests/
├── conftest.py           # Фикстуры для всех тестов
├── test_auth.py          # Тесты аутентификации
├── test_users.py         # Тесты пользователя
└── test_admin_users.py   # Тесты админ функций
```

### Storage app

```
storage/tests/
├── conftest.py               # Фикстуры
├── test_models.py            # Тесты моделей
├── test_crud_views.py        # Тесты CRUD операций
├── test_public_views.py      # Тесты публичного доступа
├── test_permission.py        # Тесты прав доступа
├── test_serializers.py       # Тесты сериализаторов
├── test_edge_cases.py        # Тесты граничных случаев
└── test_media_isolation.py   # Тесты изоляции файлов
```

## Настройки тестирования

Тесты автоматически используют:

- **MD5PasswordHasher** - Быстрое хэширование паролей
- **Временная директория** для медиа файлов
- **Отключённое ограничение частоты запросов** (throttling)

## Требования к покрытию

Минимальное покрытие кода: **80%**

```bash
pytest --cov-fail-under=80
```

## CI/CD

При пуше в репозиторий автоматически запускаются:

```bash
# Линтинг
ruff check .
black --check .

# Тесты с покрытием
pytest --cov --cov-report=xml
```

## Отладка тестов

### Показать print вывод

```bash
pytest -s
```

### Остановиться на первой ошибке

```bash
pytest -x
```

### Отладить падающий тест

```bash
pytest --pdb
```

### Посмотреть логи

```bash
pytest --log-cli-level=DEBUG
```
