# CryptoCore

CryptoCore — консольная утилита для шифрования и расшифрования файлов с использованием AES-128 в режиме ECB и дополнением PKCS#7.

## Зависимости

- Python 3.8+
- pycryptodome
- pytest (для тестов)
- Git
- OpenSSL (необязательно, для проверки)

Установка зависимостей:

```bash
pip install -r requirements.txt
```

## Установка

```bash
git clone https://github.com/<your-username>/cryptocore.git
cd cryptocore
```

### Windows

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install .
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install .
```

Проверка:

```bash
cryptocore --help
```

## Использование

### Шифрование

```bash
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

### Расшифрование

```bash
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

## Аргументы командной строки

| Аргумент | Назначение |
|---|---|
| `--algorithm` | алгоритм; в Sprint 1 — `aes` |
| `--mode` | режим; в Sprint 1 — `ecb` |
| `--encrypt` | шифрование |
| `--decrypt` | расшифрование |
| `--key` | ключ AES-128 в HEX |
| `--input` | путь к входному файлу |
| `--output` | путь к выходному файлу |

`--encrypt` и `--decrypt` взаимоисключающие.

Ключ AES-128 должен содержать ровно 32 HEX-символа (16 байт):

```text
000102030405060708090a0b0c0d0e0f
```

Если `--output` не указан, создаётся `INPUT.enc` при шифровании или `INPUT.dec` при расшифровании.

## Криптографическая реализация

Используется:

```text
AES-128 + ECB + PKCS#7
```

Размер блока — 16 байт, ключа — 16 байт.

Примитив AES берётся из `pycryptodome`:

```python
from Crypto.Cipher import AES
```

AES с нуля не реализуется.

Логика ECB реализована в проекте самостоятельно:

1. данные дополняются PKCS#7;
2. разбиваются на блоки по 16 байт;
3. каждый блок обрабатывается AES;
4. результаты объединяются.

При расшифровании padding проверяется и удаляется.

## Работа с файлами

Файлы обрабатываются как бинарные данные (`rb` / `wb`), поэтому поддерживаются и текстовые, и бинарные файлы.

Ошибки аргументов, чтения, записи и некорректного padding выводятся в `stderr`, программа завершается с ненулевым кодом.

## Проверка round-trip

Создать файл:

```bash
printf 'Hello, CryptoCore!\n' > plaintext.txt
```

Зашифровать:

```bash
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифровать:

```bash
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

### Linux / macOS

```bash
diff plaintext.txt decrypted.txt
```

### Windows

```powershell
fc.exe /b plaintext.txt decrypted.txt
```

Отсутствие различий означает, что исходный файл восстановлен.

## Проверка через OpenSSL

Создать файл:

```bash
printf 'The quick brown fox' > message.txt
```

OpenSSL:

```bash
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -in message.txt -out openssl.bin
```

CryptoCore:

```bash
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input message.txt --output cryptocore.bin
```

Сравнение:

```bash
cmp openssl.bin cryptocore.bin
```

OpenSSL использует PKCS#7 padding по умолчанию.

## Запуск тестов

```bash
pip install -e .
pip install -r requirements.txt
pytest -v
```

Тесты проверяют PKCS#7, AES-128/ECB, round-trip, текстовые и бинарные файлы, CLI, ошибки и известный AES-тестовый вектор.

## Структура проекта

```text
cryptocore/
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── cli_parser.py
│   ├── file_io.py
│   ├── padding.py
│   └── modes/
│       ├── __init__.py
│       └── ecb.py
├── tests/
│   └── test_cryptocore.py
├── setup.py
├── pyproject.toml
├── requirements.txt
├── .gitignore
└── README.md
```

## Git

```bash
git init
git add .
git commit -m "Sprint 1: AES-128 ECB"
git branch -M main
git remote add origin https://github.com/<your-username>/cryptocore.git
git push -u origin main
```

## Sprint 1

Реализованы:

- AES-128;
- ECB;
- PKCS#7;
- бинарный I/O;
- CLI;
- валидация аргументов;
- обработка ошибок;
- автоматические тесты;
- round-trip проверка;
- проверка через OpenSSL.
