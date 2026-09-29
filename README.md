# CryptoCore

**CryptoCore** --- консольная утилита для шифрования и расшифрования
файлов с использованием AES-128 в режимах ECB, CBC, CFB, OFB и CTR.

## Возможности

-   Шифрование и расшифрование с использованием AES-128.
-   Поддержка режимов ECB, CBC, CFB, OFB и CTR.
-   PKCS#7 padding для режимов ECB и CBC.
-   Без дополнения (padding) для CFB, OFB и CTR.
-   Автоматическая криптографически стойкая генерация IV для CBC, CFB,
    OFB и CTR.
-   Сохранение IV в начале зашифрованного файла.
-   Возможность явно указать IV при расшифровании.
-   Работа с бинарными файлами.
-   Защита от перезаписи исходного файла.
-   Тесты совместимости с OpenSSL.
-   Проверка по тестовым векторам NIST SP 800-38A.

## Зависимости

### Обязательные

-   Python 3.8 или новее
-   `pycryptodome`
-   `pytest` --- для запуска тестов
-   Git

### Дополнительные

-   OpenSSL --- необходим для запуска тестов совместимости с OpenSSL.

Установка Python-зависимостей:

``` bash
pip install -r requirements.txt
```

## Сборка и установка

Клонировать репозиторий:

``` bash
git clone https://github.com/<your-username>/cryptocore.git
cd cryptocore
```

### Windows

Создать виртуальное окружение:

``` powershell
py -m venv .venv
```

Активировать его:

``` powershell
.\.venv\Scripts\Activate.ps1
```

Установить зависимости:

``` powershell
pip install -r requirements.txt
```

Установить проект:

``` powershell
pip install .
```

Если PowerShell не позволяет активировать виртуальное окружение,
зависимости и проект можно установить непосредственно через Python из
окружения:

``` powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install .
```

Проверить установку:

``` powershell
cryptocore --help
```

Также программу можно запустить как Python-модуль:

``` powershell
python -m cryptocore.main --help
```

### Linux / macOS

Создать виртуальное окружение:

``` bash
python3 -m venv .venv
source .venv/bin/activate
```

Установить зависимости и проект:

``` bash
pip install -r requirements.txt
pip install .
```

Проверить установку:

``` bash
cryptocore --help
```

## Использование CLI

Общий синтаксис команды:

``` text
cryptocore --algorithm aes --mode {ecb|cbc|cfb|ofb|ctr}
           (--encrypt | --decrypt)
           --key <32 hex characters>
           [--iv <32 hex characters>]
           --input <file>
           [--output <file>]
```

### Аргументы командной строки

  -----------------------------------------------------------------------
  Аргумент                            Описание
  ----------------------------------- -----------------------------------
  `--algorithm`                       Алгоритм шифрования. В текущей
                                      версии поддерживается `aes`.

  `--mode`                            Режим AES: `ecb`, `cbc`, `cfb`,
                                      `ofb` или `ctr`.

  `--encrypt`                         Зашифровать входной файл.

  `--decrypt`                         Расшифровать входной файл.

  `--key`                             Ключ AES-128 в шестнадцатеричном
                                      формате, ровно 32 hex-символа (16
                                      байт).

  `--iv`                              IV в шестнадцатеричном формате,
                                      ровно 32 hex-символа (16 байт).
                                      Используется при расшифровании CBC,
                                      CFB, OFB и CTR.

  `--input`                           Путь к входному файлу.

  `--output`                          Путь к выходному файлу. Если не
                                      указан, для шифрования используется
                                      `.enc`, а для расшифрования ---
                                      `.dec`.
  -----------------------------------------------------------------------

Опции `--encrypt` и `--decrypt` являются взаимоисключающими.

Выходной файл не должен совпадать с входным файлом. Это предотвращает
случайную потерю исходных данных.

## Режимы AES

  Режим   Тип               Padding           IV
  ------- ----------------- ----------------- -----------------
  `ecb`   Блочный           PKCS#7            Не используется
  `cbc`   Блочный           PKCS#7            Требуется
  `cfb`   CFB128            Не используется   Требуется
  `ofb`   Потоковый         Не используется   Требуется
  `ctr`   Счётчик 128 бит   Не используется   Требуется

### ECB

Режим ECB не использует IV.

Пример шифрования:

``` bash
cryptocore --algorithm aes --mode ecb --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plain.txt \
  --output cipher.bin
```

Расшифрование:

``` bash
cryptocore --algorithm aes --mode ecb --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input cipher.bin \
  --output decrypted.txt
```

### CBC

CBC использует IV размером 16 байт и PKCS#7 padding.

При шифровании IV генерируется автоматически и сохраняется в начале
выходного файла:

``` text
<16 байт IV><зашифрованные данные>
```

Пример:

``` bash
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plain.txt \
  --output cipher.bin
```

При расшифровании IV автоматически считывается из первых 16 байт:

``` bash
cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input cipher.bin \
  --output decrypted.txt
```

### CFB

В проекте используется режим CFB128. Padding не используется.

Шифрование:

``` bash
cryptocore --algorithm aes --mode cfb --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plain.txt \
  --output cipher.bin
```

Расшифрование с использованием IV из файла:

``` bash
cryptocore --algorithm aes --mode cfb --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input cipher.bin \
  --output decrypted.txt
```

### OFB

Режим OFB не использует padding.

Шифрование:

``` bash
cryptocore --algorithm aes --mode ofb --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plain.txt \
  --output cipher.bin
```

Расшифрование:

``` bash
cryptocore --algorithm aes --mode ofb --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input cipher.bin \
  --output decrypted.txt
```

### CTR

Режим CTR использует 128-битный счётчик с порядком байтов big-endian и
не использует padding.

Шифрование:

``` bash
cryptocore --algorithm aes --mode ctr --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plain.txt \
  --output cipher.bin
```

Расшифрование:

``` bash
cryptocore --algorithm aes --mode ctr --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input cipher.bin \
  --output decrypted.txt
```

## Работа с IV

Для режимов `cbc`, `cfb`, `ofb` и `ctr` при шифровании генерируется
новый случайный IV размером 16 байт.

Зашифрованный файл имеет формат:

``` text
+----------------+-------------------+
| 16 байт IV     | Зашифрованные     |
|                | данные            |
+----------------+-------------------+
```

При расшифровании:

1.  Если `--iv` не указан, первые 16 байт входного файла используются
    как IV, а остальные байты считаются шифртекстом.
2.  Если `--iv` указан, используется переданный IV, а весь входной файл
    считается шифртекстом.
3.  Если `--iv` не указан, а размер входного файла меньше 16 байт,
    расшифрование завершается с ошибкой.

Явное указание IV необходимо, например, при расшифровании шифртекста,
созданного другой программой, такой как OpenSSL.

Пример расшифрования с явным IV:

``` bash
cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --iv AABBCCDDEEFF00112233445566778899 \
  --input cipher_only.bin \
  --output decrypted.txt
```

Опция `--iv` не используется при шифровании, поскольку CryptoCore
генерирует IV автоматически.

## Формат файлов

Для `cbc`, `cfb`, `ofb` и `ctr`:

``` text
+----------------+-------------------+
| 16 байт IV     | Шифртекст         |
+----------------+-------------------+
```

Для `ecb`:

``` text
+-------------------+
| Шифртекст         |
+-------------------+
```

## Пример полного цикла

Создать тестовый файл:

``` bash
printf 'Hello, CryptoCore!\n' > plaintext.txt
```

Зашифровать:

``` bash
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plaintext.txt \
  --output ciphertext.bin
```

Расшифровать:

``` bash
cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input ciphertext.bin \
  --output decrypted.txt
```

В Linux/macOS сравнить файлы:

``` bash
diff plaintext.txt decrypted.txt
```

В Windows:

``` powershell
fc.exe /b plaintext.txt decrypted.txt
```

Отсутствие различий означает, что исходный файл был восстановлен.

## Совместимость с OpenSSL

OpenSSL используется для проверки совместимости CryptoCore с независимой
реализацией AES.

Тесты проверяют:

-   шифрование CryptoCore → расшифрование OpenSSL;
-   шифрование OpenSSL → расшифрование CryptoCore;
-   режимы CBC, CFB, OFB и CTR;
-   передачу одинаковых ключей и IV между программами.

### Проверка установки OpenSSL

Linux/macOS:

``` bash
openssl version
```

Windows:

``` powershell
openssl version
```

Если команда не найдена, необходимо установить OpenSSL и добавить его
исполняемый файл в `PATH`.

### CryptoCore → OpenSSL

Сначала зашифровать файл в CryptoCore:

``` bash
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plain.txt \
  --output cipher.bin
```

Первые 16 байт `cipher.bin` являются IV. Для OpenSSL IV передаётся
отдельно, поэтому необходимо отделить IV от шифртекста.

В Linux/macOS:

``` bash
dd if=cipher.bin of=iv.bin bs=16 count=1
dd if=cipher.bin of=cipher_only.bin bs=16 skip=1

IV=$(xxd -p iv.bin | tr -d '\n')

openssl enc -aes-128-cbc -d \
  -K 000102030405060708090a0b0c0d0e0f \
  -iv "$IV" \
  -in cipher_only.bin \
  -out openssl_decrypted.txt

cmp plain.txt openssl_decrypted.txt && echo OK
```

В Windows PowerShell IV и шифртекст можно отделить с помощью Python:

``` powershell
python -c "from pathlib import Path; d=Path('cipher.bin').read_bytes(); Path('iv.bin').write_bytes(d[:16]); Path('cipher_only.bin').write_bytes(d[16:]); print(d[:16].hex())"
```

Команда выведет IV. Затем его можно передать OpenSSL:

``` powershell
openssl enc -aes-128-cbc -d `
  -K 000102030405060708090a0b0c0d0e0f `
  -iv AABBCCDDEEFF00112233445566778899 `
  -in cipher_only.bin `
  -out openssl_decrypted.txt
```

После этого необходимо сравнить `openssl_decrypted.txt` с исходным
`plain.txt`.

### OpenSSL → CryptoCore

Зашифровать файл с помощью OpenSSL с явно заданными ключом и IV:

``` bash
openssl enc -aes-128-cbc \
  -K 000102030405060708090a0b0c0d0e0f \
  -iv AABBCCDDEEFF00112233445566778899 \
  -in plain.txt \
  -out openssl_cipher.bin
```

Расшифровать результат с помощью CryptoCore:

``` bash
cryptocore --algorithm aes --mode cbc --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --iv AABBCCDDEEFF00112233445566778899 \
  --input openssl_cipher.bin \
  --output decrypted.txt
```

Аналогично можно проверить режимы CFB, OFB и CTR.

Для CryptoCore:

``` text
--mode cfb
--mode ofb
--mode ctr
```

Для OpenSSL:

``` text
-aes-128-cfb
-aes-128-ofb
-aes-128-ctr
```

## Запуск тестов

Установить проект в режиме разработки:

``` bash
pip install -e .
```

Запустить полный набор тестов:

``` bash
pytest -v
```

Тесты проверяют:

-   PKCS#7 padding;
-   AES-128 ECB;
-   CBC, CFB, OFB и CTR;
-   тестовые векторы NIST SP 800-38A;
-   сравнение с эталонной реализацией PyCryptodome;
-   циклы шифрования/расшифрования через CLI;
-   генерацию и извлечение IV;
-   обработку явно заданного IV;
-   проверку некорректных ключей и IV;
-   защиту от перезаписи входного файла;
-   совместимость с OpenSSL в обоих направлениях.

Тесты совместимости с OpenSSL автоматически пропускаются, если OpenSSL
недоступен в системе.

## Структура проекта

``` text
cryptocore/
├── src/
│   └── cryptocore/
│       ├── __init__.py
│       ├── main.py
│       ├── cli_parser.py
│       ├── file_io.py
│       ├── padding.py
│       └── modes/
│           ├── __init__.py
│           ├── ecb.py
│           ├── cbc.py
│           ├── cfb.py
│           ├── ofb.py
│           └── ctr.py
├── tests/
│   └── test_cryptocore.py
├── setup.py
├── pyproject.toml
├── requirements.txt
├── .gitignore
└── README.md
```

## Особенности реализации

Для базовой криптографической операции AES используется библиотека
PyCryptodome:

``` python
from Crypto.Cipher import AES
```

В проекте реализована логика:

-   PKCS#7 padding;
-   режима ECB;
-   режима CBC;
-   режима CFB128;
-   режима OFB;
-   режима CTR;
-   генерации и обработки IV;
-   работы с форматом файлов;
-   проверки аргументов CLI;
-   чтения и записи файлов.

Сам алгоритм AES не реализуется вручную --- для блочной операции
используется PyCryptodome.

## Обработка ошибок

Программа выводит ошибки аргументов командной строки, ввода/вывода,
ключа, IV и padding в `stderr` и завершает работу с ненулевым кодом
возврата.

Программа также запрещает задавать в качестве выходного файла тот же
файл, который используется как входной.

## Лицензия

Проект предоставлен в учебных целях.
