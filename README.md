# Telemt → Fail2ban

Интеграция [Telemt](https://github.com/telemt/telemt) с Fail2ban для автоматического бана IP-адресов с подозрительными TLS-отпечатками.

## Описание

Скрипт `telemt-f2b-feeder.py` периодически запрашивает API Telemt `/v1/runtime/tls-fingerprints`, определяет IP-адреса с плохими отпечатками TLS и записывает их в лог-файл. Fail2ban читает этот лог и блокирует подозрительные IP через UFW.

### Как это работает

1. **Telemt** мониторит TLS-соединения и собирает отпечатки (`general.beobachten = true`)
2. **Feeder** запускается каждые 5 минут, запрашивает отпечатки через API
3. **Анализ**: для каждого IP считается доля «плохих» соединений (`bad_or_probe / total`)
4. **Бан**: если доля >= `BAD_RATIO_THRESHOLD` и количество >= `MIN_BAD_COUNT`, IP пишется в лог
5. **Fail2ban** читает лог и применяет бан через UFW

### Пример лога

```
2025-01-15 14:30:22 telemt-bad-fp: BAD_FP ip=192.168.1.100
2025-01-15 14:30:22 telemt-bad-fp: BAD_FP ip=10.0.0.55
```

## Требования

- Python 3.8+
- Fail2ban
- UFW (или другой action в fail2ban)
- Telemt с включенным мониторингом отпечатков

## Установка

### 1. Клонируйте репозиторий

```bash
git clone https://github.com/vsibilev007/telemt-f2b.git
cd telemt-f2b
```

### 2. Установите скрипт

```bash
sudo mkdir -p /opt/telemt_f2b/
sudo cp telemt-f2b-feeder.py /opt/telemt_f2b/
sudo chmod +x /opt/telemt_f2b/telemt-f2b-feeder.py
```

### 3. Установите Fail2ban конфигурацию

```bash
# Фильтр (паттерн для парсинга лога)
sudo cp telemt-bad-fp.conf /etc/fail2ban/filter.d/

# Jail (правила бана)
sudo cp jail.d-telemt-bad-fp.conf /etc/fail2ban/jail.d/telemt-bad-fp.conf

# Action (бан через UFW)
sudo cp action.d-ufw-telemt.conf /etc/fail2ban/action.d/ufw-telemt.conf
```

### 4. Установите Systemd юниты

```bash
sudo cp telemt-f2b-feeder.service /etc/systemd/system/
sudo cp telemt-f2b-feeder.timer /etc/systemd/system/
```

### 5. Настройте переменные окружения

Отредактируйте `/etc/systemd/system/telemt-f2b-feeder.service`:

```ini
[Service]
Environment=TELEMT_URL=http://127.0.0.1:9091
Environment=TELEMT_AUTH=Bearer your_token_here
Environment=BAD_RATIO_THRESHOLD=1.0
Environment=MIN_BAD_COUNT=1
```

### 6. Запустите

```bash
# Перезагрузить systemd
sudo systemctl daemon-reload

# Включить и запустить таймер
sudo systemctl enable --now telemt-f2b-feeder.timer

# Перечитать конфиг fail2ban
sudo fail2ban-client reload
```

## Проверка

```bash
# Проверить что фильтр корректный
fail2ban-regex /var/log/telemt-bad-fp.log /etc/fail2ban/filter.d/telemt-bad-fp.conf

# Посмотреть статус jail
sudo fail2ban-client status telemt-bad-fp

# Запустить feeder вручную для теста
sudo python3 /opt/telemt_f2b/telemt-f2b-feeder.py

# Посмотреть лог feeder-а
sudo journalctl -u telemt-f2b-feeder.service -n 20

# Посмотреть что написал feeder в лог
sudo tail -f /var/log/telemt-bad-fp.log

# Список забаненных IP
sudo fail2ban-client get telemt-bad-fp banned

# Разбанить конкретный IP
sudo fail2ban-client set telemt-bad-fp unbanip 1.2.3.4
```

## Конфигурация

### Переменные окружения

| Переменная | По умолчанию | Описание |
|---|---|---|
| `TELEMT_URL` | `http://127.0.0.1:9091` | URL Telemt API |
| `TELEMT_AUTH` | — | `Bearer <token>` если нужна авторизация |
| `F2B_LOG` | `/var/log/telemt-bad-fp.log` | Лог-файл для fail2ban |
| `FP_LIMIT` | `1000` | Лимит записей из API |
| `BAD_RATIO_THRESHOLD` | `1.0` | Доля плохих соединений для бана |
| `MIN_BAD_COUNT` | `1` | Минимум плохих соединений для бана |
| `API_RETRIES` | `3` | Количество повторных попыток |
| `API_RETRY_DELAY` | `2` | Задержка между попытками (сек) |
| `LOG_MAX_SIZE` | `10485760` | Максимальный размер лога (10MB) |
| `LOG_BACKUP_COUNT` | `5` | Количество бэкапов лога |

### Fail2ban jail

Файл `/etc/fail2ban/jail.d/telemt-bad-fp.conf`:

```ini
[telemt-bad-fp]
enabled  = true
backend  = polling
filter   = telemt-bad-fp
logpath  = /var/log/telemt-bad-fp.log
bantime  = 3600      # бан на 1 час
findtime = 600       # окно поиска 10 минут
maxretry = 1         # бан с первого попадания
action   = ufw-telemt
```

## Логика бана

Feeder читает `by_ip` из `/v1/runtime/tls-fingerprints` и банит IP если:

- `bad_or_probe >= MIN_BAD_COUNT`
- `bad_or_probe / total >= BAD_RATIO_THRESHOLD`

### Примеры настроек

| `BAD_RATIO_THRESHOLD` | Поведение |
|---|---|
| `1.0` | Банить только если **все** соединения плохие (безопасно, минимум ложных срабатываний) |
| `0.8` | Банить если 80%+ соединений плохие |
| `0.5` | Банить если более 50% соединений плохие (агрессивнее) |

## Структура файлов

```
telemt-f2b/
├── telemt-f2b-feeder.py          # Основной скрипт
├── telemt-bad-fp.conf            # Fail2ban filter
├── jail.d-telemt-bad-fp.conf     # Fail2ban jail
├── action.d-ufw-telemt.conf      # Fail2ban action (UFW)
├── telemt-f2b-feeder.service     # Systemd service
├── telemt-f2b-feeder.timer       # Systemd timer
├── LICENSE                        # MIT License
└── README.md                      # Этот файл
```

## Удаление

```bash
# Остановить и отключить таймер
sudo systemctl stop telemt-f2b-feeder.timer
sudo systemctl disable telemt-f2b-feeder.timer

# Удалить systemd юниты
sudo rm /etc/systemd/system/telemt-f2b-feeder.service
sudo rm /etc/systemd/system/telemt-f2b-feeder.timer
sudo systemctl daemon-reload

# Удалить fail2ban конфиги
sudo rm /etc/fail2ban/filter.d/telemt-bad-fp.conf
sudo rm /etc/fail2ban/jail.d/telemt-bad-fp.conf
sudo rm /etc/fail2ban/action.d/ufw-telemt.conf
sudo fail2ban-client reload

# Удалить скрипт
sudo rm -rf /opt/telemt_f2b/

# Удалить логи
sudo rm /var/log/telemt-bad-fp.log*
```

## Лицензия

MIT License
