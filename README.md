# Firewalld Standard

Скрипты для проверки и приведения firewalld к стандартной схеме.

## Файлы

- `setup-firewall-standard.sh` — безопасный launcher: preflight, проверка прав, автоопределение интерфейса, проверка SSH IP, check-only.
- `setup-firewall-standard-core.sh` — основной движок check/fix/verify. Напрямую не запускать.
- `firewall-standard.example.conf` — пример конфига без реальных IP.

## Установка

```bash
cp setup-firewall-standard.sh /opt/
cp setup-firewall-standard-core.sh /opt/
cp firewall-standard.example.conf /etc/firewall-standard.conf

chown root:root /opt/setup-firewall-standard.sh /opt/setup-firewall-standard-core.sh
chmod 750 /opt/setup-firewall-standard.sh /opt/setup-firewall-standard-core.sh

chown root:root /etc/firewall-standard.conf
chmod 600 /etc/firewall-standard.conf
```

После копирования нужно отредактировать:

```bash
vi /etc/firewall-standard.conf
```

## Проверка

```bash
bash -n /opt/setup-firewall-standard.sh
bash -n /opt/setup-firewall-standard-core.sh
bash -n /etc/firewall-standard.conf
```

## Запуск

```bash
/opt/setup-firewall-standard.sh
```

Если firewall уже соответствует стандарту, изменения не выполняются.

Если есть отклонения, скрипт покажет проблему и спросит подтверждение перед исправлением.

## Важно

Файл `firewall-standard.example.conf` содержит только примерные IP.

На сервере нужно создать реальный конфиг:

```bash
cp firewall-standard.example.conf /etc/firewall-standard.conf
vi /etc/firewall-standard.conf
```

В `/etc/firewall-standard.conf` указываются реальные IP и порты.

Этот файл нельзя публиковать в GitHub.
