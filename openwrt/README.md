# Упаковка и Кросс-компиляция Hidekey (Super Box) для OpenWrt

Данная директория содержит полный набор скриптов, конфигураций и Makefile для сборки ядра `super_box` в виде стандартного пакета OpenWrt (`.ipk`), который можно установить на домашний роутер.

---

## 📁 Структура директории
*   [README.md](file:///c:/Users/User/Desktop/super%20box/openwrt/README.md) — Данная инструкция.
*   [Makefile](file:///c:/Users/User/Desktop/super%20box/openwrt/Makefile) — Сборочный Makefile для OpenWrt Buildroot SDK.
*   [build.sh](file:///c:/Users/User/Desktop/super%20box/openwrt/build.sh) — Скрипт автоматизации кросс-компиляции под различные архитектуры роутеров.
*   [super-box.init](file:///c:/Users/User/Desktop/super%20box/openwrt/super-box.init) — Системный скрипт инициализации Procd для демонизации ядра.
*   [super-box.config](file:///c:/Users/User/Desktop/super%20box/openwrt/super-box.config) — Файл конфигурации UCI (`/etc/config/super-box`).

---

## ⚙️ Поддерживаемые Архитектуры роутеров
Мы скомпонуем ядро с использованием статической линковки `musl`, что делает бинарник переносимым на любые прошивки без зависимостей от libc:
*   `mips-unknown-linux-musl` / `mipsel-unknown-linux-musl` (Популярные чипы MediaTek MT7621, Realtek)
*   `arm-unknown-linux-musleabi` / `aarch64-unknown-linux-musl` (Роутеры Keenetic, ASUS, ARM чипы)
*   `x86_64-unknown-linux-musl` (x86 роутеры, мини-ПК, виртуальные машины)

---

## 🚀 Пошаговая сборка пакета `.ipk`

### Вариант 1: Быстрая сборка через Rust Musl Target (Без SDK)
Если у вас нет полного OpenWrt SDK, вы можете собрать чистый статический бинарник с помощью Rust-компилятора, сжать его и залить на роутер.

1. Установите кросс-компилятор для архитектуры вашего роутера (например, ARM64):
   ```bash
   rustup target add aarch64-unknown-linux-musl
   ```
2. Запустите скрипт сборки [build.sh](file:///c:/Users/User/Desktop/super%20box/openwrt/build.sh):
   ```bash
   chmod +x build.sh
   ./build.sh aarch64
   ```
3. Скрипт скомпилирует ядро с максимальной оптимизацией размера (`opt-level = "z"`, LTO, strip) и сожмет бинарник. Готовый файл появится в `../target/aarch64-unknown-linux-musl/release/super_box`.

---

### Вариант 2: Сборка официального пакета через OpenWrt SDK
Если вы хотите скомпилировать полноценный устанавливаемый `.ipk` пакет со всеми скриптами автозапуска и UCI:

1. Скачайте [OpenWrt SDK](https://openwrt.org/docs/guide-developer/toolchain/use-buildsystem) под версию вашей прошивки роутера и распакуйте его.
2. Создайте папку для нашего пакета внутри SDK:
   ```bash
   mkdir -p package/utils/super-box
   ```
3. Скопируйте наш [Makefile](file:///c:/Users/User/Desktop/super%20box/openwrt/Makefile) в созданную папку `package/utils/super-box/Makefile`.
4. Скопируйте исходные файлы:
   ```bash
   cp -r /path/to/super_box/* package/utils/super-box/
   ```
5. Запустите компиляцию в SDK:
   ```bash
   make package/utils/super-box/compile V=s
   ```
6. Готовый пакет `.ipk` будет лежать по адресу: `bin/packages/<architecture>/base/super-box_<version>_<arch>.ipk`.

---

## 🔧 Конфигурация и управление на роутере

После установки пакета на роутер, вы получите:
1. **Бинарный файл:** `/usr/bin/super_box`
2. **Конфигурационный файл:** `/etc/config/super-box` (содержит ссылку подписки и порты).
3. **Автозапуск службы:** Демон контролируется через OpenWrt Procd.

**Команды управления:**
```bash
/etc/init.d/super-box enable   # Включить автозапуск при старте роутера
/etc/init.d/super-box start    # Запустить VPN туннель
/etc/init.d/super-box stop     # Остановить службу
/etc/init.d/super-box restart  # Перезапустить туннель
```

**Мониторинг логов на роутере:**
Вы можете читать логи ядра Hidekey стандартной утилитой логов OpenWrt:
```bash
logread -e "super_box"
```
