# Портирование и Интеграция ядра Hidekey (Super Box) на iOS

Данная папка содержит полную инструкцию и скрипт автоматической кросс-компиляции ядра `super_box` в универсальный Xcode-пакет **XCFramework** для разработки VPN-клиента под Apple iOS (iPhone/iPad) и iOS Simulator.

---

## 🛠 Требования для сборки
1. Компьютер под управлением **macOS** (требуется для Xcode).
2. Установленный **Xcode** и Xcode Command Line Tools.
3. Настроенный Rust-инструментарий и iOS-таргеты (скрипт сборки установит их автоматически).

---

## 📁 Структура директории
*   [README.md](file:///c:/Users/User/Desktop/super%20box/ios/README.md) — Данная инструкция по интеграции.
*   [build.sh](file:///c:/Users/User/Desktop/super%20box/ios/build.sh) — Скрипт сборки физической + симуляторных библиотек в Xcode XCFramework.

---

## 🚀 Пошаговая сборка Xcode XCFramework

1. Запустите терминал в корневой папке проекта на macOS.
2. Сделайте скрипт исполняемым и запустите его:
   ```bash
   chmod +x ios/build.sh
   ./ios/build.sh
   ```
3. Скрипт установит iOS-компиляторы для Rust, скомпилирует исходники с максимальной скоростью оптимизации (`--release`, LTO, strip) и соберет кросс-платформенную сборку.
4. Готовый пакет будет находиться в:
   `target/super_box.xcframework`

---

## 📱 Интеграция в iOS-проект (Xcode)

Для создания полноценного системного VPN на iOS используется системный фреймворк **NetworkExtension**.

### Шаг 1: Добавление XCFramework в Xcode
1. Откройте ваш iOS проект в Xcode.
2. Перетащите сгенерированную папку `super_box.xcframework` в раздел **Frameworks, Libraries, and Embedded Content** настроек вашего основного приложения и расширения **Packet Tunnel Provider**.
3. Убедитесь, что для фреймворка выбран режим **Do Not Embed** (так как библиотека слинкована статически).

### Шаг 2: Создание Objective-C Bridging Header
Поскольку Rust компилирует C-совместимые функции (`extern "C"`), нам нужно объявить интерфейс ядра в Xcode.

1. Создайте файл заголовка `super_box.h`:
   ```c
   #ifndef super_box_h
   #define super_box_h

   // Запуск системного VPN туннеля на iOS
   int super_box_start_tunnel(int tun_fd, const char* config_url);

   // Остановка и чистый выход ядра
   void super_box_stop_tunnel(void);

   #endif
   ```
2. Подключите файл `super_box.h` в ваш **Objective-C Bridging Header** проекта (или добавьте в пути заголовков Packet Tunnel).

### Шаг 3: Написание кода PacketTunnelProvider (Swift)
Создайте расширение **Packet Tunnel Provider** (системная служба VPN на iOS) и управляйте ядром Rust напрямую:

```swift
import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        
        // 1. Получаем дескриптор виртуального системного интерфейса TUN
        // (Используем reflection-доступ к сокету NetworkExtension)
        guard let tunnelProvider = self.packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32 else {
            completionHandler(NSError(domain: "VPNError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to acquire TUN fd"]))
            return
        }
        
        // 2. Получаем ссылку на подписку / конфиг
        let subscribeUrl = "hidekey://your-config-uri..."
        
        // 3. Передаем дескриптор сокета напрямую в Rust-ядро!
        // Это обеспечивает нулевые накладные расходы и феноменальную скорость
        let success = super_box_start_tunnel(tunnelProvider, subscribeUrl)
        
        if success == 1 {
            // Уведомляем систему iOS, что VPN туннель запущен и перехватывает трафик
            let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "8.8.8.8")
            
            // Направляем ВСЕ системные DNS-запросы в туннель на встроенный DoH-перехватчик
            let dnsSettings = NEDNSSettings(servers: ["8.8.8.8"])
            dnsSettings.matchDomains = [""]
            settings.dnsSettings = dnsSettings
            
            // Захватываем весь системный IP-трафик
            settings.ipv4Settings = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
            settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
            
            self.setTunnelNetworkSettings(settings) { error in
                completionHandler(error)
            }
        } else {
            completionHandler(NSError(domain: "VPNError", code: 2, userInfo: [NSLocalizedDescriptionKey: "Rust core failed to start"]))
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        // 1. Сигнализируем асинхронному ядру на Rust остановить потоки
        super_box_stop_tunnel()
        
        // 2. Уведомляем систему iOS о завершении сессии
        completionHandler()
    }
}
```

---

## 🔒 Безопасность и энергоэффективность
*   Благодаря компиляции через Rust native `staticlib`, ядро полностью скомпоновано в нативный бинарник без виртуальных машин (в отличие от Golang/Java решений).
*   Запуск сетевого стека `netstack-smoltcp` прямо на файловом дескрипторе `tun_fd` исключает копирование сетевых пакетов из пространства ядра в Swift, обеспечивая **минимальный расход батареи** и **высочайшую скорость работы** на iPhone!
