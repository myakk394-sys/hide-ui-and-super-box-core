# Портирование ядра Hidekey (Super Box) на Android

Данная папка содержит необходимые инструменты, конфигурационные файлы и исходные коды для портирования и компиляции ядра `super_box` под операционную систему Android с использованием **Android NDK** и **Rust JNI**.

---

## 🛠 Требования для сборки
Для сборки native-библиотеки вам понадобятся:
1. Установленный [Android NDK](https://developer.android.com/ndk) (рекомендуется версия r25+).
2. Настроенный Rust-инструментарий и кросс-компиляционные таргеты:
   ```bash
   rustup target add aarch64-linux-android      # Для современных 64-битных ARM телефонов
   rustup target add armv7-linux-androideabi    # Для старых 32-битных ARM телефонов
   rustup target add x86_64-linux-android        # Для эмуляторов Android на ПК
   ```
3. Утилита `cargo-ndk` для автоматического подтягивания путей к компиляторам NDK:
   ```bash
   cargo install cargo-ndk
   ```

---

## 📁 Структура директории
*   [README.md](file:///c:/Users/User/Desktop/super%20box/android/README.md) — Данная инструкция.
*   [build.sh](file:///c:/Users/User/Desktop/super%20box/android/build.sh) — Автоматический bash-скрипт компиляции native-библиотеки `.so`.
*   [jni_wrapper.rs](file:///c:/Users/User/Desktop/super%20box/android/jni_wrapper.rs) — Исходный JNI-код на Rust для связи Android Java/Kotlin c асинхронным ядром Hidekey.
*   [MyVpnService.kt](file:///c:/Users/User/Desktop/super%20box/android/MyVpnService.kt) — Пример реализации класса `VpnService` в Android-приложении.

---

## 🚀 Пошаговая инструкция по сборке

### Шаг 1: Компиляция библиотеки `.so`
Запустите скрипт сборки [build.sh](file:///c:/Users/User/Desktop/super%20box/android/build.sh), указав путь к установленному Android NDK:
```bash
export ANDROID_NDK_HOME="/path/to/your/Android/Sdk/ndk/25.x.xxxx"
chmod +x build.sh
./build.sh
```
Скрипт сгенерирует собранные библиотеки по путям:
*   `../target/aarch64-linux-android/release/libsuper_box_jni.so`
*   `../target/armv7-linux-androideabi/release/libsuper_box_jni.so`

### Шаг 2: Интеграция в Android-проект (Android Studio)
1. Скопируйте файлы библиотек `.so` в папку вашего Android-приложения:
   *   `app/src/main/jniLibs/arm64-v8a/libsuper_box_jni.so` (из aarch64)
   *   `app/src/main/jniLibs/armeabi-v7a/libsuper_box_jni.so` (из armv7)
2. Создайте Kotlin-класс службы VPN на базе примера [MyVpnService.kt](file:///c:/Users/User/Desktop/super%20box/android/MyVpnService.kt).
3. Добавьте службу в `AndroidManifest.xml`:
   ```xml
   <service
       android:name=".MyVpnService"
       android:permission="android.permission.BIND_VPN_SERVICE"
       android:exported="false">
       <intent-filter>
           <action android:name="android.net.VpnService" />
       </intent-filter>
   </service>
   ```

---

## 🔒 Как это работает криптографически на Android
Android предоставляет системный класс `VpnService`, который создаёт виртуальный TUN-интерфейс в пространстве ядра Android и возвращает приложению файловый дескриптор файла (`ParcelFileDescriptor`).
Наш JNI-загрузчик [jni_wrapper.rs](file:///c:/Users/User/Desktop/super%20box/android/jni_wrapper.rs) принимает этот файловый дескриптор напрямую, оборачивает его в асинхронный сокет `tokio` с помощью `std::os::unix::io::FromRawFd` и запускает наш zero-legacy Hidekey туннелировщик.
Это даёт **максимально возможную скорость и минимальный пинг**, исключая лишнее копирование пакетов между Java и Rust.
