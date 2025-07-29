<div align="center">

### 👇

  <p>
    <a href="https://github.com/EXLOUD/windows-telemetry-disabler/archive/refs/heads/main.zip">
      <img src="https://img.shields.io/badge/_>_Завантажити_Цей_Скрипт_<_-darkgreen?style=for-the-badge">
    </a>
  </p>


---

### 👀 Перегляди Репозиторію

  <img alt="count" src="https://count.getloli.com/get/@:EXLOUD-WIN-TELEMETRY-DISABLER?theme=rule34" />

  **⭐ Якщо цей інструмент допоміг вам, будь ласка, поставте зірочку! ⭐**

---

  **Мова:** [English](README.md) | [Українська](#)

  <h1>Вимикач Телеметрії Windows</h1>
  
  <p>
    <a href="https://docs.microsoft.com/en-us/windows/privacy/">
      <img src="https://img.shields.io/badge/Приватність_Windows-0078D4?style=for-the-badge" alt="Windows Privacy">
    </a>
  </p>
  
  <img src="assets/preview.gif" width="600" alt="Демо перегляд">
  
  [![GitHub issues](https://img.shields.io/github/issues/EXLOUD/windows-telemetry-disabler?style=flat-square)](https://github.com/EXLOUD/windows-telemetry-disabler/issues)
  ![PowerShell](https://custom-icon-badges.demolab.com/badge/PowerShell-5.0-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
  ![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white)
  ![License](https://img.shields.io/badge/Ліцензія-MIT-green?style=for-the-badge)
  ![Architecture](https://custom-icon-badges.demolab.com/badge/Архітектура-x86%20%7C%20x64%20%7C%20ARM64-blue?style=for-the-badge&logo=cpu&logoColor=white)
  [![GitHub stars](https://img.shields.io/github/stars/EXLOUD/windows-telemetry-disabler?style=flat-square)](https://github.com/EXLOUD/windows-telemetry-disabler/stargazers)

  Потужний скрипт для вимкнення телеметрії та збору даних в операційній системі Windows. Цей інструмент працює з привілеями TrustedInstaller для максимальної ефективності та підтримує всі сучасні архітектури Windows.

</div>

---

# Вимикач Телеметрії Windows

**Автор:** EXLOUD  
**GitHub:** https://github.com/EXLOUD

Скрипт для вимкнення телеметрії та збору даних в операційній системі Windows.

## 📋 Опис

Цей інструмент дозволяє вимкнути різні служби телеметрії Windows, які збирають дані про використання та відправляють їх до Microsoft. Скрипт працює з підвищеними привілеями (TrustedInstaller) для максимальної ефективності.

## 🔧 Системні Вимоги

- **Операційна система:** Windows 10/11
- **PowerShell:** версія 5.0 або новіша
- **Архітектура:** x64, x86 (win32), ARM64
- **Привілеї:** Запуск від імені Адміністратора

## 🛠️ Використовувані Сторонні Інструменти

Цей скрипт наразі використовує кілька сторонніх пропрієтарних утиліт для виконання (альтернативи розробляються):

  <p align="center">
    <a href="https://github.com/M2Team/NSudo">
      <img src="https://img.shields.io/badge/NSudo-від_M2Team-blue?style=for-the-badge&logo=github&logoColor=white" alt="NSudo">
    </a>
    <a href="https://github.com/eject37">
      <img src="https://img.shields.io/badge/Unlocker-від_Eject37-orange?style=for-the-badge&logo=github&logoColor=white" alt="Unlocker by Eject37">
    </a>
  </p>

- **NSudo** - Надає привілеї TrustedInstaller для модифікацій на системному рівні
- **Unlocker** - Базується на IObitUnlocker від компанії IObit, модифікований Eject37 для розблокування та видалення файлів

> **Примітка:** Ці пропрієтарні утиліти використовуються тимчасово, поки розробляються власні альтернативи.

## 📁 Структура Проекту

```
├── assets
├── launcher.bat              # Головний лаунчер
├── script/
│   ├── telemetry-win.ps1    # Головний PowerShell скрипт
│   └── Tools/
│       ├── NSudo/
│       │   ├── x64/
│       │   ├── win32/
│       │   └── arm64/
│       │       └── NSudoLG.exe
│       └── Unlocker.exe      # Утиліта для розблокування та видалення файлів
├── README.md
└── README-UK.md
```

## 🚀 Встановлення та Використання

1. **Завантажте** всі файли проекту
2. **Розпакуйте** в будь-яку папку
3. **Запустіть** `launcher.bat` **від імені Адміністратора**

### Покрокові інструкції:

1. Клацніть правою кнопкою миші на `launcher.bat`
2. Виберіть "Запустити від імені адміністратора"
3. Підтвердіть запит UAC
4. Дочекайтесь завершення роботи скрипта

## ⚙️ Як це Працює

Лаунчер виконує наступні дії:

1. **Перевіряє доступність PowerShell 5**
2. **Визначає архітектуру процесора** (x64/x86/ARM64)
3. **Знаходить відповідну версію NSudo**
4. **Запускає PowerShell скрипт** з привілеями TrustedInstaller
5. **Застосовує конфігурації** для вимкнення телеметрії

## 🛡️ Що Вимикається

Скрипт може вимкнути/налаштувати:

- Служби телеметрії Windows
- Збір діагностичних даних
- Передачу даних про використання до Microsoft
- Рекламні ідентифікатори
- Автоматичні оновлення телеметрії
- Різні заплановані завдання

*Для детального списку змін дивіться `telemetry-win.ps1`*

## ⚠️ Важливі Попередження

- **Резервна копія:** Створіть точку відновлення системи перед запуском
- **Відповідальність:** Використовуйте на свій ризик
- **Тестування:** Спочатку протестуйте на віртуальній машині
- **Оновлення:** Деякі налаштування можуть скинутися після оновлень Windows

## 🔄 Відновлення Налаштувань

Якщо потрібно відновити стандартні налаштування:

1. Використайте точку відновлення системи
2. Або вручну увімкніть вимкнені служби через `services.msc`
3. Перезавантажте систему

## 🆘 Усунення Проблем

### Помилка "PowerShell 5 не знайдено"
- Переконайтесь, що PowerShell встановлено
- Перевірте шлях: `%SystemRoot%\System32\WindowsPowerShell\v1.0\`

### Помилка "NSudoLG.exe не знайдено"
- Переконайтесь, що файли NSudo існують в папці `script/Tools/NSudo/`
- Перевірте, що структура папок збережена

### Помилка "Непідтримувана архітектура процесора"
- Ваша архітектура процесора не підтримується
- Зверніться до розробника для додання підтримки

## 📞 Підтримка

- **GitHub Issues:** Створіть issue в репозиторії
- **GitHub:** https://github.com/EXLOUD

## 📄 Ліцензія

Цей проект ліцензовано під **MIT Ліцензією**.

```
MIT License

Copyright (c) 2025 EXLOUD

Дозволяється безкоштовно отримувати копію цього програмного забезпечення 
та супровідних файлів документації ("Програмне забезпечення"), для роботи 
з Програмним забезпеченням без обмежень, включаючи без обмежень права на 
використання, копіювання, модифікацію, об'єднання, публікацію, розповсюдження, 
ліцензування та/або продаж копій Програмного забезпечення, а також надання 
права особам, яким надається Програмне забезпечення, робити це за умови 
дотримання наступних умов:

Вищезазначене повідомлення про авторські права та це повідомлення про дозвіл 
повинні бути включені до всіх копій або значних частин Програмного забезпечення.

ПРОГРАМНЕ ЗАБЕЗПЕЧЕННЯ НАДАЄТЬСЯ "ЯК Є", БЕЗ БУДЬ-ЯКИХ ГАРАНТІЙ, ЯВНИХ ЧИ 
НЕЯВНИХ, ВКЛЮЧАЮЧИ, АЛЕ НЕ ОБМЕЖУЮЧИСЬ ГАРАНТІЯМИ ТОВАРНОСТІ, ПРИДАТНОСТІ 
ДЛЯ ПЕВНОЇ МЕТИ ТА НЕНАРУШЕННЯ. В ЖОДНОМУ ВИПАДКУ АВТОРИ ЧИ ВЛАСНИКИ 
АВТОРСЬКИХ ПРАВ НЕ НЕСУТЬ ВІДПОВІДАЛЬНОСТІ ЗА БУДЬ-ЯКІ ПОЗОВИ, ЗБИТКИ АБО 
ІНШУ ВІДПОВІДАЛЬНІСТЬ, ЧИ ТО В РАМКАХ ДОГОВОРУ, ПРАВОПОРУШЕННЯ АБО ІНШИМ 
ЧИНОМ, ЩО ВИНИКАЮТЬ З АБО У ЗВ'ЯЗКУ З ПРОГРАМНИМ ЗАБЕЗПЕЧЕННЯМ АБО 
ВИКОРИСТАННЯМ ЧИ ІНШИМИ ДІЯМИ З ПРОГРАМНИМ ЗАБЕЗПЕЧЕННЯМ.
```

---

**Попередження:** Цей інструмент змінює системні налаштування Windows. Переконайтесь, що розумієте наслідки перед використанням.

  <div align="center">
    <a href="https://github.com/EXLOUD/windows-telemetry-disabler">
      <img src="https://img.shields.io/badge/⬆️_На_початок-blue?style=for-the-badge">
    </a>
  </div>