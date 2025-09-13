<div align="center">

### 👇

  <p>
    <a href="https://github.com/EXLOUD/windows-telemetry-disabler/archive/refs/heads/main.zip  ">
      <img src="https://img.shields.io/badge/_  >_Завантажити_Цей_Скрипт_<_-darkgreen?style=for-the-badge">
    </a>
  </p>

---

### 👀 Перегляди репозиторію

  <img alt="count" src="https://count.getloli.com/get/@:EXLOUD-WIN-TELEMETRY-DISABLER?theme=rule34" />

**⭐ Якщо цей інструмент допоміг вам, будь ласка, залиште зірочку! ⭐**

---

**Мова:** [English](#) | [Українська](README-UK.md)

  <h1>Windows Telemetry Disabler</h1>

  <p>
    <a href="https://docs.microsoft.com/en-us/windows/privacy/  ">
      <img src="https://img.shields.io/badge/Windows_Конфіденційність-0078D4?style=for-the-badge" alt="Windows Privacy">
    </a>
  </p>

  <img src="assets/preview.gif" width="600" alt="Попередній перегляд роботи Windows Telemetry Disabler">

[![GitHub issues](https://img.shields.io/github/issues/EXLOUD/windows-telemetry-disabler?style=flat-square)](https://github.com/EXLOUD/windows-telemetry-disabler/issues)
![PowerShell](https://custom-icon-badges.demolab.com/badge/PowerShell-5.0-5391FE?style=for-the-badge\&logo=powershell\&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D4?style=for-the-badge\&logo=windows\&logoColor=white)
![Ліцензія](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Архітектура](https://custom-icon-badges.demolab.com/badge/Архітектура-x86%20%7C%20x64%20%7C%20ARM64-blue?style=for-the-badge\&logo=cpu\&logoColor=white)
[![GitHub stars](https://img.shields.io/github/stars/EXLOUD/windows-telemetry-disabler?style=flat-square)](https://github.com/EXLOUD/windows-telemetry-disabler/stargazers)

Потужний скрипт для вимкнення телеметрії та збору даних у Windows. Інструмент працює з правами TrustedInstaller для максимальної ефективності та підтримує всі сучасні архітектури Windows.

</div>

---

# Windows Telemetry Disabler

**Автор:** EXLOUD
**GitHub:** [https://github.com/EXLOUD](https://github.com/EXLOUD)

Скрипт для вимкнення телеметрії та збору даних у Windows.

## 📋 Опис

Цей інструмент дозволяє вимкнути різні служби телеметрії Windows, які збирають дані про використання та надсилають їх до Microsoft. Скрипт працює з підвищеними правами (**TrustedInstaller**) для максимальної ефективності.

## 🔧 Системні вимоги

* **ОС:** Windows 10/11
* **PowerShell:** версія 5.0 або новіша
* **Архітектура:** x64, x86 (win32), ARM64
* **Привілеї:** запуск від імені адміністратора

## 🛠️ Інструмент підвищення привілеїв

Скрипт використовує спеціальну утиліту (`superUser*.exe`) для запуску PowerShell-команд із правами **TrustedInstaller**, що забезпечує надійне застосування системних змін.

> **Примітка:** Файли `superUser`, включені в цей реліз — це попередньо скомпільовані сторонні утиліти для тимчасового використання. Ведеться розробка відкритих альтернатив.

<p align="center">
  <a href="https://github.com/mspaintmsi/superUser">
    <img src="https://img.shields.io/badge/superUser-від_mspaintmsi-blue?style=for-the-badge&logo=github&logoColor=white" alt="superUser by mspaintmsi">
  </a>
</p>

## 📁 Структура проєкту

```
📂 assets  
📄 launcher.bat           # Основний запускатор  
📂 script/  
│   📄 telemetry-win.ps1  # Основний PowerShell-скрипт  
│   📂 Tools/  
│       📂 x64/  
│       │   📄 superUser64.exe  
│       📂 win32/  
│       │   📄 superUser32.exe  
│       📂 arm64/  
│           📄 superUserA64.exe  
📄 README.md  
📄 README-UK.md  
```

## 🚀 Встановлення та використання

1. **Завантажте** усі файли проєкту
2. **Розпакуйте** у будь-яку папку
3. **Запустіть** `launcher.bat` **від імені адміністратора**

### Покрокова інструкція:

1. Клікніть правою кнопкою по `launcher.bat`
2. Оберіть "Запустити від імені адміністратора"
3. Підтвердьте UAC-запит
4. Дочекайтесь завершення роботи скрипта

## ⚙️ Як це працює

Запускатор виконує такі дії:

1. **Перевіряє наявність PowerShell 5**
2. **Визначає архітектуру процесора** (x64/x86/ARM64)
3. **Знаходить відповідну версію `superUser`**
4. **Запускає PowerShell-скрипт** з правами TrustedInstaller
5. **Застосовує налаштування** для вимкнення телеметрії

## 🛡️ Що вимикається

Скрипт може вимикати/налаштовувати:

* Служби телеметрії Windows
* Збір діагностичних даних
* Передавання інформації про використання до Microsoft
* Рекламні ідентифікатори
* Автоматичні оновлення телеметрії
* Різні заплановані завдання
* Фонові UWP-додатки
* Зарезервоване сховище
* Журнали DiagTrack
* CompatTelRunner.exe
* Та інше (див. `telemetry-win.ps1`)

## ⚠️ Важливі застереження

* **Резервна копія:** створіть точку відновлення перед запуском
* **Відповідальність:** використовуйте на власний ризик
* **Тестування:** перевіряйте спочатку на віртуальній машині
* **Оновлення:** деякі параметри можуть бути скинуті після оновлення Windows

## 🔄 Відновлення налаштувань

Якщо потрібно повернути стандартні параметри:

1. Використайте точку відновлення
2. Або вручну увімкніть служби через `services.msc`
3. Перезапустіть систему

## 🆘 Усунення несправностей

### Помилка "PowerShell 5 не знайдено"

* Переконайтесь, що PowerShell встановлений
* Перевірте шлях: `%SystemRoot%\System32\WindowsPowerShell\v1.0\`

### Помилка "superUser\*.exe не знайдено"

* Перевірте наявність файлів `superUser` у `script/Tools/`
* Переконайтесь, що збережена структура папок

### Помилка "Непідтримувана архітектура процесора"

* Ваша архітектура наразі не підтримується
* Зв’яжіться з розробником для додавання підтримки

## 📞 Підтримка

* **GitHub Issues:** створіть Issue у репозиторії
* **GitHub:** [https://github.com/EXLOUD](https://github.com/EXLOUD)

## 📄 Ліцензія

Цей проєкт розповсюджується за **MIT License**.

MIT License

Copyright (c) 2025 EXLOUD

Дозвіл надається безкоштовно будь-якій особі, яка отримає копію цього програмного забезпечення та супровідної документації ("Програмне забезпечення"), без обмежень, включно з правом використовувати, копіювати, змінювати, об’єднувати, публікувати, розповсюджувати, субліцензувати та/або продавати копії Програмного забезпечення, а також дозволяти особам, яким надається це Програмне забезпечення, робити те саме, з дотриманням таких умов:

Усі копії чи значні частини Програмного забезпечення мають містити зазначене повідомлення про авторські права та цей дозвіл.

ПРОГРАМНЕ ЗАБЕЗПЕЧЕННЯ НАДАЄТЬСЯ "ЯК Є", БЕЗ ЖОДНИХ ГАРАНТІЙ, ЯВНИХ АБО НЕЯВНИХ, ВКЛЮЧНО, АЛЕ НЕ ОБМЕЖУЮЧИСЬ ГАРАНТІЯМИ КОМЕРЦІЙНОЇ ЦІННОСТІ, ПРИДАТНОСТІ ДЛЯ ПЕВНОЇ МЕТИ ТА ВІДСУТНОСТІ ПОРУШЕНЬ. У ЖОДНОМУ ВИПАДКУ АВТОРИ АБО ВЛАСНИКИ АВТОРСЬКИХ ПРАВ НЕ НЕСУТЬ ВІДПОВІДАЛЬНОСТІ ЗА БУДЬ-ЯКІ ВИМОГИ, ЗБИТКИ ЧИ ІНШІ ЗОБОВ’ЯЗАННЯ, ЯК У РЕЗУЛЬТАТІ ДОГОВОРУ, ДЕЛІКТУ ЧИ ІНШОГО ШЛЯХУ, ЩО ВИНИКАЮТЬ ІЗ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ АБО У ЗВ’ЯЗКУ З НИМ.

---

<div align="center">

**Увага:** Цей інструмент змінює системні налаштування Windows. Переконайтесь, що ви розумієте наслідки перед використанням.

**[⬆ Повернутись до початку](#windows-telemetry-disabler)**

</div>
