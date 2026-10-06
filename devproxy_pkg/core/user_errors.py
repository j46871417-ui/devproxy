"""Safe Russian diagnostics: never display raw exception text or upstream headers."""
import socket
import ssl
from .transport import ProxyError


class UserInputError(ValueError):
    pass


def describe_error(error, target="github.com"):
    if isinstance(error, UserInputError):
        return str(error)
    if isinstance(error, ProxyError):
        if error.code == "auth_failed":
            hint = f" (HTTP {error.status})" if error.status else ""
            return (
                f"Этап: авторизация на прокси.\n"
                f"Причина: прокси отклонил логин или пароль{hint}.\n"
                f"Что делать: нажмите «Изменить» и проверьте данные авторизации."
            )
        if error.code == "auth_method":
            return (
                "Этап: согласование метода авторизации.\n"
                "Причина: прокси не принял способ авторизации SOCKS5.\n"
                "Что делать: проверьте тип прокси и необходимость логина/пароля."
            )
        if error.code == "credential_length":
            return (
                "Этап: проверка данных авторизации.\n"
                "Причина: для SOCKS5 логин и пароль должны содержать от 1 до 255 байт каждый.\n"
                "Что делать: проверьте длину логина и пароля в настройках профиля."
            )
        if error.code == "http_rejected":
            status = str(error.status) if isinstance(error.status, int) else "неизвестный"
            return (
                f"Этап: открытие туннеля к {target}.\n"
                f"Причина: прокси ответил HTTP {status} при подключении к {target}.\n"
                f"Что делать: проверьте ограничения прокси или выберите другой сайт проверки."
            )
        if error.code == "destination_rejected":
            return (
                f"Этап: подключение к сайту {target}.\n"
                f"Причина: SOCKS5-прокси запретил или не смог открыть {target}.\n"
                f"Что делать: проверьте ограничения и DNS на стороне прокси."
            )
        return (
            "Этап: проверка сетевого протокола.\n"
            "Причина: ответ сервера не соответствует выбранному типу прокси.\n"
            "Что делать: проверьте HTTP/SOCKS5 и порт."
        )
    if isinstance(error, ssl.SSLError):
        return (
            "Этап: защищённое TLS-соединение с прокси.\n"
            "Причина: ошибка защищённого соединения с прокси (недействительный или недоверенный сертификат).\n"
            "Что делать: проверьте его сертификат и тип подключения HTTPS; проверка сертификатов не отключается."
        )
    if isinstance(error, socket.gaierror):
        return (
            "Этап: поиск сервера прокси в сети (DNS).\n"
            "Причина: не удалось найти сервер прокси по имени.\n"
            "Что делать: проверьте адрес и подключение к сети."
        )
    if isinstance(error, ConnectionRefusedError):
        return (
            "Этап: подключение к серверу прокси.\n"
            "Причина: сервер прокси отказал в подключении (порт закрыт или сервис не запущен).\n"
            "Что делать: проверьте адрес, порт и запущен ли прокси."
        )
    if isinstance(error, (ConnectionResetError, ConnectionError)):
        return (
            "Этап: обмен данными с сервером прокси.\n"
            "Причина: соединение с прокси разорвано.\n"
            "Что делать: проверьте тип прокси, порт и доступность сервера."
        )
    if isinstance(error, TimeoutError):
        return (
            "Этап: ожидание ответа прокси.\n"
            "Причина: прокси не ответил вовремя (таймаут соединения).\n"
            "Что делать: проверьте адрес, порт, сеть и доступность сервера."
        )
    if isinstance(error, FileNotFoundError):
        return (
            "Этап: запуск приложения.\n"
            "Причина: исполняемый файл приложения не найден.\n"
            "Что делать: нажмите «Найти приложения» или добавьте файл вручную."
        )
    if isinstance(error, PermissionError):
        return (
            "Этап: доступ к файлу приложения.\n"
            "Причина: Windows запретила доступ.\n"
            "Что делать: проверьте права на приложение; пакетная версия может требовать обычную установку EXE."
        )
    if isinstance(error, ValueError):
        known = {
            "Proxy profile not found": "Профиль прокси не найден. Добавьте его или выберите другой.",
            "Saved proxy credential unavailable; re-save the profile": "Сохранённый пароль недоступен. Нажмите «Изменить», введите пароль заново и сохраните профиль.",
            "Profile store is corrupt; refusing to overwrite it": "Файл настроек повреждён. DevProxy не перезаписывает его, чтобы сохранить ваши данные.",
            "Invalid proxy address; use scheme://host:port (IPv6 in brackets)": "Некорректный адрес прокси. Используйте формат тип://сервер:порт или сервер:порт:логин:пароль.",
            "Credentials in proxy URLs are prohibited": "Учётные данные в ссылке запрещены. Вводите их в полях диалога профиля.",
            "Select the actual EXE; batch and command wrappers are unsupported": "Выберите исполняемый файл .exe. Скрипты .cmd и .bat не поддерживаются.",
            "Strict per-application routing requires a WFP redirector; this build only supports native/environment proxy configuration": "Принудительный fail-closed режим требует драйвера WFP и прав администратора. Текущая сборка работает в режиме переменных окружения.",
            "Application not detected; select its EXE path": "Приложение не найдено. Нажмите «Добавить EXE…» и укажите путь вручную.",
            "Application arguments cannot override session proxy, profile or TLS policy": "Параметры запуска не могут отключать прокси или проверку TLS.",
        }
        if str(error) in known:
            return known[str(error)]
        return "Некорректные настройки. Проверьте название, адрес, порт, тип прокси и логин."
    if isinstance(error, OSError):
        if str(error) == "Windows Credential Manager unavailable; profile was not saved":
            return "Windows не смогла сохранить пароль. Нужен доступный Диспетчер учётных данных в вашей пользовательской сессии. Профиль не сохранён."
        return "Ошибка Windows при выполнении операции. Проверьте подключение к сети и права доступа."
    return "Не удалось выполнить действие. Проверьте настройки прокси и выбранные приложения."
