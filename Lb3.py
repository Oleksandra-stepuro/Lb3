import sqlite3
import hashlib

DATABASE_NAME = 'users.db'

def create_connection():
    # З'єднання з базою даних SQLite
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        print(f"SQLite DB [{DATABASE_NAME}] підключено успішно.")
    except sqlite3.Error as e:
        print(f"Помилка підключення до SQLite: {e}")
    return conn

def create_table(conn):
    # Створення таблиці користувачів
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_accounts (
                login TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                full_name TEXT
            );
        """)
        conn.commit()
        print("Таблиця 'user_accounts' перевірена/створена.")
    except sqlite3.Error as e:
        print(f"Помилка при створенні таблиці: {e}")

def hash_password(password):
    # Хешування
    hasher = hashlib.sha256()
    hasher.update(password.encode('utf-8'))
    return hasher.hexdigest()

def add_user(conn):
    print("\n/// Додавання нового користувача ///")
    login = input("Введіть логін: ")
    password = input("Введіть пароль: ")
    full_name = input("Введіть повне ПІБ: ")

    # Перевіряється чи існує вже користувач з таким логіном
    cursor = conn.cursor()
    cursor.execute("SELECT login FROM user_accounts WHERE login = ?", (login,))
    if cursor.fetchone():
        print(f"Помилка: Користувач з логіном '{login}' вже існує.")
        return

    hashed_pw = hash_password(password)

    try:
        cursor.execute("""
            INSERT INTO user_accounts (login, password, full_name)
            VALUES (?, ?, ?);
        """, (login, hashed_pw, full_name))
        conn.commit()
        print(f"Користувача '{login}' успішно додано.")
    except sqlite3.Error as e:
        print(f"Помилка при додаванні користувача: {e}")

def update_user_password(conn):
    #Оновлюється пароль існуючого користувача
    print("\n/// Оновлення паролю користувача ///")
    login = input("Введіть логін користувача, якому потрібно оновити пароль: ")
    new_password = input("Введіть новий пароль: ")

    # Перевірка чи існує користувач
    cursor = conn.cursor()
    cursor.execute("SELECT login FROM user_accounts WHERE login = ?", (login,))
    if not cursor.fetchone():
        print(f"Помилка: Користувача з логіном '{login}' не знайдено.")
        return

    hashed_new_pw = hash_password(new_password)

    try:
        cursor.execute("""
            UPDATE user_accounts
            SET password = ?
            WHERE login = ?;
        """, (hashed_new_pw, login))
        conn.commit()
        if cursor.rowcount > 0:
            print(f"Пароль для користувача '{login}' успішно оновлено.")
        else:
            print(f"Не вдалося оновити пароль для користувача '{login}'. Користувач не знайдений.")
    except sqlite3.Error as e:
        print(f"Помилка при оновленні паролю: {e}")

def check_authentication(conn):
    # Перевірка автентифікацією користувача
    print("\n/// Перевірка автентифікації ///")
    login = input("Введіть логін: ")
    password_attempt = input("Введіть пароль: ")

    cursor = conn.cursor()
    try:
        cursor.execute("SELECT password FROM user_accounts WHERE login = ?", (login,))
        result = cursor.fetchone()

        if result:
            stored_hashed_password = result[0]
            # Хешується введений пароль для порівняння
            attempt_hashed_password = hash_password(password_attempt)

            if stored_hashed_password == attempt_hashed_password:
                print(f"Автентифікація для користувача '{login}' успішна!")
                return True
            else:
                print(f"Неправильний пароль для користувача '{login}'.")
                return False
        else:
            print(f"Користувача з логіном '{login}' не знайдено.")
            return False
    except sqlite3.Error as e:
        print(f"Помилка при перевірці автентифікації: {e}")
        return False

def main_menu(conn):
    while True:
        print("\nОберіть дію:")
        print("1. Додати нового користувача")
        print("2. Оновити пароль користувача")
        print("3. Перевірити автентифікацію користувача")
        print("4. Вийти")

        choice = input("Ваш вибір (1-4): ")

        if choice == '1':
            add_user(conn)
        elif choice == '2':
            update_user_password(conn)
        elif choice == '3':
            check_authentication(conn)
        elif choice == '4':
            print("Завершення роботи програми.")
            break
        else:
            print("Невірний вибір. Будь ласка, введіть число від 1 до 4.")

if __name__ == '__main__':
    db_connection = create_connection()

    if db_connection:
        create_table(db_connection) # Створюється таблиця, якщо її немає
        main_menu(db_connection)   # Показати головне меню
        db_connection.close()      # Закривається з'єднання з БД при виході
        print(f"З'єднання з SQLite DB [{DATABASE_NAME}] закрито.")
    else:
        print(f"Не вдалося підключитися до бази даних [{DATABASE_NAME}]. Програма не може продовжити роботу.")