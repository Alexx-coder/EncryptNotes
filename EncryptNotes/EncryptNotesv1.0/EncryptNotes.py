import sqlite3
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import datetime
import time
import sys
import getpass
import secrets
from cryptography.hazmat.primitives import hashes

class DataBaseNotes:
    def __init__(self):
        self.db_name = "EncryptNotes.db"

    def init_db(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        conn.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL, 
            fernet_key_encrypted TEXT NOT NULL,
            privacy_accepted BOOLEAN DEFAULT 0,
            accepted_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS notes(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content_encrypted TEXT NOT NULL,
            category TEXT DEFAULT 'Общее',
            tags TEXT DEFAULT '[]',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP,
            is_pinned INTEGER DEFAULT 0,
            is_archived INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)

        conn.commit()
        conn.close()

    def get_connection(self):
        return sqlite3.connect(self.db_name)


class CryptoNotes:
    @staticmethod
    def generate_salt():
        return secrets.token_bytes(16)
    
    @staticmethod
    def generate_fernet_key():
        return Fernet.generate_key().decode('utf-8')  # Возвращаем как строку
    
    @staticmethod
    def encrypt_fernet_key_with_password(fernet_key_str, password, salt):
        # Создаём ключ для шифрования ключа Fernet
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        encryption_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Шифруем ключ Fernet
        cipher = Fernet(encryption_key)
        fernet_key_bytes = fernet_key_str.encode('utf-8')
        encrypted_key = cipher.encrypt(fernet_key_bytes)
        
        return base64.b64encode(encrypted_key).decode('utf-8')
    
    @staticmethod
    def decrypt_fernet_key_with_password(encrypted_fernet_key_b64, password, salt):
        try:
            # Создаём тот же ключ для расшифровки
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000
            )
            encryption_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Расшифровываем ключ Fernet
            cipher = Fernet(encryption_key)
            encrypted_key = base64.b64decode(encrypted_fernet_key_b64)
            decrypted_key = cipher.decrypt(encrypted_key)
            
            return decrypted_key.decode('utf-8')
        except Exception:
            return None

    
    @staticmethod
    def hash_password(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )

        return base64.b64encode(kdf.derive(password.encode())).decode()
    
class  EncryptNotes:
    def __init__(self):
        self.name = "EncryptNotes"
        self.version = "v1.0"
        self.company = "With Open Crypto"
        self.current_user = None
        self.notes_cipher = None
        self.username = None
        self.crypto = CryptoNotes()
        self.db = DataBaseNotes()
        self.db.init_db()

    def registr(self):
        print("РЕГИСТРАЦИЯ")

        if not self.accept_policy():
            return False

        while True:
           username = input("Введите имя пользователю: ").strip()
           if not username:
                print("Имя не должно быть пустыми. Попробуйте снова!")
                continue

           conn = self.db.get_connection()
           cursor = conn.cursor()
           cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
           if cursor.fetchone():
               print("Имя занято. Попробуйте придумать другое имя!")
               conn.close()
               continue
           while True:
             password = getpass.getpass("Придумайте мастер-пароль: ").strip()
             if not password:
                print("Мастер-пароль не должен быть пустыми. Попробуйте снова!")
                continue
           
             if len(password) < 8:
               print("Пароль слишком маленький! Попробуйте снова.")
               continue
           
             confirm = getpass.getpass("Подтвердите мастер-пароль: ").strip()
           
             if password != confirm:
               print("Пароль не совпадают. Повторите попытку.")
               continue
           
             break

           break

        salt = self.crypto.generate_salt()
        password_hash = self.crypto.hash_password(password, salt)
        
        # 1. Генерируем ОТДЕЛЬНЫЙ ключ для заметок
        fernet_key_for_notes = self.crypto.generate_fernet_key()
        
        # 2. Шифруем этот ключ мастер-паролем
        encrypted_fernet_key = self.crypto.encrypt_fernet_key_with_password(
            fernet_key_for_notes, password, salt
        )


        try:
            cursor.execute("""
            INSERT INTO users (username, password_hash , salt, fernet_key_encrypted, privacy_accepted, accepted_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (username, password_hash, base64.b64encode(salt).decode(), encrypted_fernet_key, 1, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

            conn.commit()
            self.current_user = cursor.lastrowid
            self.username = username
            self.notes_cipher = Fernet(fernet_key_for_notes.encode())
            self.notes_decrypted = True 

            self.notes_cipher = Fernet(fernet_key_for_notes.encode())
            self.notes_decrypted = True 

            print(f"Успешная регистрация!\nДобро пожаловать {username}!")
            print(f"Ваш ключ для заметок: {fernet_key_for_notes}")
            print("ВАЖНОЕ УВЕДОМЛЕНИЕ: Запомните мастер-пароль. Потеряв его вы не сможете войти в аккаунт!")
            print("ВАЖНОЕ УВЕДОМЛЕНИЕ: Запомните свой Fernet-ключ. Забыв его вы потеряете доступ к расшифрованию заметок! Вы можете хранить в нашем продукте CryptoVault")
            print("ВАЖНОЕ УВЕДОМЛЕНИЕ: Ваше согласие с политикой конфидециальности сохранено в базе-данных!")
            
            print("Перехожу...")
            time.sleep(0.5)
            self.menu_show_func()

            return True
        
        except Exception as registr:
            print(f"Произошла ошибка: {registr}")
            return False
        except sqlite3.DatabaseError as sqlite:
            print(f"Произошла ошибка: {sqlite}")
            return False
        except sqlite3.ProgrammingError as sqliteP:
            print(f"Произошла ошибка: {sqliteP}")
            return False
        finally:
            conn.close()
    

    def login(self):
        print("ВХОД В АККАУНТ")

        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        conn.close()
    
        if user_count == 0:
          print("В системе нет зарегистрированных пользователей!")
          print("Сначала зарегистрируйтесь.")
          time.sleep(1.5)
          return False  

        while True:
            username = input("Введите имя пользователя: ").strip()
            if not username:
                print("Имя не должно быть пустыми. Попробуйте снова!")
                continue

            password = getpass.getpass("Введите мастер-пароль: ").strip()
            if not password:
                print("Мастер-пароль не должен быть пустыми. Попробуйте снова!")
                continue

            

            conn = self.db.get_connection()
            cursor = conn.cursor()

            try:
                cursor.execute("""
                SELECT id, password_hash, salt, fernet_key_encrypted FROM users WHERE username = ?
                """, (username,))

                user_data = cursor.fetchone()
                if not user_data:
                  print("Пользователь не найден!")
                  continue
                
                user_id, stored_hash, salt_b64, encrypted_fernet_key = user_data
                salt = base64.b64decode(salt_b64)


                password_hash = self.crypto.hash_password(password, salt)
                if password_hash != stored_hash:
                  print("Неверный пароль!")
                  conn.close()
                  continue

            
                fernet_key = self.crypto.decrypt_fernet_key_with_password(
                  encrypted_fernet_key, password, salt  
                )
                if not fernet_key:
                  print("Ошибка расшифровки ключа!")
                  conn.close()
                  continue

            
                self.current_user = user_id
                self.username = username
                self.notes_decrypted = False 
                self.notes_cipher = None 
                


                print(f"Успешный вход!\nДобро пожаловать {username}!")
                print("ВАЖНОЕ УВЕДОМЛЕНИЕ: Ваши заметки не расшифрованы. Чтобы расшифровать вам понадобиться ваш Fernet-ключ!")

                print("Перехожу...")
                time.sleep(0.5)
                self.menu_show_func()

                return True

            except Exception as login:
                print(f"Возникла ошибка: {login}")
                return False
            finally:
                conn.close()


    def enter_fernet_key(self):
        if not self.current_user:
          print("Сначала войдите в систему!")
          return False
    
        print("Ввод Fernet-ключа для расшифровки")

        fernet_key_str = getpass.getpass("Введите ключ Fernet для заметок: ").strip()

        try:
          self.notes_cipher = Fernet(fernet_key_str.encode())
          self.notes_decrypted = True

          print("Fernet-ключ принят! Вам доступно расшифрование ваших заметок")
        
        
          test_message = b"test"
          encrypted_test = self.notes_cipher.encrypt(test_message)
          decrypted_test = self.notes_cipher.decrypt(encrypted_test)
        
          if decrypted_test == test_message:
            print("Ключ работает корректно!")
          else:
            print("Проблема с ключом!")
            self.notes_cipher = None
            self.notes_decrypted = False
            return False

          print("Перехожу...")
          time.sleep(0.5)
          self.menu_show_func()

          return True
    
        except Exception as efk:
          print(f"Неправильный ключ! Ошибка: {efk}")
          print("Формат ключа должен быть: 44 символа, base64-encoded")
          print("Пример: abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH")
          return False
        

    def create_note(self):
        if not self.current_user:
            print("Сначала войдите в систему!")
            return False
        

        if not self.notes_decrypted:
            print("Сначала введите Fernet-ключ для расшифровки!")
            return False
        
        print("Создание заметок")

        title = input("Введите заголовок заметки: ").strip()
        content = input("Введите текст заметки: ").strip()

        encrypted_content = self.notes_cipher.encrypt(content.encode()).decode()

        conn = self.db.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
            INSERT INTO notes(user_id, title, content_encrypted)
            VALUES (?, ?, ?)
            """, (self.current_user, title, encrypted_content))

            conn.commit()
            print(f"Заметка с именем {title} успешна сохранена!")

        except Exception as cn:
            print(f"Возникла ошибка: {cn}")
        finally:
            conn.close()

    def watch_note(self):
        if not self.current_user:
            print("Сначала войдите в систему!")
            return False
        
        conn = self.db.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
            SELECT id, title, content_encrypted, created_at
            FROM notes
            WHERE user_id = ?
            ORDER By created_at DESC
            """, (self.current_user,))

            notes = cursor.fetchall()

            if not notes:
                print("У вас нет заметок. Чтобы просматривать заметки, сначала создайте их!")
                return
            
            print("Ваши заметки: ")

            for note_id, title, content_encrypted, created_at in notes:
                print(f"\nID: {note_id}")
                print(f"Заголовок: {title}")
                print(f"Дата создания: {created_at}")

                if self.notes_decrypted:
                    try:
                        decrypted_content = self.notes_cipher.decrypt(content_encrypted.encode()).decode()
                        print(f"\nСодержимое: {decrypted_content}")
                        print("Правильный Fernet-ключ: Содержимое расшифровано успешно!")
                    except Exception as wn:
                        print(f"\nСодержимое: {content_encrypted}")
                        print("Неправильный Fernet-ключ: Содержимое показано зашифровано")
                else:
                    if len(content_encrypted) > 50:
                      print(f"Содержимое: {content_encrypted[:50]}...")
                    else:
                        print(f"Содержимое: {content_encrypted}")


            if not self.notes_decrypted:
                print("\nДля расшифровки заметок надо: иметь Fernet-ключ")
                print("Если ваш Fernet-ключ потерян: Вы не сможете расшифровать заметки")

        except Exception as wn:
            print(f"Возникла ошибка: {wn}")
        finally:
            conn.close()



    def accept_policy(self):
        print("Политика конфидециальности")
        while True:
            print("""
1. Данные шифруются на вашем устройстве
2. Мы не имеем доступа к вашим заметкам
3. Вы отвечаете за сохранность Fernet-ключа
4. Вы отвечаете за сохранность базы-данных ваших заметок
5. Согласие требуется один раз при регистрации
            """)

            accept_the_policy = input("Принимайте политику конфидециальности? (Да/Нет): ").strip().lower()
            if accept_the_policy == "да":
                print("Вы приняли политику конфидециальности...")
                return True
            elif accept_the_policy == "нет":
                print("Вы не приняли политику конфедициальности...")
                time.sleep(2)
                sys.exit(0)
            else:
                print("Ваш ответ не понятен. Попробуйте снова!")
                continue


    def menu(self):
        print("Добро пожаловать в EncryptNotes!")
        print("Данная программа осуществляет безопасное хранение зашифрованных заметок с базой данных!")

        while True:
            print("\n1 - ВХОД В АККАУНТ")
            print("2 - РЕГИСТРАЦИЯ")
            print("3 - ВЫХОД")

            choice = input("Введите (1-3): ").strip()
            if choice == "1":
                print("Перехожу...")
                time.sleep(0.5)
                if self.login():
                   continue  
                else:
                   continue
            elif choice == "2":
                print("Перехожу...")
                time.sleep(0.5)
                self.registr()
            elif choice == "3":
                print("Выхожу...")
                time.sleep(0.5)
                sys.exit(0)
            else:
                print("Ответ не понятен. Введите (1-3) снова.")
                time.sleep(0.5)
                continue

    def menu_show_func(self):
        while True:
            print("1 - Создать заметки")
            print("2 - Посмотреть заметки")
            print("3 - Ввести Fernet-ключ для расшифровки")
            print("4 - Выход в главное меню")
            print("5 - Быстрый выход")

            choice = input("Введите (1-4): ").strip()
            if choice == "1":
              print("Перехожу...")
              time.sleep(0.5)
              self.create_note()
            
            elif choice == "2":
              print("Перехожу...")
              time.sleep(0.5)
              self.watch_note()
            
            elif choice == "3":  
              print("Перехожу...")
              time.sleep(0.5)
              self.enter_fernet_key()
            
            
            elif choice == "4":
              print("Возвращаюсь в главное меню...")
              time.sleep(0.5)
              self.menu()
            
            elif choice == "5":
              print("Выхожу...")
              time.sleep(0.5)
              sys.exit(0)
            
            else:
              print("Ответ не понятен. Попробуйте снова!")
                
if __name__ == "__main__":
    try:
        app = EncryptNotes()
        app.menu()

    except Exception as EN:
        print(f"Возникла ошибка: {EN}")
        import traceback
        traceback.print_exc()
    except KeyboardInterrupt:
        print("Программа приостановлена пользователем")
    finally:
        print("EncryptNotes завершает работу! До свидания!")








        



    

