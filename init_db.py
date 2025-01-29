from app import app, db, User, SiteSettings
from datetime import datetime
import random
import string


def create_founder_accounts():
    """İlk founder hesabını oluştur"""
    try:
        founder = User.query.filter_by(username='admin').first()
        
        if not founder:
            founder = User(
                username='admin',
                email='admin@system.com',
                is_founder=True,
                is_admin=True,
                _is_banned=False,
                date_joined=datetime.utcnow(),
                profile_image='default.jpg'
            )
            sifre = create_password(10, use_digits=True, use_special=True)
            founder.set_password(sifre)
            db.session.add(founder)
            print("Founder hesabı oluşturuldu")
            myint = random.randint(1, 3131)
            with open(f"admin_password{myint}", "w", encoding="utf-8") as dosya:
                dosya.write(sifre)
            print(f"Founder hesabı şifresi admin_password{myint} dosyasına yazıldı.")

    except Exception as e:
        print(f"Founder hesabı oluşturulurken hata: {str(e)}")
        db.session.rollback()
        raise e

def init_db():
    """Veritabanını başlat ve gerekli tabloları oluştur"""
    try:
        with app.app_context():
            # Tüm tabloları oluştur
            db.create_all()
            print("Veritabanı tabloları oluşturuldu")
            
            # Founder hesabını oluştur
            create_founder_accounts()
            
            # Site ayarlarını oluştur
            if not SiteSettings.query.first():
                settings = SiteSettings()
                db.session.add(settings)
                db.session.commit()
                print("Site ayarları oluşturuldu")
            
            db.session.commit()
            print("Veritabanı başarıyla başlatıldı.")
            
    except Exception as e:
        print(f"Veritabanı başlatılırken hata: {str(e)}")
        raise e

def create_password(length=12, use_digits=True, use_special=True):
    characters = string.ascii_letters  # Harfler (büyük + küçük)
    
    if use_digits:
        characters += string.digits  # Rakamlar ekle
    
    if use_special:
        characters += string.punctuation  # Özel karakterler ekle
    
    if not characters:
        raise ValueError("En az bir karakter türü seçmelisiniz!")
    
    return ''.join(random.choice(characters) for _ in range(length))

if __name__ == '__main__':
    input("Çalıştırmadan önce, veritabanının olmadığından emin olun. Ve site çalışır duurmda olmamalıdır. Aksi takdirde çalışmayabilir! Devam etmek için Enter'a basın...")
    init_db()
    input("Çıkış için enter'a basın...")