from wsgi import app
from models import db
from models import InternetSource

def seed_source():
    with app.app_context():
        # Verifica se já existe uma fonte CSV
        source = InternetSource.query.filter_by(provider='csv').first()
        if not source:
            print("Criando fonte de dados CSV padrão...")
            new_source = InternetSource(
                name="Log de Teste Local",
                source_type="log_file",
                provider="csv",
                is_active=True
            )
            db.session.add(new_source)
            db.session.commit()
            print("Fonte CSV criada com sucesso.")
        else:
            print("Fonte CSV já existe.")

if __name__ == "__main__":
    seed_source()
