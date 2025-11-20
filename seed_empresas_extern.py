# seed_empresas_extern.py
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from models import Base, EmpresaExterna

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("Falta DATABASE_URL en .env")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"sslmode": "require"},  # igual que en app.py
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

EMPRESAS_SEED = [
    {"identificacion": "900111222-1", "nombre": "BioMedTech S.A.S."},
    {"identificacion": "800333444-2", "nombre": "ElectroServicios LTDA"},
    {"identificacion": "901555666-3", "nombre": "Hospital Soporte Externo"},
]

def run():
    Base.metadata.create_all(engine)

    db = SessionLocal()
    try:
        for e in EMPRESAS_SEED:
            ident = e["identificacion"]
            nombre = e["nombre"]

            exists = (
                db.query(EmpresaExterna)
                  .filter(EmpresaExterna.identificacion == ident)
                  .first()
            )
            if exists:
                print(f"[SKIP] Empresa ya existe: {ident} - {nombre}")
                continue

            emp = EmpresaExterna(
                identificacion=ident,
                nombre=nombre,
            )
            db.add(emp)
            try:
                db.commit()
                print(f"[OK] Empresa creada: {ident} - {nombre}")
            except IntegrityError:
                db.rollback()
                print(f"[ERR] No se pudo crear empresa: {ident} - {nombre}")
    finally:
        db.close()

if __name__ == "__main__":
    run()
