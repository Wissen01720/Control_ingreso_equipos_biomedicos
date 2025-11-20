# seed_resp_ent_empresa.py
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from models import Base, EmpresaExterna, ResponsableEntrega

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("Falta DATABASE_URL en .env")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"sslmode": "require"},
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# id_empresa_nit → lista de responsables
RESP_SEED = {
    "900111222-1": [
        {
            "id_responsable": "CC1001",
            "nombre_responsable": "Carlos Gómez",
            "correo_responsable": "carlos.gomez@biomedtech.com",
        },
        {
            "id_responsable": "CC1002",
            "nombre_responsable": "Laura Pérez",
            "correo_responsable": "laura.perez@biomedtech.com",
        },
    ],
    "800333444-2": [
        {
            "id_responsable": "CC2001",
            "nombre_responsable": "Andrés Torres",
            "correo_responsable": "andres.torres@electroservicios.com",
        }
    ],
    "901555666-3": [
        {
            "id_responsable": "CC3001",
            "nombre_responsable": "Marta Ruiz",
            "correo_responsable": "marta.ruiz@hospitalexterno.org",
        }
    ],
}

def run():
    Base.metadata.create_all(engine)

    db = SessionLocal()
    try:
        for nit, responsables in RESP_SEED.items():
            empresa = (
                db.query(EmpresaExterna)
                  .filter(EmpresaExterna.identificacion == nit)
                  .first()
            )
            if not empresa:
                print(f"[WARN] No existe empresa con NIT {nit}, omitiendo sus responsables.")
                continue

            for r in responsables:
                id_resp = r["id_responsable"]

                exists = (
                    db.query(ResponsableEntrega)
                      .filter(ResponsableEntrega.id_responsable == id_resp)
                      .first()
                )
                if exists:
                    print(f"[SKIP] Responsable ya existe: {id_resp}")
                    continue

                resp = ResponsableEntrega(
                    id_responsable=id_resp,
                    nombre_responsable=r["nombre_responsable"],
                    correo_responsable=r["correo_responsable"],
                    empresa_id=empresa.id,
                )
                db.add(resp)
                try:
                    db.commit()
                    print(f"[OK] Responsable creado: {id_resp} ({resp.nombre_responsable}) en {empresa.nombre}")
                except IntegrityError as ie:
                    db.rollback()
                    print(f"[ERR] No se pudo crear responsable {id_resp}: {ie}")
    finally:
        db.close()

if __name__ == "__main__":
    run()
