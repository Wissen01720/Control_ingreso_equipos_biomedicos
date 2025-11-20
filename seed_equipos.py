# seed_equipos.py
import os
from datetime import datetime, timedelta

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from models import Base, EmpresaExterna, ResponsableEntrega, Equipo, User

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

def run():
    Base.metadata.create_all(engine)
    db = SessionLocal()
    try:
        # Tomamos un usuario "usuario" para usar como autorizado_por
        autorizador = (
            db.query(User)
              .filter(User.role == "usuario")
              .order_by(User.id.asc())
              .first()
        )
        if not autorizador:
            print("[ERROR] No hay usuarios con rol 'usuario'. Crea uno antes de sembrar equipos.")
            return

        print(f"Usando user.id={autorizador.id} ({autorizador.username}) como 'autorizado_por'")

        # Helpers para buscar empresa/responsable por identificadores “humanos”
        def empresa_por_nit(nit: str):
            return (
                db.query(EmpresaExterna)
                  .filter(EmpresaExterna.identificacion == nit)
                  .first()
            )

        def responsable_por_id(id_resp: str):
            return (
                db.query(ResponsableEntrega)
                  .filter(ResponsableEntrega.id_responsable == id_resp)
                  .first()
            )

        now = datetime.now()

        SEED_EQUIPOS = [
            # pendiente: sin fecha_salida
            {
                "codigo_interno": "EQ-0001",
                "tipo_equipo": "tecnologico",
                "marca": "Dell",
                "modelo": "Latitude 5420",
                "serial": "SN-DLL-001",
                "empresa_nit": "900111222-1",
                "responsable_doc": "CC1001",
                "fecha_ingreso": now - timedelta(days=2),
                "fecha_salida": None,
                "estado": "pendiente",
                "observaciones": "Equipo en cola para revisión inicial.",
            },
            # en revisión: sin fecha_salida
            {
                "codigo_interno": "EQ-0002",
                "tipo_equipo": "biomedico",
                "marca": "Philips",
                "modelo": "MX450",
                "serial": "SN-PHP-002",
                "empresa_nit": "900111222-1",
                "responsable_doc": "CC1002",
                "fecha_ingreso": now - timedelta(days=1),
                "fecha_salida": None,
                "estado": "en_revision",
                "observaciones": "Monitor en pruebas de calibración.",
            },
            # aprobado: fecha_salida opcional pero coherente
            {
                "codigo_interno": "EQ-0003",
                "tipo_equipo": "tecnologico",
                "marca": "HP",
                "modelo": "ProBook 440",
                "serial": "SN-HP-003",
                "empresa_nit": "800333444-2",
                "responsable_doc": "CC2001",
                "fecha_ingreso": now - timedelta(days=5),
                "fecha_salida": now + timedelta(days=5),
                "estado": "aprobado",
                "observaciones": "Equipo aprobado para uso en sala de conferencias.",
            },
            # devuelto: requiere fecha_salida >= ingreso
            {
                "codigo_interno": "EQ-0004",
                "tipo_equipo": "biomedico",
                "marca": "Siemens",
                "modelo": "Acuson",
                "serial": "SN-SIE-004",
                "empresa_nit": "901555666-3",
                "responsable_doc": "CC3001",
                "fecha_ingreso": now - timedelta(days=10),
                "fecha_salida": now - timedelta(days=1),
                "estado": "devuelto",
                "observaciones": "Equipo devuelto al proveedor tras finalizar contrato.",
            },
        ]

        for item in SEED_EQUIPOS:
            # saltar si ya existe código interno
            exists = (
                db.query(Equipo)
                  .filter(Equipo.codigo_interno == item["codigo_interno"])
                  .first()
            )
            if exists:
                print(f"[SKIP] Ya existe equipo {item['codigo_interno']}")
                continue

            emp = empresa_por_nit(item["empresa_nit"])
            if not emp:
                print(f"[WARN] No existe empresa {item['empresa_nit']} para equipo {item['codigo_interno']}, saltando.")
                continue

            resp = responsable_por_id(item["responsable_doc"])
            if not resp:
                print(f"[WARN] No existe responsable {item['responsable_doc']} para equipo {item['codigo_interno']}, saltando.")
                continue

            # Validaciones básicas manuales coherentes con el CheckConstraint
            fi = item["fecha_ingreso"]
            fs = item["fecha_salida"]
            estado = item["estado"]

            if estado in ("pendiente", "en_revision") and fs is not None:
                print(f"[WARN] {item['codigo_interno']}: estado {estado} no debe tener fecha_salida. Ajustando a None.")
                fs = None

            if estado == "devuelto":
                if fs is None or fs < fi:
                    print(f"[WARN] {item['codigo_interno']}: ajustando fecha_salida para cumplir constraint (devuelto).")
                    fs = fi + timedelta(days=1)

            if estado == "aprobado" and fs is not None and fs < fi:
                print(f"[WARN] {item['codigo_interno']}: ajustando fecha_salida para aprobado.")
                fs = fi + timedelta(days=1)

            eq = Equipo(
                codigo_interno=item["codigo_interno"],
                tipo_equipo=item["tipo_equipo"],
                marca=item["marca"],
                modelo=item["modelo"],
                serial=item["serial"],
                empresa_id=emp.id,
                responsable_id=resp.id,
                fecha_ingreso=fi,
                fecha_salida=fs,
                estado=estado,
                observaciones=item["observaciones"],
                autorizado_por=autorizador.id,
            )

            db.add(eq)
            try:
                db.commit()
                print(f"[OK] Equipo creado: {eq.codigo_interno}")
            except IntegrityError as ie:
                db.rollback()
                print(f"[ERR] No se pudo crear equipo {item['codigo_interno']}: {ie}")

    finally:
        db.close()

if __name__ == "__main__":
    run()
