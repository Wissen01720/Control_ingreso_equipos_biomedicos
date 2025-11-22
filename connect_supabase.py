from dotenv import load_dotenv
import os
import psycopg

load_dotenv()

# ⚠️ SEGURIDAD: Nunca incluir credenciales hardcodeadas
dsn = os.getenv("PSYCOPG_DSN")
if not dsn:
    raise RuntimeError(
        "❌ PSYCOPG_DSN no configurado en .env\n"
        "Define la variable de entorno PSYCOPG_DSN con tu cadena de conexión."
    )

try:
    with psycopg.connect(dsn, sslmode="require") as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT current_database(), current_user, NOW();")
            print("✅ Conectado:", cur.fetchone())
    print("🔒 Conexión cerrada correctamente.")
except Exception as e:
    print("❌ Error:", e)
