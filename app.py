# --- Standard library para Python ---
import os
import json
import io
import csv
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Dict
from openpyxl import Workbook


# --- Third-party packages para Flask ---
from dotenv import load_dotenv
from flask import Flask, render_template, flash, redirect, url_for, session, request, jsonify, Response, send_file
from flask_wtf import CSRFProtect
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from markupsafe import Markup, escape
from werkzeug.exceptions import NotFound

from sqlalchemy import create_engine, select, or_, cast, String, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker, scoped_session, joinedload, aliased


# --- Local modules  para la aplicación ---
import models  
from models import Base, User, UserAudit, Equipo, EquipoAudit, EmpresaExterna, ResponsableEntrega
from forms import LoginForm, UserCreateForm, UserEditForm, UserSelfEditForm, EquipoForm, EmpresaExternaForm,ResponsableEntregaForm
from models import Notification

from xhtml2pdf import pisa



# ===  constantes de throttling y helper === thorttle significa aceleración controlada de un proceso
MAX_FAILS = 2                # Intentos permitidos antes de bloquear
FAIL_WINDOW_SECONDS = 60     # Ventana para contar fallos (1 minuto)
LOCK_SECONDS = 60            # Bloqueo 1 minuto

def normalize_username(u: str) -> str:
    return (u or "").strip().lower()
# ===============================================


load_dotenv()

app = Flask(__name__)
# Configuración base
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY", "dev_secret_change_me"),
    WTF_CSRF_SECRET_KEY=os.getenv("WTF_CSRF_SECRET_KEY", "dev_csrf_change_me"),
    RECAPTCHA_PUBLIC_KEY=os.getenv("RECAPTCHA_SITE_KEY"),
    RECAPTCHA_PRIVATE_KEY=os.getenv("RECAPTCHA_SECRET_KEY"),
    RECAPTCHA_PARAMETERS={"hl": "es"},
    # Cookies (ajustar SECURE=True solo si sirves por HTTPS)
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False  # cambiar a True en producción CI/CD con HTTPS
)

csrf = CSRFProtect(app)

# ---------- SQLAlchemy postgresql----------
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "Falta DATABASE_URL en .env (ej: postgresql+psycopg://usuario:pass@host:5432/dbname)"
    )

# Supabase exige SSL
engine = create_engine( # crear motor con SSL, es decir, cifrado en la conexión. SSL es Secure Sockets Layer
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"sslmode": "require"},
)

SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))
Base.metadata.create_all(engine)




# ---------- Flask-Login ----------
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Inicia sesión para continuar."
login_manager.login_message_category = "warning"

@login_manager.user_loader # carga el usuario a partir del ID almacenado en la sesión
def load_user(user_id):
    db = SessionLocal()
    try:
        return db.get(User, int(user_id))
    finally:
        db.close()

@login_manager.unauthorized_handler # qué hacer si el usuario no está autenticado
def unauthorized():
    flash("Inicia sesión para continuar.", "warning")
    return redirect(url_for("login", next=request.path))

@app.teardown_appcontext # cerrar sesión de BD al terminar request
def remove_session(exception=None):
    SessionLocal.remove()


def _equipo_snapshot(e):
    return {
        "codigo_interno": e.codigo_interno,
        "tipo_equipo": e.tipo_equipo,
        "marca": e.marca,
        "modelo": e.modelo,
        "serial": e.serial,
        #  snapshot con IDs 
        "empresa_id": e.empresa_id,
        "empresa_nombre": e.empresa.nombre if getattr(e, "empresa", None) else None,
        "responsable_id": e.responsable_id,
        "responsable_nombre": e.responsable.nombre_responsable if getattr(e, "responsable", None) else None,
        "fecha_ingreso": e.fecha_ingreso.isoformat() if e.fecha_ingreso else None,
        "fecha_salida": e.fecha_salida.isoformat() if e.fecha_salida else None,
        "estado": e.estado,
        "autorizado_por": e.autorizado_por,
        "observaciones": e.observaciones,
    }



def log_equipo_audit(db, *, equipo_id: int, action: str, detail: dict | None = None, actor_user_id: int | None = None): # registra auditoría de equipos
    entry = EquipoAudit(
        equipo_id=equipo_id,
        actor_user_id=actor_user_id,
        action=action,
        detail=json.dumps(detail, ensure_ascii=False) if detail else None,
        ip=_client_ip(request),
        user_agent=_ua(request),
    )
    db.add(entry)
    db.commit()
    return entry


@app.template_filter("to_colombia") # filtro Jinja2 para convertir fechas a hora Colombia
def to_colombia(value):
    """Convierte UTC → hora Colombia (UTC-5)"""
    if not value:
        return "—"
    try:
        # Si viene naive (sin tzinfo), lo tratamos como UTC
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        # Convertimos a UTC-5
        colombia_tz = timezone(timedelta(hours=-5))
        local_value = value.astimezone(colombia_tz)
        return local_value.strftime("%d/%m/%Y %H:%M")
    except Exception:
        return str(value)


# ---------- Rutas ----------
@app.route("/")
def index():
    # Landing informativa
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    # Si ya está autenticado, respeta ?next= o lleva a dashboard
    if current_user.is_authenticated:
        dest = request.args.get("next") or url_for("dashboard")
        return redirect(dest)

    form = LoginForm()
    if form.validate_on_submit():
        now = datetime.utcnow()
        input_username = normalize_username(form.username.data)
        db = SessionLocal()
        try:
            # --- 1) Verificar si está bloqueado ---
            from models import AuthThrottle, User  # evita imports circulares en runtime
            throttle = db.query(AuthThrottle).filter(AuthThrottle.username == input_username).first()
            if throttle and throttle.locked_until and now < throttle.locked_until:
                remaining = int((throttle.locked_until - now).total_seconds())
                flash(f"Usuario bloqueado. Inténtalo en {remaining} s.", "danger")
                #  aquí mandamos lock_remaining al template para el banner + countdown
                return render_template("login.html", form=form, lock_remaining=remaining)

            # --- 2) Intentar autenticar ---
            user = db.query(User).filter(User.username == input_username).first()
            is_valid = bool(user and user.check_password(form.password.data))

            if is_valid:
                # éxito → reset de throttle y login
                if throttle:
                    throttle.fail_count = 0
                    throttle.first_fail_at = None
                    throttle.locked_until = None
                    db.add(throttle)
                    db.commit()

                login_user(user)
                flash("¡Bienvenido!", "success")
                next_url = request.args.get("next")
                return redirect(next_url or url_for("dashboard"))

            # --- 3) Fallo: actualizar contadores/lock sin filtrar info ---
            if not throttle:
                throttle = AuthThrottle(
                    username=input_username,
                    fail_count=1,
                    first_fail_at=now,
                    locked_until=None
                )
                db.add(throttle)
                db.commit()
            else:
                # Si ventana venció, reinicia contador
                if not throttle.first_fail_at or (now - throttle.first_fail_at).total_seconds() > FAIL_WINDOW_SECONDS:
                    throttle.fail_count = 1
                    throttle.first_fail_at = now
                    throttle.locked_until = None
                else:
                    throttle.fail_count += 1
                    # ¿se alcanza umbral?
                    if throttle.fail_count >= MAX_FAILS:
                        throttle.fail_count = 0
                        throttle.first_fail_at = None
                        throttle.locked_until = now + timedelta(seconds=LOCK_SECONDS)

                db.add(throttle)
                db.commit()

            # Mensaje genérico (sin filtrar si el usuario existe o no)
            flash("Usuario o contraseña inválidos.", "danger")

        finally:
            db.close()

    elif form.is_submitted():
        for field, errors in form.errors.items():
            for err in errors:
                flash(f"{getattr(form, field).label.text}: {err}", "danger")
        flash("Revisa el formulario.", "warning")

    # Render normal (sin bloqueo)
    return render_template("login.html", form=form)



@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("login"))

# Páginas protegidas
@app.route("/dashboard")
@login_required
def dashboard():
    db = SessionLocal()
    try:
        # Datos básicos del usuario para el saludo
        data = {
            "nombre": current_user.username,
            "correo": current_user.email,
        }

        # --- Métricas de equipos ---

        # Total de equipos registrados
        total_equipos = db.query(func.count(Equipo.id)).scalar() or 0

        # Conteo por estado
        rows = (
            db.query(Equipo.estado, func.count(Equipo.id))
              .group_by(Equipo.estado)
              .all()
        )

        # Inicializamos todos los estados en 0
        por_estado = {
            "pendiente": 0,
            "en_revision": 0,
            "aprobado": 0,
            "devuelto": 0,
        }

        for est, cnt in rows:
            if est in por_estado:
                por_estado[est] = cnt or 0

        metrics = {
            "total": total_equipos,
            "por_estado": por_estado,
        }

        return render_template("dashboard.html", data=data, metrics=metrics)
    finally:
        db.close()


@app.route("/perfil")
@login_required
def perfil():
    data = {"nombre": current_user.username, "correo": current_user.email}
    return render_template("perfil.html", data=data)

@app.route("/reportes")
@login_required
def reportes():
    db = SessionLocal()
    try:
        data = {"nombre": current_user.username, "correo": current_user.email}

        # --------- 0) Leer enums desde el modelo (para validar y para el FE) ---------
        tipo_enum = Equipo.__table__.c.tipo_equipo.type
        estado_enum = Equipo.__table__.c.estado.type

        tipo_equipo_choices = list(getattr(tipo_enum, "enums", [])) or ["tecnologico", "biomedico"]
        estado_choices = list(getattr(estado_enum, "enums", [])) or ["pendiente", "en_revision", "aprobado", "devuelto"]

        # --------- 1) Leer filtros desde querystring ---------
        fecha_desde_str = (request.args.get("fecha_desde") or "").strip()
        fecha_hasta_str = (request.args.get("fecha_hasta") or "").strip()
        estado_raw      = (request.args.get("estado") or "").strip()
        tipo_raw        = (request.args.get("tipo_equipo") or "").strip()
        empresa_id_str  = (request.args.get("empresa_id") or "").strip()
        fmt             = (request.args.get("format") or "").lower()

        # --- Parseo de fechas (como date) ---
        fecha_desde = None
        fecha_hasta = None

        if fecha_desde_str:
            try:
                fecha_desde = datetime.strptime(fecha_desde_str, "%Y-%m-%d").date()
            except ValueError:
                fecha_desde = None

        if fecha_hasta_str:
            try:
                fecha_hasta = datetime.strptime(fecha_hasta_str, "%Y-%m-%d").date()
            except ValueError:
                fecha_hasta = None

        # Si las dos existen y el rango es inválido, lo ignoramos y avisamos
        if fecha_desde and fecha_hasta and fecha_desde > fecha_hasta:
            flash("El rango de fechas es inválido: 'Desde' no puede ser mayor que 'Hasta'.", "warning")
            fecha_desde = None
            fecha_hasta = None
            fecha_desde_str = ""
            fecha_hasta_str = ""

        # --- Empresa ID ---
        empresa_id = None
        if empresa_id_str:
            try:
                empresa_id = int(empresa_id_str)
            except ValueError:
                empresa_id = None
                empresa_id_str = ""

        # --- Sanitizar enums: solo aceptamos valores válidos ---
        estado = estado_raw if estado_raw in estado_choices else ""
        tipo_equipo = tipo_raw if tipo_raw in tipo_equipo_choices else ""

        # --------- Filtros que usaremos tanto para pantalla como para PDF ---------
        filtros = {
            "fecha_desde": fecha_desde_str,
            "fecha_hasta": fecha_hasta_str,
            "estado": estado,
            "tipo_equipo": tipo_equipo,
            "empresa_id": empresa_id_str,
        }

        # --------- 2) Query base de equipos (con filtros) ---------
        base_q = (
            db.query(Equipo)
              .join(EmpresaExterna)
        )

        # Para filtrar DateTime con date: usamos límites de día
        if fecha_desde:
            dt_desde = datetime.combine(fecha_desde, datetime.min.time())
            base_q = base_q.filter(Equipo.fecha_ingreso >= dt_desde)
        if fecha_hasta:
            dt_hasta = datetime.combine(fecha_hasta, datetime.max.time())
            base_q = base_q.filter(Equipo.fecha_ingreso <= dt_hasta)

        if estado:
            base_q = base_q.filter(Equipo.estado == estado)
        if tipo_equipo:
            base_q = base_q.filter(Equipo.tipo_equipo == tipo_equipo)
        if empresa_id:
            base_q = base_q.filter(Equipo.empresa_id == empresa_id)

        # --------- 3) Si se pidió exportar, usar estos filtros ---------
        if fmt in ("csv", "xlsx", "pdf"):
            equipos_export = (
                base_q
                .options(
                    joinedload(Equipo.empresa),
                    joinedload(Equipo.responsable),
                )
                .order_by(Equipo.fecha_ingreso.desc().nullslast())
                .all()
            )

            if fmt == "csv":
                return _export_equipos_csv(equipos_export)
            elif fmt == "xlsx":
                return _export_equipos_xlsx(equipos_export)
            elif fmt == "pdf":
                return _export_equipos_pdf(equipos_export, filtros)

        # --------- 4) Estadísticas para los gráficos ---------
        por_estado = {k: 0 for k in estado_choices}

        rows_estado = (
            base_q
            .with_entities(Equipo.estado, func.count(Equipo.id))
            .group_by(Equipo.estado)
            .all()
        )
        for est, total in rows_estado:
            if est in por_estado:
                por_estado[est] = total
            else:
                por_estado[est] = por_estado.get(est, 0) + total

        # 4.2) Equipos por empresa (top 10)
        rows_empresas = (
            base_q
            .with_entities(EmpresaExterna.nombre, func.count(Equipo.id))
            .group_by(EmpresaExterna.id, EmpresaExterna.nombre)
            .order_by(func.count(Equipo.id).desc())
            .limit(10)
            .all()
        )
        por_empresa = [
            {"nombre": nombre, "total": total}
            for nombre, total in rows_empresas
        ]

        stats = {
            "por_estado": por_estado,
            "por_empresa": por_empresa,
        }

        # --------- 5) Empresas para el <select> de filtros ---------
        empresas = (
            db.query(EmpresaExterna)
              .order_by(EmpresaExterna.nombre.asc())
              .all()
        )

        # --------- 6) Render del template HTML normal ---------
        return render_template(
            "reportes.html",
            data=data,
            empresas=empresas,
            stats=stats,
            filtros=filtros,
            tipo_equipo_choices=tipo_equipo_choices,
            estado_choices=estado_choices,
        )
    finally:
        db.close()




# --- Ruta: solo admin ---
def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if getattr(current_user, "role", None) != "admin":
            flash("No tienes permisos para esta sección.", "danger")
            return redirect(url_for("dashboard"))
        return view_func(*args, **kwargs)
    return wrapper

# ------------------ Gestión de usuarios (CRUD) ------------------

@app.route("/usuarios")
@login_required
@admin_required
def users_index():
    q = (request.args.get("q") or "").strip()
    db = SessionLocal()
    try:
        query = db.query(User)
        if q:
            like = f"%{q.lower()}%"
            query = query.filter(or_(
                User.username.ilike(like),
                User.email.ilike(like),
                User.identificacion.ilike(like)   
            ))
        users = query.order_by(User.id.desc()).all()
        return render_template("users_index.html", users=users, q=q)
    finally:
        db.close()


@app.route("/usuarios/crear", methods=["GET", "POST"])
@login_required
@admin_required
def users_create():
    form = UserCreateForm()
    if form.validate_on_submit():
        db = SessionLocal()
        try:
            ident = (form.identificacion.data or "").strip()
            username = (form.username.data or "").strip().lower()
            email = (form.email.data or "").strip().lower()

            exists = db.query(User).filter(
                or_(
                    User.username == username,
                    User.email == email,
                    User.identificacion == ident
                )
            ).first()
            if exists:
                flash("Ya existe un usuario con ese username, correo o identificación.", "danger")
                return render_template("users_form.html", form=form, is_edit=False)

            u = User(
                identificacion=ident,
                username=username,
                email=email,
                role=form.role.data
            )
            u.set_password(form.password.data)
            db.add(u)
            db.commit()

            # Auditoría
            log_audit(
                db,
                user_id=u.id,
                action="admin_user_create",
                detail={
                    "created": {
                        "identificacion": u.identificacion,
                        "username": u.username,
                        "email": u.email,
                        "role": u.role
                    }
                },
                actor_user_id=current_user.id
            )
            # Notificar al propio usuario
            notify_user(
                db,
                user_id=u.id,
                title="Tu cuenta fue creada",
                body=f"Bienvenido {u.username}.",
                level="success",
            )
            flash("Usuario creado correctamente.", "success")
            return redirect(url_for("users_index"))
        finally:
            db.close()
    elif form.is_submitted():
        flash("Revisa el formulario.", "warning")

    return render_template("users_form.html", form=form, is_edit=False)


@app.route("/usuarios/<int:user_id>/editar", methods=["GET", "POST"])
@login_required
@admin_required
def users_edit(user_id: int):
    db = SessionLocal()
    try:
        u = db.get(User, user_id)
        if not u:
            raise NotFound()

        form = UserEditForm(obj=u)
        if form.validate_on_submit():
            # No permitir que un admin se cambie su propio rol
            is_self_admin = (current_user.id == u.id and u.role == "admin")
            if is_self_admin and form.role.data != u.role:
                flash("No puedes cambiar tu propio rol de administrador.", "warning")
                # Forzamos a que el select muestre de nuevo el rol actual
                form.role.data = u.role
                return render_template("users_form.html", form=form, is_edit=True, user=u)
            new_ident = (form.identificacion.data or "").strip()
            new_username = (form.username.data or "").strip().lower()
            new_email = (form.email.data or "").strip().lower()

            # Chequear colisiones...
            clash = db.query(User).filter(
                or_(
                    User.username == new_username,
                    User.email == new_email,
                    User.identificacion == new_ident
                )
            ).filter(User.id != u.id).first()
            if clash:
                flash("Otro usuario ya tiene ese username, correo o identificación.", "danger")
                return render_template("users_form.html", form=form, is_edit=True, user=u)

            # === DIFF para auditoría ===
            old_ident = u.identificacion
            old_username = u.username
            old_email    = u.email
            old_role     = u.role

            u.identificacion = new_ident
            u.username = new_username
            u.email = new_email
            u.role = form.role.data

            pwd_changed = False
            if form.password.data:
                u.set_password(form.password.data)
                pwd_changed = True

            db.add(u)
            db.commit()

            # === AUDITORÍA ===
            changes = {}
            if u.identificacion != old_ident:
                changes["identificacion"] = {"old": old_ident, "new": u.identificacion}
            if u.username != old_username:
                changes["username"] = {"old": old_username, "new": u.username}
            if u.email != old_email:
                changes["email"] = {"old": old_email, "new": u.email}
            if u.role != old_role:
                changes["role"] = {"old": old_role, "new": u.role}
            if pwd_changed:
                changes["password"] = "updated"

            if changes:
                log_audit(
                    db,
                    user_id=u.id,
                    action="admin_user_update",
                    detail={"changes": changes, "reason": "admin_edit"},
                    actor_user_id=current_user.id
                )

                if "role" in changes and current_user.id != u.id:
                    old_role = changes["role"]["old"]
                    new_role = changes["role"]["new"]
                    notify_user(
                        db,
                        user_id=u.id,
                        title="Tu rol ha sido actualizado",
                        body=f"Tu rol cambió de '{old_role}' a '{new_role}' por {current_user.username}.",
                        level="warning",
                    )

            flash("Usuario actualizado.", "success")
            return redirect(url_for("users_index"))
        elif request.method == "GET":
            form.role.data = u.role


        return render_template("users_form.html", form=form, is_edit=True, user=u)
    finally:
        db.close()



@app.route("/usuarios/<int:user_id>/eliminar", methods=["POST"])
@login_required
@admin_required
def users_delete(user_id: int):
    if user_id == current_user.id:
        flash("No puedes eliminar tu propio usuario mientras estás logueado.", "warning")
        return redirect(url_for("users_index"))

    db = SessionLocal()
    try:
        u = db.get(User, user_id)
        if not u:
            raise NotFound()

        # 1) Guardar snapshot en papelera (sin audit_row)
        record_user_deletion(db, u, actor_id=current_user.id)

        # 2) Borrado real
        db.delete(u)
        db.commit()

        flash("Usuario eliminado.", "info")
        return redirect(url_for("users_index"))
    finally:
        db.close()



# --- Ruta: edición de perfil por el propio usuario (sin permitir cambiar el rol) ---

@app.route("/mi-perfil/editar", methods=["GET", "POST"])
@login_required
def self_edit_profile():
    db = SessionLocal()
    try:
        u = db.get(User, current_user.id)
        if not u:
            flash("Usuario no encontrado.", "danger")
            return redirect(url_for("perfil"))

        form = UserSelfEditForm(obj=u)

        if form.validate_on_submit():
            new_username = (form.username.data or "").strip().lower()
            new_email    = (form.email.data or "").strip().lower()
            new_pwd      = (form.new_password.data or "").strip()

            # 1) Colisiones de username/email con otros usuarios
            clash = db.query(User).filter(
                or_(User.username == new_username, User.email == new_email)
            ).filter(User.id != u.id).first()
            if clash:
                flash("Otro usuario ya tiene ese username o correo.", "danger")
                return render_template("perfil_edit.html", form=form)

            # 2) Detectar cambios sensibles
            changing_email    = (new_email != u.email)
            changing_password = bool(new_pwd)

            if changing_email or changing_password:
                # Requiere contraseña actual correcta
                if not form.current_password.data or not u.check_password(form.current_password.data):
                    flash("Debes confirmar tu contraseña actual para cambiar correo o contraseña.", "danger")
                    return render_template("perfil_edit.html", form=form)

            # ================== AUDITORÍA DE CAMBIOS ==================
            # Estado original (por claridad/depuración futura)
            original = {"username": u.username, "email": u.email}

            # Calcula diferencias
            changes = {}
            if new_username != u.username:
                changes["username"] = {"old": u.username, "new": new_username}
            if new_email != u.email:
                changes["email"] = {"old": u.email, "new": new_email}
            if changing_password:
                changes["password"] = "updated"  
            # ==========================================================

            # 3) Aplicar cambios permitidos
            u.username = new_username
            u.email = new_email
            if changing_password:
                u.set_password(new_pwd)

            db.add(u)
            db.commit()

            # 4) Registrar auditoría si hubo cambios
            if changes:
                log_audit(
                  db,
                  user_id=u.id,  # usuario afectado
                  action="profile_update",
                  detail={
                    "changes": changes,
                    "reason": "self_edit",
                  },
                  actor_user_id=current_user.id  # quien realizó la acción
                )

                # 4.1) Notificación al usuario sobre la actualización de su perfil
                notify_user(
                    db,
                    user_id=u.id,
                    title="Tu perfil fue actualizado",
                    body="Se han realizado cambios en tu perfil de usuario.",
                    level="info",
                )

            flash("Perfil actualizado correctamente.", "success")
            return redirect(url_for("perfil"))


        # GET o errores de validación
        return render_template("perfil_edit.html", form=form)

    finally:
        db.close()



# --- Auditoría de acciones para usuarios, es para obtener IP y User-Agent ---
def _client_ip(req) -> str | None:
    # Respeta proxy/reverse-proxy (si lo llevamos en producción a futuro a Render/NGINX)
    hdr = (req.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return hdr or req.remote_addr

# --- Auditoría de acciones para usuarios, en esta User-Agent es para obtener el navegador ---
def _ua(req) -> str | None:
    return (req.headers.get("User-Agent") or "")[:255]

# --- Auditoría de acciones para usuarios, en esta función se registra la auditoría ---
def log_audit(db, user_id: int, action: str, detail: dict | None = None, actor_user_id: int | None = None):
    entry = UserAudit(
        user_id=user_id,
        actor_user_id=actor_user_id,
        action=action,
        detail=json.dumps(detail, ensure_ascii=False) if detail else None,
        ip=_client_ip(request),
        user_agent=_ua(request),
    )
    db.add(entry)
    db.commit()
    return entry  



# --- Vista de auditoría personal ---
@app.route("/mi-perfil/auditoria")
@login_required
def my_audit():
    db = SessionLocal()
    try:
        page = max(1, int(request.args.get("page", 1)))
        size = min(50, max(5, int(request.args.get("size", 10))))
        q = db.query(models.UserAudit).filter(models.UserAudit.user_id == current_user.id)\
                                      .order_by(models.UserAudit.id.desc())
        total = q.count()
        audits = q.offset((page-1)*size).limit(size).all()
        return render_template("audit_my.html", audits=audits, page=page, size=size, total=total)
    finally:
        db.close()

# --- Vista de auditoría para admin (todos los usuarios) ---

@app.route("/admin/auditoria")
@login_required
@admin_required
def audit_admin():
    db = SessionLocal()
    try:
        q_text = (request.args.get("q") or "").strip().lower()
        page = max(1, int(request.args.get("page", 1)))
        size = min(100, max(10, int(request.args.get("size", 20))))

        # alias para poder filtrar por usuario afectado y actor
        UserAffected = aliased(models.User)
        UserActor    = aliased(models.User)

        qry = (db.query(models.UserAudit)
                .outerjoin(UserAffected, models.UserAudit.user)   # relación "user"
                .outerjoin(UserActor,    models.UserAudit.actor)  # relación "actor"
                .options(
                    joinedload(models.UserAudit.user),
                    joinedload(models.UserAudit.actor),
                )
                .order_by(models.UserAudit.id.desc()))

        if q_text:
            like = f"%{q_text}%"
            qry = qry.filter(or_(
                models.UserAudit.action.ilike(like),
                models.UserAudit.detail.ilike(like),
                models.UserAudit.ip.ilike(like),
                models.UserAudit.user_agent.ilike(like),
                UserAffected.username.ilike(like),   # ← usuario afectado
                UserActor.username.ilike(like),      # ← actor
            ))

        total = qry.count()
        audits = qry.offset((page-1)*size).limit(size).all()

        return render_template("audit_admin.html",
                               audits=audits, page=page, size=size, total=total, q=q_text)
    finally:
        db.close()


@app.template_filter("prettyjson")  # ################################ solo si queremos la vista de cambios en formato json
def prettyjson_filter(value):
    import json
    from markupsafe import Markup, escape
    try:
        if isinstance(value, str):
            data = json.loads(value)
        else:
            data = value
        pretty = json.dumps(data, ensure_ascii=False, indent=2)
        return Markup("<pre class='m-0 small bg-light border rounded p-2'>") + escape(pretty) + Markup("</pre>")
    except Exception:
        return Markup("<pre class='m-0 small bg-light border rounded p-2'>") + escape(value or "") + Markup("</pre>")



@app.route("/admin/mis-acciones") # ---------------------------------- Vista de auditoría de acciones propias (solo admin)
@login_required
@admin_required
def audit_admin_mine():
    db = SessionLocal()
    try:
        q_text = (request.args.get("q") or "").strip().lower()
        page = max(1, int(request.args.get("page", 1)))
        size = min(100, max(10, int(request.args.get("size", 20))))

        UserAffected = aliased(models.User)

        qry = (db.query(models.UserAudit)
                .filter(models.UserAudit.actor_user_id == current_user.id)
                .outerjoin(UserAffected, models.UserAudit.user)
                .options(
                    joinedload(models.UserAudit.user),
                    joinedload(models.UserAudit.actor),
                )
                .order_by(models.UserAudit.id.desc()))

        if q_text:
            like = f"%{q_text}%"
            qry = qry.filter(or_(
                models.UserAudit.action.ilike(like),
                models.UserAudit.detail.ilike(like),
                models.UserAudit.ip.ilike(like),
                models.UserAudit.user_agent.ilike(like),
                UserAffected.username.ilike(like),   # usuario afectado
            ))

        total = qry.count()
        audits = qry.offset((page-1)*size).limit(size).all()

        return render_template("audit_admin_mine.html",
                               audits=audits, page=page, size=size, total=total, q=q_text)
    finally:
        db.close()


@app.template_filter("render_audit_detail") # ################################ renderiza el campo detail de auditoría
def render_audit_detail(value):
    """
    Renderiza el campo 'detail' (JSON o dict) en HTML legible:
    - 'changes': lista de cambios old → new; password = 'actualizada'
    - 'created' / 'deleted': ficha con campos
    - 'reason': nota al pie
    """
    # 1) Parsea a dict
    try:
        data = json.loads(value) if isinstance(value, str) else (value or {})
        if not isinstance(data, dict):
            data = {}
    except Exception:
        # Si no es JSON válido, lo mostramos plano
        return Markup("<span class='text-muted small'>") + escape(value or "") + Markup("</span>")

    parts = []

    # 2) Cambios
    changes = data.get("changes")
    if isinstance(changes, dict) and changes:
        rows = []
        for key, val in changes.items():
            if key == "password" and (val == "updated" or (isinstance(val, str) and "updated" in val)):
                rows.append(
                    f"<li class='mb-1'><strong>{escape(key)}</strong>: "
                    f"<span class='badge text-bg-warning'>actualizada</span></li>"
                )
            elif isinstance(val, dict) and "old" in val and "new" in val:
                old = escape(val.get("old", ""))
                new = escape(val.get("new", ""))
                rows.append(
                    "<li class='mb-1'><strong>{k}</strong>: "
                    "<span class='text-danger'>{o}</span> &rarr; "
                    "<span class='text-success'>{n}</span></li>"
                    .format(k=escape(key), o=old, n=new)
                )
            else:
                rows.append(
                    "<li class='mb-1'><strong>{k}</strong>: {v}</li>"
                    .format(k=escape(key), v=escape(str(val)))
                )
        parts.append(
            "<div class='mb-2'>"
            "<div class='fw-semibold mb-1'>Cambios</div>"
            "<ul class='mb-0 small ps-3'>"
            + "".join(rows) +
            "</ul></div>"
        )

    # 3) Creado / Eliminado
    def _render_kv_block(label, obj):
        items = "".join(
            "<dt class='col-sm-4 text-muted'>{k}</dt><dd class='col-sm-8'>{v}</dd>"
            .format(k=escape(k), v=escape(v))
            for k, v in obj.items()
        )
        return (
            "<div class='mb-2'>"
            f"<span class='badge text-bg-secondary'>{label}</span>"
            "<dl class='row small mb-0 mt-2'>" + items + "</dl>"
            "</div>"
        )

    created = data.get("created")
    if isinstance(created, dict) and created:
        parts.append(_render_kv_block("Creado", created))

    deleted = data.get("deleted")
    if isinstance(deleted, dict) and deleted:
        parts.append(_render_kv_block("Eliminado", deleted))

    # 4) reason
    reason = data.get("reason")
    if reason:
        parts.append("<div class='small text-muted mt-1'>Motivo: {}</div>".format(escape(reason)))

    if not parts:
        parts.append("<span class='text-muted'>—</span>")

    return Markup("".join(parts))


def record_user_deletion(db, u: User, actor_id: int | None):
    from models import UserDeletion
    row = UserDeletion(
        user_id=u.id,
        identificacion=u.identificacion,   
        username=u.username,
        email=u.email,
        role=u.role,
        actor_user_id=actor_id,
        ip=_client_ip(request),
        user_agent=_ua(request),
    )
    db.add(row)
    db.commit()
    return row


def record_equipo_deletion(db, e, actor_id: int | None): # registra la eliminación de un equipo
    from models import EquipoDeletion
    row = EquipoDeletion(
        equipo_id=e.id,
        codigo_interno=e.codigo_interno,
        tipo_equipo=e.tipo_equipo,
        marca=e.marca,
        modelo=e.modelo,
        serial=e.serial,
        # snapshot de los nombres
        empresa_externa=e.empresa.nombre if e.empresa else None,
        responsable_entrega=e.responsable.nombre_responsable if e.responsable else None,
        estado=e.estado,
        fecha_ingreso=e.fecha_ingreso,
        fecha_salida=e.fecha_salida,
        autorizado_por=e.autorizado_por,
        observaciones=e.observaciones,
        actor_user_id=actor_id,
        ip=_client_ip(request),
        user_agent=_ua(request),
    )
    db.add(row)
    db.commit()
    return row




@app.route("/admin/eliminados") # ---------------------------------- Vista de usuarios eliminados (solo admin)
@login_required
@admin_required
def audit_deleted():
    db = SessionLocal()
    try:
        q = (request.args.get("q") or "").strip()
        page = max(1, int(request.args.get("page", 1)))
        size = min(100, max(10, int(request.args.get("size", 20))))

        Actor = aliased(models.User)

        qry = (db.query(models.UserDeletion)
               .outerjoin(Actor, models.UserDeletion.actor)
               .options(joinedload(models.UserDeletion.actor))
               .order_by(models.UserDeletion.id.desc()))

        if q:
            like = f"%{q.lower()}%"
            qry = qry.filter(or_(
                models.UserDeletion.username.ilike(like),
                models.UserDeletion.email.ilike(like),
                models.UserDeletion.role.ilike(like),
                Actor.username.ilike(like),
                models.UserDeletion.ip.ilike(like),
                models.UserDeletion.user_agent.ilike(like),
            ))

        total = qry.count()
        rows = qry.offset((page-1)*size).limit(size).all()
        return render_template("audit_deleted.html", rows=rows, page=page, size=size, total=total, q=q)
    finally:
        db.close()




@app.route("/empresas")
@login_required
def empresas_index():
    q = (request.args.get("q") or "").strip()
    db = SessionLocal()
    try:
        qry = db.query(EmpresaExterna)
        if q:
            like = f"%{q.lower()}%"
            qry = qry.filter(or_(
                EmpresaExterna.identificacion.ilike(like),
                EmpresaExterna.nombre.ilike(like),
            ))
        empresas = qry.order_by(EmpresaExterna.nombre.asc()).all()
        return render_template("empresas_index.html", empresas=empresas, q=q)
    finally:
        db.close()

@app.route("/empresas/crear", methods=["GET", "POST"])
@login_required
@admin_required
def empresas_create():
    form = EmpresaExternaForm()
    if form.validate_on_submit():
        db = SessionLocal()
        try:
            ident = (form.identificacion.data or "").strip()
            nombre = (form.nombre.data or "").strip()

            # Verificar unicidad de identificación
            exists = db.query(EmpresaExterna).filter(
                EmpresaExterna.identificacion == ident
            ).first()
            if exists:
                flash("Ya existe una empresa con esa identificación.", "danger")
                return render_template("empresas_form.html", form=form, is_edit=False)

            emp = EmpresaExterna(
                identificacion=ident,
                nombre=nombre,
            )
            db.add(emp)
            db.commit()

            flash("Empresa creada correctamente.", "success")
            return redirect(url_for("empresas_index"))
        finally:
            db.close()
    elif form.is_submitted():
        flash("Revisa el formulario.", "warning")

    return render_template("empresas_form.html", form=form, is_edit=False)


@app.route("/empresas/<int:empresa_id>/editar", methods=["GET", "POST"])
@login_required
@admin_required
def empresas_edit(empresa_id: int):
    db = SessionLocal()
    try:
        emp = db.get(EmpresaExterna, empresa_id)
        if not emp:
            raise NotFound()

        form = EmpresaExternaForm(obj=emp)

        if form.validate_on_submit():
            new_ident = (form.identificacion.data or "").strip()
            new_nombre = (form.nombre.data or "").strip()

            # Verificar colisión de identificación con otra empresa
            clash = db.query(EmpresaExterna).filter(
                EmpresaExterna.identificacion == new_ident,
                EmpresaExterna.id != emp.id
            ).first()
            if clash:
                flash("Otra empresa ya tiene esa identificación.", "danger")
                return render_template("empresas_form.html", form=form, is_edit=True, empresa=emp)

            emp.identificacion = new_ident
            emp.nombre = new_nombre

            db.add(emp)
            db.commit()

            flash("Empresa actualizada.", "success")
            return redirect(url_for("empresas_index"))

        return render_template("empresas_form.html", form=form, is_edit=True, empresa=emp)
    finally:
        db.close()

@app.route("/responsables")
@login_required
def responsables_index():
    q = (request.args.get("q") or "").strip()
    db = SessionLocal()
    try:
        qry = db.query(ResponsableEntrega).join(EmpresaExterna)

        if q:
            like = f"%{q.lower()}%"
            qry = qry.filter(or_(
                ResponsableEntrega.id_responsable.ilike(like),
                ResponsableEntrega.nombre_responsable.ilike(like),
                ResponsableEntrega.correo_responsable.ilike(like),
                EmpresaExterna.nombre.ilike(like),
                EmpresaExterna.identificacion.ilike(like),
            ))

        responsables = qry.order_by(
            EmpresaExterna.nombre.asc(),
            ResponsableEntrega.nombre_responsable.asc()
        ).all()

        return render_template("responsables_index.html", responsables=responsables, q=q)
    finally:
        db.close()


@app.route("/responsables/crear", methods=["GET", "POST"])
@login_required
@admin_required
def responsables_create():
    db = SessionLocal()
    try:
        empresas = (
            db.query(EmpresaExterna)
              .order_by(EmpresaExterna.nombre.asc())
              .all()
        )

        if not empresas:
            flash("Primero debes crear al menos una empresa externa.", "warning")
            return redirect(url_for("empresas_create"))

        form = ResponsableEntregaForm()
        form.empresa_id.choices = [
            (e.id, f"{e.identificacion} — {e.nombre}")
            for e in empresas
        ]

        if form.validate_on_submit():
            id_resp = (form.id_responsable.data or "").strip()
            nombre = (form.nombre_responsable.data or "").strip()
            correo = (form.correo_responsable.data or "").strip()

            # Unicidad de id_responsable
            exists = db.query(ResponsableEntrega).filter(
                ResponsableEntrega.id_responsable == id_resp
            ).first()
            if exists:
                flash("Ya existe un responsable con ese ID.", "danger")
                return render_template("responsables_form.html", form=form, is_edit=False)

            resp = ResponsableEntrega(
                id_responsable=id_resp,
                nombre_responsable=nombre,
                correo_responsable=correo,
                empresa_id=form.empresa_id.data,
            )
            db.add(resp)
            db.commit()

            flash("Responsable creado correctamente.", "success")
            return redirect(url_for("responsables_index"))

        elif form.is_submitted():
            flash("Revisa el formulario.", "warning")

        return render_template("responsables_form.html", form=form, is_edit=False)
    finally:
        db.close()

@app.route("/responsables/<int:resp_id>/editar", methods=["GET", "POST"])
@login_required
@admin_required
def responsables_edit(resp_id: int):
    db = SessionLocal()
    try:
        resp = db.get(ResponsableEntrega, resp_id)
        if not resp:
            raise NotFound()

        empresas = (
            db.query(EmpresaExterna)
              .order_by(EmpresaExterna.nombre.asc())
              .all()
        )

        if not empresas:
            flash("No hay empresas registradas. Crea una primero.", "warning")
            return redirect(url_for("empresas_create"))

        form = ResponsableEntregaForm(obj=resp)
        form.empresa_id.choices = [
            (e.id, f"{e.identificacion} — {e.nombre}")
            for e in empresas
        ]

        # Preseleccionar empresa actual en GET
        if request.method == "GET":
            form.empresa_id.data = resp.empresa_id

        if form.validate_on_submit():
            new_id_resp = (form.id_responsable.data or "").strip()
            new_nombre = (form.nombre_responsable.data or "").strip()
            new_correo = (form.correo_responsable.data or "").strip()

            # Unicidad de id_responsable
            clash = db.query(ResponsableEntrega).filter(
                ResponsableEntrega.id_responsable == new_id_resp,
                ResponsableEntrega.id != resp.id
            ).first()
            if clash:
                flash("Otro responsable ya tiene ese ID.", "danger")
                return render_template("responsables_form.html", form=form, is_edit=True, responsable=resp)

            resp.id_responsable = new_id_resp
            resp.nombre_responsable = new_nombre
            resp.correo_responsable = new_correo
            resp.empresa_id = form.empresa_id.data

            db.add(resp)
            db.commit()

            flash("Responsable actualizado.", "success")
            return redirect(url_for("responsables_index"))

        return render_template("responsables_form.html", form=form, is_edit=True, responsable=resp)
    finally:
        db.close()


@app.route("/empresas/<int:empresa_id>/eliminar", methods=["POST"])
@login_required
@admin_required
def empresas_delete(empresa_id: int):
    db = SessionLocal()
    try:
        emp = db.get(EmpresaExterna, empresa_id)
        if not emp:
            raise NotFound()

        # ¿Hay equipos usando esta empresa?
        has_equipos = db.query(Equipo).filter(Equipo.empresa_id == emp.id).first() is not None
        if has_equipos:
            flash("No puedes eliminar la empresa porque tiene equipos asociados.", "warning")
            return redirect(url_for("empresas_index"))

        # Si no hay equipos, se puede eliminar.
        db.delete(emp)
        db.commit()
        flash("Empresa eliminada correctamente.", "info")
        return redirect(url_for("empresas_index"))
    finally:
        db.close()


@app.route("/responsables/<int:resp_id>/eliminar", methods=["POST"])
@login_required
@admin_required
def responsables_delete(resp_id: int):
    db = SessionLocal()
    try:
        resp = db.get(ResponsableEntrega, resp_id)
        if not resp:
            raise NotFound()

        # ¿Hay equipos que dependan de este responsable?
        has_equipos = db.query(Equipo).filter(Equipo.responsable_id == resp.id).first() is not None
        if has_equipos:
            flash("No puedes eliminar el responsable porque tiene equipos asociados.", "warning")
            return redirect(url_for("responsables_index"))

        db.delete(resp)
        db.commit()
        flash("Responsable eliminado correctamente.", "info")
        return redirect(url_for("responsables_index"))
    finally:
        db.close()




# ========= Gestión de Equipos =========


@app.route("/equipos") # ---------------------------------- Listado de equipos
@login_required
def equipos_index():
    q = (request.args.get("q") or "").strip()
    page = max(1, int(request.args.get("page", 1)))
    size = min(100, max(10, int(request.args.get("size", 20))))

    db = SessionLocal()
    try:
        qry = (
            db.query(Equipo)
              .join(EmpresaExterna, Equipo.empresa_id == EmpresaExterna.id)
              .join(ResponsableEntrega, Equipo.responsable_id == ResponsableEntrega.id)
        )

        if q:
            like = f"%{q.lower()}%"
            qry = qry.filter(or_(
                Equipo.codigo_interno.ilike(like),
                Equipo.marca.ilike(like),
                Equipo.modelo.ilike(like),
                Equipo.serial.ilike(like),
                EmpresaExterna.nombre.ilike(like),
                EmpresaExterna.identificacion.ilike(like),
                ResponsableEntrega.nombre_responsable.ilike(like),
                ResponsableEntrega.id_responsable.ilike(like),
                cast(Equipo.estado, String).ilike(like),
                cast(Equipo.tipo_equipo, String).ilike(like),
            ))

        #  total de EQUIPOS según el filtro actual
        total = qry.distinct(Equipo.id).count()

        equipos = (
            qry.order_by(Equipo.id.desc())
               .offset((page-1)*size)
               .limit(size)
               .all()
        )

        return render_template(
            "equipos_index.html",
            equipos=equipos,
            q=q,
            page=page,
            size=size,
            total=total,
        )
    finally:
        db.close()




@app.route("/equipos/<int:equipo_id>") # ---------------------------------- Ver detalle de un equipo
@login_required
def equipos_show(equipo_id: int):
    db = SessionLocal()
    try:
        e = (
                db.query(Equipo)
                .options(
                    joinedload(Equipo.autorizador),
                    joinedload(Equipo.empresa),
                    joinedload(Equipo.responsable),
                )
                .get(equipo_id)
            )
        if not e:
            flash("Equipo no encontrado.", "warning")
            return redirect(url_for("equipos_index"))

        return render_template("equipos_show.html", e=e)
    finally:
        db.close()




# --- Crear equipo ---
@app.route("/equipos/crear", methods=["GET","POST"])
@login_required
@admin_required
def equipos_create():
    db = SessionLocal()
    try:
        # Usuarios que pueden autorizar
        usuarios_autorizadores = (
            db.query(User)
              .filter(User.role == "usuario")
              .order_by(User.identificacion.asc(), User.username.asc())
              .all()
        )

        # Empresas externas
        empresas = (
            db.query(EmpresaExterna)
              .order_by(EmpresaExterna.nombre.asc())
              .all()
        )

        # Responsables de entrega (con empresa)
        responsables = (
            db.query(ResponsableEntrega)
              .join(EmpresaExterna)
              .order_by(EmpresaExterna.nombre.asc(), ResponsableEntrega.nombre_responsable.asc())
              .all()
        )

        #  avisar si faltan catálogos base
        if not empresas:
            flash("Antes de crear un equipo debes registrar al menos una empresa externa.", "warning")
        if not responsables:
            flash("Antes de crear un equipo debes registrar al menos un responsable de entrega.", "warning")

        form = EquipoForm(is_create=True)

        # Choices para autorizado_por
        form.autorizado_por.choices = [
            (u.id, f"{u.identificacion} — {u.username}")
            for u in usuarios_autorizadores
        ]

        # Choices para empresa
        form.empresa_id.choices = [
            (e.id, f"{e.identificacion} — {e.nombre}")
            for e in empresas
        ]

        # Choices para responsable (lista completa; el JS luego filtra por empresa)
        form.responsable_id.choices = [
            (r.id, f"{r.id_responsable} — {r.nombre_responsable} ({r.empresa.nombre})")
            for r in responsables
        ]

        if form.validate_on_submit():
            code = form.codigo_interno.data.strip()

            # Unicidad de código interno
            if db.query(Equipo).filter(Equipo.codigo_interno == code).first():
                flash("Ya existe un equipo con ese código interno.", "danger")
                return render_template(
                    "equipos_form.html",
                    form=form,
                    is_edit=False,
                    usuarios_autorizadores=usuarios_autorizadores,
                    empresas=empresas,
                    responsables=responsables,
                )

            serial = (form.serial.data or "").strip() or None
            if serial and db.query(Equipo).filter(Equipo.serial == serial).first():
                flash("Ya existe un equipo con ese serial.", "danger")
                return render_template(
                    "equipos_form.html",
                    form=form,
                    is_edit=False,
                    usuarios_autorizadores=usuarios_autorizadores,
                    empresas=empresas,
                    responsables=responsables,
                )

            #  VALIDACIÓN EXTRA: el responsable debe pertenecer a la empresa seleccionada
            resp = db.get(ResponsableEntrega, form.responsable_id.data)
            if not resp or resp.empresa_id != form.empresa_id.data:
                flash("El responsable seleccionado no pertenece a la empresa escogida.", "danger")
                return render_template(
                    "equipos_form.html",
                    form=form,
                    is_edit=False,
                    usuarios_autorizadores=usuarios_autorizadores,
                    empresas=empresas,
                    responsables=responsables,
                )

            e = Equipo(
                codigo_interno=code,
                tipo_equipo=form.tipo_equipo.data,
                marca=(form.marca.data or "").strip() or None,
                modelo=(form.modelo.data or "").strip() or None,
                serial=serial,
                empresa_id=form.empresa_id.data,
                responsable_id=form.responsable_id.data,
                fecha_ingreso=form.fecha_ingreso.data,
                fecha_salida=form.fecha_salida.data,
                estado=form.estado.data,
                observaciones=form.observaciones.data or None,
                autorizado_por=form.autorizado_por.data,
            )

            db.add(e)
            try:
                db.commit()
            except IntegrityError as ie:
                db.rollback()
                msg = "No se pudo guardar: "
                s = str(ie.orig)
                if "uq_equipos_serial" in s:
                    msg += "el serial ya existe."
                elif "equipos_codigo_interno_key" in s or "unique" in s.lower():
                    msg += "el código interno ya existe."
                elif "ck_equipos_estado_fecha" in s or "ck_equipos_fechas_coherentes" in s:
                    msg += "las fechas no son coherentes con el estado seleccionado."
                else:
                    msg += "violación de restricción."
                flash(msg, "danger")
                return render_template(
                    "equipos_form.html",
                    form=form,
                    is_edit=False,
                    usuarios_autorizadores=usuarios_autorizadores,
                    empresas=empresas,
                    responsables=responsables,
                )

            #  Obtener el usuario autorizado (si hay)
            autorizador = db.get(User, e.autorizado_por) if e.autorizado_por else None

            # Auditoría
            log_equipo_audit(
                db,
                equipo_id=e.id,
                action="equipo_create",
                detail={
                    "created": {
                        "id": e.id,
                        "codigo_interno": e.codigo_interno,
                        "tipo_equipo": e.tipo_equipo,
                        "serial": e.serial,
                        "estado": e.estado,
                        "fecha_ingreso": e.fecha_ingreso.isoformat() if e.fecha_ingreso else None,
                        "fecha_salida": e.fecha_salida.isoformat() if e.fecha_salida else None,
                    }
                },
                actor_user_id=current_user.id
            )

            #  Notificar a todos los admins
            notify_admins(
                db,
                title=f"Equipo creado: {e.codigo_interno}",
                body=f"Tipo: {e.tipo_equipo}. Estado: {e.estado}.",
                level="success",
            )

            #  Notificar al usuario asociado como “Autorizado por”
            if autorizador:
                notify_user(
                    db,
                    user_id=autorizador.id,
                    title="Te han asignado como 'Autorizado por'",
                    body=(
                        f"Has sido asignado como autorizado para el equipo "
                        f"{e.codigo_interno} "
                        f"({e.marca or ''} {e.modelo or ''}). "
                        f"Estado actual: {e.estado}."
                    ),
                    level="info",
                )

            flash("Equipo creado correctamente.", "success")
            return redirect(url_for("equipos_index"))

        elif form.is_submitted():
            # Flash de todos los errores de WTForms (incluyendo los del validate())
            for field, errors in form.errors.items():
                label = getattr(form, field).label.text
                for err in errors:
                    flash(f"{label}: {err}", "danger")
            flash("Revisa el formulario: hay errores de validación (fechas/estado/etc.).", "warning")

        # GET inicial o render tras errores
        return render_template(
            "equipos_form.html",
            form=form,
            is_edit=False,
            usuarios_autorizadores=usuarios_autorizadores,
            empresas=empresas,
            responsables=responsables,
        )
    finally:
        db.close()


# --- Editar equipo ---
@app.route("/equipos/<int:equipo_id>/editar", methods=["GET","POST"])
@login_required
@admin_required
def equipos_edit(equipo_id: int):
    db = SessionLocal()
    try:
        e = db.get(Equipo, equipo_id)
        if not e:
            flash("Equipo no encontrado.", "warning")
            return redirect(url_for("equipos_index"))

        #  Usuarios que pueden autorizar (rol 'usuario')
        usuarios_autorizadores = (
            db.query(User)
              .filter(User.role == "usuario")
              .order_by(User.identificacion.asc(), User.username.asc())
              .all()
        )

        empresas = (
            db.query(EmpresaExterna)
              .order_by(EmpresaExterna.nombre.asc())
              .all()
        )

        responsables = (
            db.query(ResponsableEntrega)
              .join(EmpresaExterna)
              .order_by(EmpresaExterna.nombre.asc(), ResponsableEntrega.nombre_responsable.asc())
              .all()
        )

        form = EquipoForm(obj=e, is_create=False)

        form.autorizado_por.choices = [
            (u.id, f"{u.identificacion} — {u.username}")
            for u in usuarios_autorizadores
        ]
        form.empresa_id.choices = [
            (em.id, f"{em.identificacion} — {em.nombre}")
            for em in empresas
        ]
        form.responsable_id.choices = [
            (r.id, f"{r.id_responsable} — {r.nombre_responsable} ({r.empresa.nombre})")
            for r in responsables
        ]

        # Preseleccionar valores actuales
        if request.method == "GET":
            if e.autorizado_por:
                form.autorizado_por.data = e.autorizado_por
            form.empresa_id.data = e.empresa_id
            form.responsable_id.data = e.responsable_id

        if form.validate_on_submit():
            new_code = form.codigo_interno.data.strip()
            serial = (form.serial.data or "").strip() or None

            # Unicidad de código interno
            if db.query(Equipo).filter(
                Equipo.codigo_interno == new_code,
                Equipo.id != e.id
            ).first():
                flash("Ya existe un equipo con ese código interno.", "danger")
                return render_template(
                    "equipos_form.html",
                    form=form,
                    is_edit=True,
                    e=e,
                    usuarios_autorizadores=usuarios_autorizadores,
                    empresas=empresas,
                    responsables=responsables,
                )

            # Unicidad de serial
            if serial and db.query(Equipo).filter(
                Equipo.serial == serial,
                Equipo.id != e.id
            ).first():
                flash("Ya existe un equipo con ese serial.", "danger")
                return render_template(
                    "equipos_form.html",
                    form=form,
                    is_edit=True,
                    e=e,
                    usuarios_autorizadores=usuarios_autorizadores,
                    empresas=empresas,
                    responsables=responsables,
                )

            #  VALIDACIÓN EXTRA: el responsable debe pertenecer a la empresa seleccionada
            resp = db.get(ResponsableEntrega, form.responsable_id.data)
            if not resp or resp.empresa_id != form.empresa_id.data:
                flash("El responsable seleccionado no pertenece a la empresa escogida.", "danger")
                return render_template(
                    "equipos_form.html",
                    form=form,
                    is_edit=True,
                    e=e,
                    usuarios_autorizadores=usuarios_autorizadores,
                    empresas=empresas,
                    responsables=responsables,
                )

            # Snapshot ANTES (para auditoría)
            before = _equipo_snapshot(e)
            old_aut_id = e.autorizado_por  # puede ser None

            # --- Aplicar cambios ---
            e.codigo_interno = new_code
            e.tipo_equipo = form.tipo_equipo.data
            e.marca = (form.marca.data or "").strip() or None
            e.modelo = (form.modelo.data or "").strip() or None
            e.serial = serial
            e.empresa_id = form.empresa_id.data
            e.responsable_id = form.responsable_id.data

            e.fecha_ingreso = form.fecha_ingreso.data
            e.fecha_salida = form.fecha_salida.data
            e.estado = form.estado.data

            #  guarda el user.id
            e.autorizado_por = form.autorizado_por.data

            e.observaciones = form.observaciones.data or None

            try:
                db.add(e)
                db.commit()
            except IntegrityError as ie:
                db.rollback()
                msg = "No se pudo guardar: "
                s = str(ie.orig)
                if "uq_equipos_serial" in s:
                    msg += "el serial ya existe."
                elif "equipos_codigo_interno_key" in s or "unique" in s.lower():
                    msg += "el código interno ya existe."
                elif "ck_equipos_estado_fecha" in s or "ck_equipos_fechas_coherentes" in s:
                    msg += "las fechas no son coherentes con el estado seleccionado."
                else:
                    msg += "violación de restricción."
                flash(msg, "danger")
                return render_template(
                    "equipos_form.html",
                    form=form,
                    is_edit=True,
                    e=e,
                    usuarios_autorizadores=usuarios_autorizadores,
                    empresas=empresas,
                    responsables=responsables,
                )

            # Snapshot DESPUÉS
            after = _equipo_snapshot(e)
            changes = {
                k: {"old": before.get(k), "new": after.get(k)}
                for k in after.keys()
                if before.get(k) != after.get(k)
            }

            #  Notificaciones relacionadas con el AUTORIZADO POR
            new_aut_id = e.autorizado_por

            if old_aut_id != new_aut_id:
                # Recuperar usuarios viejo/nuevo (los que apliquen)
                ids = [i for i in [old_aut_id, new_aut_id] if i]
                usuarios_map = {}
                if ids:
                    usuarios = db.query(User).filter(User.id.in_(ids)).all()
                    usuarios_map = {u.id: u for u in usuarios}

                # Notificar al nuevo autorizado
                if new_aut_id and new_aut_id in usuarios_map:
                    nuevo = usuarios_map[new_aut_id]
                    notify_user(
                        db,
                        user_id=nuevo.id,
                        title="Te han asignado como 'Autorizado por'",
                        body=(
                            f"Has sido asignado como autorizado para el equipo "
                            f"{e.codigo_interno} "
                            f"({e.marca or ''} {e.modelo or ''}). "
                            f"Estado actual: {e.estado}."
                        ),
                        level="info",
                    )

                # Notificar al anterior autorizado (si existía y es distinto)
                if old_aut_id and old_aut_id in usuarios_map:
                    anterior = usuarios_map[old_aut_id]
                    notify_user(
                        db,
                        user_id=anterior.id,
                        title="Ya no eres 'Autorizado por' de un equipo",
                        body=(
                            f"Ya no figuras como autorizado para el equipo "
                            f"{e.codigo_interno} "
                            f"({e.marca or ''} {e.modelo or ''})."
                        ),
                        level="warning",
                    )

            # Auditoría
            if changes:
                log_equipo_audit(
                    db,
                    equipo_id=e.id,
                    action="equipo_update",
                    detail={"id": e.id, "changes": changes, "reason": "admin_edit_equipo"},
                    actor_user_id=current_user.id
                )

                # Si cambió el estado, avisar a admins
                if "estado" in changes:
                    old_state = changes["estado"]["old"]
                    new_state = changes["estado"]["new"]
                    notify_admins(
                        db,
                        title=f"Estado actualizado: {e.codigo_interno}",
                        body=f"De '{old_state}' a '{new_state}' por {current_user.username}.",
                        level="info",
                    )

            flash("Equipo actualizado.", "success")
            return redirect(url_for("equipos_index"))

        elif form.is_submitted():
            for field, errors in form.errors.items():
                label = getattr(form, field).label.text
                for err in errors:
                    flash(f"{label}: {err}", "danger")
            flash("Revisa el formulario: hay errores de validación (fechas/estado/etc.).", "warning")

        return render_template(
            "equipos_form.html",
            form=form,
            is_edit=True,
            e=e,
            usuarios_autorizadores=usuarios_autorizadores,
            empresas=empresas,
            responsables=responsables,
        )
    finally:
        db.close()


# ------------------ Eliminar equipo ------------------
@app.route("/equipos/<int:equipo_id>/eliminar", methods=["POST"])
@login_required
@admin_required
def equipos_delete(equipo_id: int):
    # --- Validar mini-captcha con varias operaciones ---
    try:
        a = int(request.form.get("cap_a", 0))
        b = int(request.form.get("cap_b", 0))
        op = request.form.get("cap_op", "+")
        r = int(request.form.get("cap_result", -1))
    except ValueError:
        a = b = 0
        r = -1
        op = "+"

    # --- Evaluar resultado esperado ---
    if op == "+":
        esperado = a + b
    elif op == "-":
        esperado = a - b
    elif op == "×":
        esperado = a * b
    elif op == "÷":
        esperado = a // b if b != 0 else None
    else:
        esperado = None

    if esperado is None or r != esperado:
        flash("⚠️ No se confirmó correctamente la operación de eliminación.", "warning")
        return redirect(url_for("equipos_index"))

    db = SessionLocal()
    try:
        e = db.get(Equipo, equipo_id)
        if not e:
            flash("Equipo no encontrado.", "warning")
            return redirect(url_for("equipos_index"))

        # Snapshot, eliminación y auditoría
        snapshot = _equipo_snapshot(e) | {"id": e.id}
        record_equipo_deletion(db, e, actor_id=current_user.id)
        db.delete(e)
        db.commit()

        notify_admins(
            db,
            title=f"Equipo eliminado: {e.codigo_interno}",
            body=f"Actor: {current_user.username}",
            level="warning",
        )

        flash("✅ Equipo eliminado correctamente.", "info")
        return redirect(url_for("equipos_index"))
    finally:
        db.close()




@app.route("/equipos/eliminar-todos", methods=["POST"])
@login_required
@admin_required
def equipos_delete_all():
    db = SessionLocal()
    try:
        # Traer todos los equipos
        equipos = db.query(Equipo).all()
        if not equipos:
            flash("No hay equipos para eliminar.", "info")
            return redirect(url_for("equipos_index"))

        count = 0
        for e in equipos:
            # Guardar snapshot en tabla de eliminados (papelera)
            record_equipo_deletion(db, e, actor_id=current_user.id)
            # Borrado real del equipo
            db.delete(e)
            count += 1

        db.commit()

        # Notificar a todos los administradores
        notify_admins(
            db,
            title="Eliminación masiva de equipos",
            body=f"Se eliminaron {count} equipos. Actor: {current_user.username}",
            level="danger",
        )

        flash(f"Se eliminaron {count} equipos.", "warning")
        return redirect(url_for("equipos_index"))
    finally:
        db.close()


@app.route("/equipos/eliminar-filtrados", methods=["POST"])
@login_required
@admin_required
def equipos_delete_filtered():
    q = (request.form.get("q") or "").strip()

    db = SessionLocal()
    try:
        # Armar la misma query base que en equipos_index
        qry = db.query(Equipo).join(EmpresaExterna).join(ResponsableEntrega)

        if q:
            like = f"%{q.lower()}%"
            qry = qry.filter(or_(
                Equipo.codigo_interno.ilike(like),
                Equipo.marca.ilike(like),
                Equipo.modelo.ilike(like),
                Equipo.serial.ilike(like),
                EmpresaExterna.nombre.ilike(like),
                EmpresaExterna.identificacion.ilike(like),
                ResponsableEntrega.nombre_responsable.ilike(like),
                ResponsableEntrega.id_responsable.ilike(like),
                cast(Equipo.estado, String).ilike(like),
                cast(Equipo.tipo_equipo, String).ilike(like),
            ))

        equipos = qry.all()

        if not equipos:
            flash("No hay equipos que coincidan con el filtro para eliminar.", "info")
            # Volver manteniendo el filtro (por si luego quiere revisar)
            return redirect(url_for("equipos_index", q=q or None))

        count = 0
        for e in equipos:
            # Guardar en tabla de eliminados (papelera)
            record_equipo_deletion(db, e, actor_id=current_user.id)
            # Borrado real sobre el equipo
            db.delete(e)
            count += 1

        db.commit()

        # Notificar a admins
        filtro_desc = q if q else "sin filtro (todos)"
        notify_admins(
            db,
            title="Eliminación masiva de equipos (filtrados)",
            body=f"Se eliminaron {count} equipos con filtro: {filtro_desc}. Actor: {current_user.username}",
            level="danger",
        )

        flash(f"Se eliminaron {count} equipos que coincidían con el filtro.", "warning")
        return redirect(url_for("equipos_index"))

    finally:
        db.close()



@app.route("/admin/equipos/auditoria") # ---------------------------------- Vista de auditoría de equipos (solo admin)
@login_required
@admin_required
def audit_equipos_admin():
    db = SessionLocal()
    try:
        q_text = (request.args.get("q") or "").strip().lower()
        page = max(1, int(request.args.get("page", 1)))
        size = min(100, max(10, int(request.args.get("size", 20))))

        Actor = aliased(models.User)
        EquipoAlias = aliased(models.Equipo)

        qry = (db.query(models.EquipoAudit)
               .outerjoin(Actor, models.EquipoAudit.actor)
               .outerjoin(EquipoAlias, models.EquipoAudit.equipo)
               .options(
                   joinedload(models.EquipoAudit.actor),
                   joinedload(models.EquipoAudit.equipo),
               )
               .order_by(models.EquipoAudit.id.desc()))

        if q_text:
            like = f"%{q_text}%"
            qry = qry.filter(or_(
                models.EquipoAudit.action.ilike(like),
                models.EquipoAudit.detail.ilike(like),
                models.EquipoAudit.ip.ilike(like),
                models.EquipoAudit.user_agent.ilike(like),
                Actor.username.ilike(like),
                EquipoAlias.codigo_interno.ilike(like),
                EquipoAlias.serial.ilike(like),
            ))

        total = qry.count()
        audits = qry.offset((page-1)*size).limit(size).all()
        return render_template("audit_equipos_admin.html",
                               audits=audits, page=page, size=size, total=total, q=q_text)
    finally:
        db.close()


@app.route("/equipos/<int:equipo_id>/auditoria") # ---------------------------------- Vista de auditoría de un equipo específico
@login_required
@admin_required
def audit_equipo_show(equipo_id: int):
    db = SessionLocal()
    try:
        e = db.get(Equipo, equipo_id)
        if not e:
            flash("Equipo no encontrado.", "warning")
            return redirect(url_for("equipos_index"))

        page = max(1, int(request.args.get("page", 1)))
        size = min(100, max(10, int(request.args.get("size", 20))))

        qry = (db.query(EquipoAudit)
               .filter(EquipoAudit.equipo_id == equipo_id)
               .options(joinedload(EquipoAudit.actor))
               .order_by(EquipoAudit.id.desc()))

        total = qry.count()
        audits = qry.offset((page-1)*size).limit(size).all()
        return render_template("audit_equipo_list.html",
                               e=e, audits=audits, page=page, size=size, total=total)
    finally:
        db.close()


@app.route("/admin/equipos/eliminados") # ---------------------------------- Vista de equipos eliminados (solo admin)
@login_required
@admin_required
def equipos_eliminados():
    db = SessionLocal()
    try:
        q_text = (request.args.get("q") or "").strip().lower()
        page = max(1, int(request.args.get("page", 1)))
        size = min(100, max(10, int(request.args.get("size", 20))))

        Actor = aliased(models.User)

        qry = (db.query(models.EquipoDeletion)
               .outerjoin(Actor, models.EquipoDeletion.actor)
               .options(joinedload(models.EquipoDeletion.actor))
               .order_by(models.EquipoDeletion.id.desc()))

        if q_text:
            like = f"%{q_text}%"
            qry = qry.filter(or_(
                models.EquipoDeletion.codigo_interno.ilike(like),
                models.EquipoDeletion.serial.ilike(like),
                models.EquipoDeletion.marca.ilike(like),
                models.EquipoDeletion.modelo.ilike(like),
                models.EquipoDeletion.empresa_externa.ilike(like),
                models.EquipoDeletion.responsable_entrega.ilike(like),
                models.EquipoDeletion.estado.ilike(like),
                Actor.username.ilike(like),
            ))

        total = qry.count()
        rows = qry.offset((page-1)*size).limit(size).all()

        return render_template(
            "equipos_deleted.html",
            rows=rows, q=q_text, page=page, size=size, total=total
        )
    finally:
        db.close()


# ========= Notificaciones =========

# -- Notificar a un usuario específico --
def notify_user(db, user_id: int, title: str, body: str | None = None, level: str = "info"):
    n = Notification(user_id=user_id, title=title, body=body, level=level)
    db.add(n)
    db.commit()
    return n
# -- Notificar a todos los administradores --
def notify_admins(db, title: str, body: str | None = None, level: str = "info"):
    from models import User
    admins = db.query(User).filter(User.role == "admin").all()
    for a in admins:
        db.add(Notification(user_id=a.id, title=title, body=body, level=level))
    db.commit()

# ========= Rutas de API de notificaciones =========

@app.route("/api/notifications/unread_count")
@login_required
def api_notifs_unread_count():
    db = SessionLocal()
    try:
        cnt = db.query(Notification).filter(
            Notification.user_id == current_user.id,
            Notification.is_read == 0
        ).count()
        return jsonify({"count": cnt})
    finally:
        db.close()

@app.route("/api/notifications/list")
@login_required
def api_notifs_list():
    db = SessionLocal()
    try:
        rows = (db.query(Notification)
                  .filter(Notification.user_id == current_user.id)
                  .order_by(Notification.created_at.desc())
                  .limit(20).all())
        data = [{
            "id": r.id,
            "title": r.title,
            "body": r.body or "",
            "level": r.level,
            "is_read": bool(r.is_read),
            "created_at": r.created_at.isoformat()
        } for r in rows]
        return jsonify(data)
    finally:
        db.close()

@app.route("/notifications/<int:notif_id>/read", methods=["POST"])
@login_required
def notif_mark_read(notif_id: int):
    db = SessionLocal()
    try:
        n = db.get(Notification, notif_id)
        if not n or n.user_id != current_user.id:
            return ("", 404)
        n.is_read = 1
        db.add(n)
        db.commit()
        return ("", 204)
    finally:
        db.close()

@app.route("/notifications/mark_all_read", methods=["POST"])
@login_required
def notif_mark_all_read():
    db = SessionLocal()
    try:
        # Marcar todas las notificaciones de este usuario como leídas
        (db.query(Notification)
           .filter(
               Notification.user_id == current_user.id,
               Notification.is_read == 0
           )
           .update({Notification.is_read: 1})
        )
        db.commit()

        # Si viene desde AJAX, devolvemos 204 sin redirigir
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return ("", 204)

        flash("Todas tus notificaciones han sido marcadas como leídas.", "info")
        # Volver a la página desde donde vino o a /notificaciones
        return redirect(request.referrer or url_for("notifications_page"))
    finally:
        db.close()




@app.route("/notificaciones")
@login_required
def notifications_page():
    db = SessionLocal()
    try:
        rows = (db.query(Notification)
                  .filter(Notification.user_id == current_user.id)
                  .order_by(Notification.created_at.desc())
                  .limit(100).all())
        return render_template("notifications.html", rows=rows)
    finally:
        db.close()


def _export_equipos_csv(equipos):
    """
    Exporta la lista de equipos a CSV usando los filtros aplicados.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    headers = [
        "Código interno",
        "Tipo equipo",
        "Marca",
        "Modelo",
        "Serial",
        "Empresa",
        "Responsable",
        "Fecha ingreso",
        "Fecha salida",
        "Estado",
    ]
    writer.writerow(headers)

    for e in equipos:
        empresa = e.empresa.nombre if getattr(e, "empresa", None) else ""
        responsable = ""
        if getattr(e, "responsable", None):
            responsable = f"{e.responsable.id_responsable} - {e.responsable.nombre_responsable}"

        fi = e.fecha_ingreso.strftime("%Y-%m-%d") if e.fecha_ingreso else ""
        fs = e.fecha_salida.strftime("%Y-%m-%d") if e.fecha_salida else ""

        writer.writerow([
            e.codigo_interno,
            e.tipo_equipo,
            e.marca or "",
            e.modelo or "",
            e.serial or "",
            empresa,
            responsable,
            fi,
            fs,
            e.estado,
        ])

    csv_data = output.getvalue()
    output.close()

    # BOM para que Excel abra bien UTF-8
    csv_data = "\ufeff" + csv_data

    resp = Response(csv_data, mimetype="text/csv; charset=utf-8")
    resp.headers["Content-Disposition"] = "attachment; filename=equipos_report.csv"
    return resp





def _export_equipos_xlsx(equipos):
    """
    Exporta la lista de equipos a XLSX usando openpyxl.
    """
    wb = Workbook()
    ws = wb.active
    ws.title = "Equipos"

    headers = [
        "Código interno",
        "Tipo equipo",
        "Marca",
        "Modelo",
        "Serial",
        "Empresa",
        "Responsable",
        "Fecha ingreso",
        "Fecha salida",
        "Estado",
    ]
    ws.append(headers)

    for e in equipos:
        empresa = e.empresa.nombre if getattr(e, "empresa", None) else ""
        responsable = ""
        if getattr(e, "responsable", None):
            responsable = f"{e.responsable.id_responsable} - {e.responsable.nombre_responsable}"

        fi = e.fecha_ingreso.strftime("%Y-%m-%d") if e.fecha_ingreso else ""
        fs = e.fecha_salida.strftime("%Y-%m-%d") if e.fecha_salida else ""

        ws.append([
            e.codigo_interno,
            e.tipo_equipo,
            e.marca or "",
            e.modelo or "",
            e.serial or "",
            empresa,
            responsable,
            fi,
            fs,
            e.estado,
        ])

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="equipos_report.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


# ==== Soporte xhtml2pdf: resolver rutas de recursos estáticos ====
def _pdf_link_callback(uri, rel):
    """
    Convierte las rutas de imágenes/CSS usadas en el HTML del PDF
    a paths reales del sistema de archivos para xhtml2pdf.
    """
    # URLs absolutas http/https se dejan tal cual
    if uri.startswith("http://") or uri.startswith("https://"):
        return uri

    # Data-URIs también se dejan como están
    if uri.startswith("data:"):
        return uri

    # Si viene con / (ej: /static/img/logo.png) quitamos la barra inicial
    if uri.startswith("/"):
        uri = uri[1:]

    # Si por cualquier cosa viene con file://, se lo quitamos
    if uri.startswith("file://"):
        uri = uri[7:]

    # Lo resolvemos relativo al root de la app
    path = os.path.join(app.root_path, uri)

    return path



def _export_equipos_pdf(equipos, filtros: dict):
    """
    Genera un PDF con logo USTA, encabezado institucional, nombre de la app
    y paginación, usando los filtros recibidos.
    """
    # --- Normalizar filtros para mostrarlos en texto legible ---
    estado_map = {
        "pendiente": "Pendiente",
        "en_revision": "En revisión",
        "aprobado": "Aprobado",
        "devuelto": "Devuelto",
        "": "Todos",
        None: "Todos",
    }
    tipo_map = {
        "tecnologico": "Tecnológico",
        "biomedico": "Biomédico",
        "": "Todos",
        None: "Todos",
    }

    estado_txt = estado_map.get(filtros.get("estado") or "", "Todos")
    tipo_txt = tipo_map.get(filtros.get("tipo_equipo") or "", "Todos")

    empresa_txt = "Todas"
    if filtros.get("empresa_id"):
        emp_id = filtros["empresa_id"]
        # Intentamos obtener el nombre de la empresa a partir de los equipos filtrados
        emp_nombre = None
        for e in equipos:
            if str(e.empresa_id) == str(emp_id) and getattr(e, "empresa", None):
                emp_nombre = e.empresa.nombre
                break
        empresa_txt = emp_nombre or f"ID {emp_id}"

    filtros_pdf = {
        "fecha_desde": filtros.get("fecha_desde") or "—",
        "fecha_hasta": filtros.get("fecha_hasta") or "—",
        "estado": estado_txt,
        "tipo_equipo": tipo_txt,
        "empresa": empresa_txt,
    }

    # Fecha/hora de generación (simple, sin tz)
    generado = datetime.now().strftime("%d/%m/%Y %H:%M")

        # URL "normal" al logo, igual que en base.html
    logo_url = url_for("static", filename="img/logo.png")

    html = render_template(
        "reportes_pdf.html",
        equipos=equipos,
        filtros=filtros_pdf,
        generado=generado,
        logo_url=logo_url,
    )

    pdf_io = io.BytesIO()
    pisa_status = pisa.CreatePDF(
        html,                 # se puede pasar el string directamente
        dest=pdf_io,
        encoding="utf-8",
        link_callback=_pdf_link_callback,  # resolver /static/...
    )


    if pisa_status.err:
        # Si algo falla, devolvemos el HTML para depuración
        return Response(html, mimetype="text/html; charset=utf-8")

    pdf_io.seek(0)
    return send_file(
        pdf_io,
        as_attachment=True,
        download_name="equipos_report.pdf",
        mimetype="application/pdf"
    )



if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8095)
