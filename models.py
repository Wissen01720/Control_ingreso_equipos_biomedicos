# models.py
from flask_login import UserMixin
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import CheckConstraint, String, Integer, Enum, Enum as SAEnum, Text, UniqueConstraint
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Integer, String, DateTime, func
from datetime import datetime
from sqlalchemy import Text, ForeignKey
from sqlalchemy.orm import relationship

from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship, backref



class Base(DeclarativeBase):  # para heredar en los modelos, es decir para hacer el mapeo ORM
    pass # pass es para indicar que no hay nada más que hacer aquí, es un marcador de posición.

class User(Base, UserMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    #  identificación alfanumérica única
    identificacion: Mapped[str] = mapped_column(
        String(30),
        unique=True,
        nullable=False,
        index=True
    )
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        Enum("admin", "usuario", name="role_enum"),
        default="usuario",
        nullable=False
    )

    # helpers
    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class AuthThrottle(Base):
    __tablename__ = "auth_throttle"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    fail_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_fail_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )


class UserAudit(Base):
    __tablename__ = "user_audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    actor_user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
        nullable=True
    )
    action: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
        nullable=False
    )

    user = relationship("User", foreign_keys=[user_id])
    actor = relationship("User", foreign_keys=[actor_user_id])


class UserDeletion(Base):
    __tablename__ = "user_deletions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Identidad del eliminado (snapshot)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    identificacion: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(20), nullable=False)

    # Actor (quien eliminó)
    actor_user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True
    )
    actor = relationship("User", foreign_keys=[actor_user_id])

    # Metadatos
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    deleted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
        nullable=False
    )


# ================== NUEVAS TABLAS: EMPRESA + RESPONSABLE ================== #

class EmpresaExterna(Base):
    __tablename__ = "empresas_externas"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Identificación de la empresa (NIT/código), única y manual
    identificacion: Mapped[str] = mapped_column(
        String(30),
        unique=True,
        nullable=False,
        index=True
    )

    # Nombre / razón social
    nombre: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
        index=True
    )

    # Relación inversa: una empresa puede tener varios equipos
    equipos = relationship("Equipo", back_populates="empresa")


class ResponsableEntrega(Base):
    __tablename__ = "responsables_entrega"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # ID manual del responsable (cédula / código interno), única
    id_responsable: Mapped[str] = mapped_column(
        String(30),
        unique=True,
        nullable=False,
        index=True
    )

    nombre_responsable: Mapped[str] = mapped_column(
        String(150),
        nullable=False
    )

    correo_responsable: Mapped[str] = mapped_column(
        String(150),
        nullable=False
    )

    # FK a EmpresaExterna
    empresa_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("empresas_externas.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    empresa = relationship("EmpresaExterna")
    equipos = relationship("Equipo", back_populates="responsable")


# ================== EQUIPOS ================== #

class Equipo(Base):
    __tablename__ = "equipos"

    __table_args__ = (
        UniqueConstraint("serial", name="uq_equipos_serial"),
        CheckConstraint(
            """
            (
                estado IN ('pendiente','en_revision')
                AND fecha_salida IS NULL
            )
            OR
            (
                estado = 'aprobado'
                AND (fecha_salida IS NULL OR fecha_ingreso <= fecha_salida)
            )
            OR
            (
                estado = 'devuelto'
                AND fecha_salida IS NOT NULL
                AND fecha_ingreso <= fecha_salida
            )
            """,
            name="ck_equipos_estado_fecha"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    codigo_interno: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    tipo_equipo: Mapped[str] = mapped_column(
        SAEnum("tecnologico", "biomedico", name="tipo_equipo_enum"),
        nullable=False,
        index=True
    )
    marca: Mapped[str | None] = mapped_column(String(100))
    modelo: Mapped[str | None] = mapped_column(String(100))
    serial: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)

    # 🔴 AHORA: FKs en lugar de texto suelto
    empresa_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("empresas_externas.id", ondelete="RESTRICT"),
        nullable=False,
        index=True
    )
    responsable_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("responsables_entrega.id", ondelete="RESTRICT"),
        nullable=False,
        index=True
    )

    fecha_ingreso: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
        nullable=False
    )
    fecha_salida: Mapped[datetime | None] = mapped_column(DateTime(timezone=False))

    estado: Mapped[str] = mapped_column(
        SAEnum("pendiente", "en_revision", "aprobado", "devuelto", name="estado_equipo_enum"),
        nullable=False,
        default="pendiente",
        server_default="pendiente",
        index=True
    )

    observaciones: Mapped[str | None] = mapped_column(Text)

    # FK a users.id (autorizador)
    autorizado_por: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    autorizador = relationship("User", foreign_keys=[autorizado_por])

    # Relaciones a empresa y responsable
    empresa = relationship("EmpresaExterna", back_populates="equipos")
    responsable = relationship("ResponsableEntrega", back_populates="equipos")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )


class EquipoAudit(Base):
    __tablename__ = "equipo_audit"

    id = Column(Integer, primary_key=True)
    equipo_id = Column(Integer, ForeignKey("equipos.id", ondelete="CASCADE"), nullable=False)
    actor_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    action = Column(String(50), nullable=False)
    detail = Column(Text, nullable=True)
    ip = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    equipo = relationship(
        "Equipo",
        backref=backref("audits", passive_deletes=True)
    )
    actor = relationship("User", backref="equipo_audits", foreign_keys=[actor_user_id])


class EquipoDeletion(Base):
    __tablename__ = "equipos_deletions"

    id = Column(Integer, primary_key=True)
    equipo_id = Column(Integer, index=True)   # ID que tenía el equipo (no FK)
    codigo_interno = Column(String(100))
    tipo_equipo = Column(String(50))
    marca = Column(String(100))
    modelo = Column(String(100))
    serial = Column(String(120))

    # 👇 Aquí mantenemos texto plano como snapshot
    empresa_externa = Column(String(120))
    responsable_entrega = Column(String(120))

    estado = Column(String(50))
    fecha_ingreso = Column(DateTime(timezone=True))
    fecha_salida = Column(DateTime(timezone=True))
    autorizado_por = Column(Integer)  # snapshot del users.id que autorizaba
    observaciones = Column(Text)

    actor_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    ip = Column(String(45))
    user_agent = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    actor = relationship("User", passive_deletes=True)


# ================== NOTIFICACIONES ================== #

class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )
    title: Mapped[str] = mapped_column(String(120), nullable=False)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    level: Mapped[str] = mapped_column(
        SAEnum("info", "success", "warning", "danger", name="notif_level_enum"),
        nullable=False,
        server_default="info"
    )
    is_read: Mapped[bool] = mapped_column(Integer, nullable=False, server_default="0")  # 0/1
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
        nullable=False
    )

    user = relationship("User")