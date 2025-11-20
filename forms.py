# forms.py
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.fields import DateTimeLocalField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, Optional, EqualTo, ValidationError, Regexp



class LoginForm(FlaskForm):
    username = StringField(
        "Usuario",
        validators=[DataRequired("El usuario es obligatorio."), Length(min=3, max=50)]
    )
    password = PasswordField(
        "Contraseña",
        validators=[DataRequired("La contraseña es obligatoria.")]
    )
    recaptcha = RecaptchaField()
    submit = SubmitField("Ingresar")


class UserCreateForm(FlaskForm):
    username = StringField("Usuario", validators=[DataRequired(), Length(min=3, max=50)])
    identificacion = StringField(
        "Identificación",
        validators=[
            DataRequired(),
            Length(max=30),
            Regexp(r"^[A-Za-z0-9\-_.]+$", message="Solo letras, números y los caracteres - _ .")
        ]
    )
    email = StringField("Correo", validators=[DataRequired(), Email(), Length(max=120)])
    role = SelectField("Rol", choices=[("admin", "admin"), ("usuario", "usuario")], validators=[DataRequired()])
    password = PasswordField("Contraseña", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Crear")


class UserEditForm(FlaskForm):
    username = StringField("Usuario", validators=[DataRequired(), Length(min=3, max=50)])
    identificacion = StringField(
        "Identificación",
        validators=[
            DataRequired(),
            Length(max=30),
            Regexp(r"^[A-Za-z0-9\-_.]+$", message="Solo letras, números y los caracteres - _ .")
        ]
    )
    email = StringField("Correo", validators=[DataRequired(), Email(), Length(max=120)])
    role = SelectField("Rol", choices=[("admin", "admin"), ("usuario", "usuario")], validators=[DataRequired()])
    # Password opcional al editar; si lo dejas vacío no cambia
    password = PasswordField("Nueva contraseña (opcional)", validators=[Optional(), Length(min=6)])
    submit = SubmitField("Guardar cambios")

class UserSelfEditForm(FlaskForm):
    """Edición de perfil por el propio usuario (sin permitir el cambio de rol)."""
    username = StringField("Usuario", validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField("Correo", validators=[DataRequired(), Email(), Length(max=120)])

    # Cambios sensibles
    current_password = PasswordField("Contraseña actual (requerida si cambias correo o contraseña)", validators=[Optional()])
    new_password = PasswordField("Nueva contraseña (opcional)", validators=[Optional(), Length(min=6, message="Mínimo 6 caracteres.")])
    confirm_new_password = PasswordField("Confirmar nueva contraseña",validators=[Optional(), EqualTo("new_password", message="Las contraseñas no coinciden.")])
    submit = SubmitField("Guardar cambios")


class EquipoForm(FlaskForm):
    # Básicos
    codigo_interno = StringField("Código interno", validators=[DataRequired(), Length(max=50)])
    tipo_equipo = SelectField(
        "Tipo de equipo",
        choices=[("tecnologico", "Tecnológico"), ("biomedico", "Biomédico")],
        validators=[DataRequired()]
    )
    marca = StringField("Marca", validators=[Optional(), Length(max=100)])
    modelo = StringField("Modelo", validators=[Optional(), Length(max=100)])
    serial = StringField("Serial", validators=[Optional(), Length(max=100)])

    empresa_id = SelectField(
        "Empresa externa",
        coerce=int,
        validators=[DataRequired(message="Debes seleccionar la empresa externa.")]
    )

    responsable_id = SelectField(
        "Responsable entrega",
        coerce=int,
        validators=[DataRequired(message="Debes seleccionar el responsable de entrega.")]
    )



    # Fechas
    fecha_ingreso = DateTimeLocalField(
        "Fecha ingreso",
        format="%Y-%m-%dT%H:%M",
        validators=[DataRequired()]
    )
    fecha_salida = DateTimeLocalField(
        "Fecha salida",
        format="%Y-%m-%dT%H:%M",
        validators=[Optional()]
    )

    # Estado
    estado = SelectField(
        "Estado",
        choices=[
            ("pendiente", "pendiente"),
            ("en_revision", "en revisión"),
            ("aprobado", "aprobado"),
            ("devuelto", "devuelto"),
        ],
        validators=[DataRequired()]
    )

    #  Obligatorio: guarda el users.id
    autorizado_por = SelectField(
        "Autorizado por",
        coerce=int,  # muy importante: convierte el valor del select a int
        validators=[DataRequired(message="Debes seleccionar quién autoriza.")]
    )


    observaciones = TextAreaField(
        "Observaciones",
        validators=[Optional(), Length(max=5000)]
    )

    submit = SubmitField("Guardar")

    # flag para saber si es creación o edición
    def __init__(self, *args, is_create: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.is_create = is_create

    def validate(self, **kwargs):
        ok = super().validate(**kwargs)
        if not ok:
            return False

        est = (self.estado.data or "").strip()
        fi = self.fecha_ingreso.data
        fs = self.fecha_salida.data

        # 1) No permitir devuelto en creación
        if self.is_create and est == "devuelto":
            self.estado.errors.append(
                "No puedes registrar un equipo directamente como 'devuelto'."
            )
            return False

        # 2) Reglas por estado
        if est in ("pendiente", "en_revision"):
            if fs is not None:
                self.fecha_salida.errors.append(
                    "Con estado pendiente/en_revision no se permite fecha de salida."
                )
                return False

        if est == "aprobado":
            # salida es opcional, pero si viene debe ser ≥ ingreso
            if fs is not None and fi and fs < fi:
                self.fecha_salida.errors.append(
                    "La fecha de salida no puede ser menor a la fecha de ingreso."
                )
                return False

        if est == "devuelto":
            # en edición: salida obligatoria y ≥ ingreso
            if fs is None:
                self.fecha_salida.errors.append(
                    "Para marcar como devuelto debes registrar la fecha de salida."
                )
                return False
            if fi and fs < fi:
                self.fecha_salida.errors.append(
                    "La fecha de salida no puede ser menor a la fecha de ingreso."
                )
                return False

        return True

class EmpresaExternaForm(FlaskForm):
    identificacion = StringField(
        "Identificación (NIT / código)",
        validators=[
            DataRequired(),
            Length(max=30),
            Regexp(
                r"^[A-Za-z0-9\-_.]+$",
                message="Solo letras, números y los caracteres - _ ."
            )
        ]
    )
    nombre = StringField(
        "Nombre / razón social",
        validators=[DataRequired(), Length(max=150)]
    )
    submit = SubmitField("Guardar")


class ResponsableEntregaForm(FlaskForm):
    id_responsable = StringField(
        "ID responsable (cédula / código)",
        validators=[
            DataRequired(),
            Length(max=30),
            Regexp(
                r"^[A-Za-z0-9\-_.]+$",
                message="Solo letras, números y los caracteres - _ ."
            )
        ]
    )
    nombre_responsable = StringField(
        "Nombre responsable",
        validators=[DataRequired(), Length(max=150)]
    )
    correo_responsable = StringField(
        "Correo responsable",
        validators=[DataRequired(), Email(), Length(max=150)]
    )

    empresa_id = SelectField(
        "Empresa externa",
        coerce=int,
        validators=[DataRequired(message="Debes seleccionar la empresa externa.")]
    )

    submit = SubmitField("Guardar")
