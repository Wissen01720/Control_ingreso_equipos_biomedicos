# 🔐 Sistema de Gestión de Equipos y Auditoría

Sistema web desarrollado con Flask para la gestión de equipos, empresas externas y seguimiento de auditoría completo. Incluye autenticación segura, control de acceso basado en roles y registro detallado de todas las operaciones.

## 📋 Características Principales

- ✅ **Autenticación y Autorización**

  - Sistema de login seguro con bcrypt
  - Control de acceso basado en roles (Admin/Usuario)
  - Protección anti-throttling (bloqueo temporal tras intentos fallidos)
  - Gestión de sesiones con Flask-Login

- 📊 **Gestión de Recursos**

  - CRUD completo de equipos
  - Gestión de empresas externas
  - Administración de responsables de entrega
  - Panel de usuarios (solo para administradores)

- 🔍 **Sistema de Auditoría**

  - Registro automático de todas las operaciones (creación, edición, eliminación)
  - Auditoría de usuarios y equipos
  - Historial de eliminaciones con soft delete
  - Exportación de reportes en PDF y Excel

- 🎨 **Interfaz de Usuario**
  - Dashboard interactivo
  - Sistema de notificaciones en tiempo real
  - Diseño responsivo
  - Búsqueda y filtrado avanzado

## 🚀 Tecnologías Utilizadas

### Backend

- **Flask 3.0.3** - Framework web
- **SQLAlchemy 2.0.36** - ORM para base de datos
- **PostgreSQL** - Base de datos (Supabase)
- **Flask-Login** - Gestión de sesiones
- **Flask-WTF** - Formularios y validación
- **bcrypt** - Encriptación de contraseñas

### Frontend

- **HTML5/CSS3**
- **JavaScript**
- **Bootstrap** (vía CDN en templates)

### Reportes

- **xhtml2pdf** - Generación de PDFs
- **openpyxl** - Exportación a Excel

## 📦 Instalación

### Prerrequisitos

- Python 3.8 o superior
- PostgreSQL (o cuenta en Supabase)
- Git

### Pasos de Instalación

1. **Clonar el repositorio**

```bash
git clone <url-del-repositorio>
cd project_131125
```

2. **Crear y activar entorno virtual**

```bash
# Crear entorno virtual
python -m venv .venv

# Activar entorno virtual
# En Windows (PowerShell)
.venv\Scripts\Activate.ps1

# En Linux/Mac
source .venv/bin/activate
```

3. **Instalar dependencias**

```bash
# Actualizar pip
python -m pip install --upgrade pip

# Instalar dependencias del proyecto
pip install -r requirements.txt
```

4. **Configurar variables de entorno**

```bash
# Copiar el archivo de ejemplo
cp .env.example .env

# Editar .env con tus credenciales
```

Variables necesarias en `.env`:

```env
FLASK_SECRET_KEY=tu_clave_secreta_aqui
WTF_CSRF_SECRET_KEY=otra_clave_secreta
DATABASE_URL=postgresql+psycopg://user:password@host:port/database
```

5. **Ejecutar seeds (datos iniciales)**

Ejecutar en este orden:

```bash
# 1. Crear empresas externas
python seed_empresas_extern.py

# 2. Crear responsables de entrega
python seed_resp_ent_empresa.py

# 3. Crear usuario administrador
python manage.py

# 4. Crear equipos (requiere al menos 1 usuario tipo "usuario")
python seed_equipos.py
```

6. **Iniciar la aplicación**

```bash
python app.py
```

La aplicación estará disponible en `http://127.0.0.1:8095`

## 📁 Estructura del Proyecto

```
project_131125/
├── app.py                      # Aplicación principal Flask
├── models.py                   # Modelos de base de datos (SQLAlchemy)
├── forms.py                    # Formularios WTForms
├── manage.py                   # Script de gestión (crear admin)
├── requirements.txt            # Dependencias del proyecto
├── .env                        # Variables de entorno (no incluido en Git)
├── .env.example               # Ejemplo de variables de entorno
├── .gitignore                 # Archivos ignorados por Git
│
├── static/                    # Archivos estáticos
│   ├── css/
│   │   └── custom.css        # Estilos personalizados
│   └── img/                  # Imágenes
│
├── templates/                 # Plantillas HTML
│   ├── base.html             # Template base
│   ├── index.html            # Página principal
│   ├── login.html            # Login
│   ├── dashboard.html        # Panel principal
│   ├── equipos_*.html        # Gestión de equipos
│   ├── empresas_*.html       # Gestión de empresas
│   ├── users_*.html          # Gestión de usuarios
│   ├── audit_*.html          # Vistas de auditoría
│   └── reportes_*.html       # Reportes
│
└── seeds/                     # Scripts de datos iniciales
    ├── seed_empresas_extern.py
    ├── seed_resp_ent_empresa.py
    └── seed_equipos.py
```

## 🔑 Roles y Permisos

### Administrador

- Acceso completo al sistema
- Gestión de usuarios
- Visualización de todas las auditorías
- Exportación de reportes
- CRUD de todos los recursos

### Usuario

- Gestión de equipos propios
- Visualización de auditoría propia
- Edición de perfil
- Exportación de reportes limitada

## 📊 Funcionalidades Clave

### Sistema de Auditoría

Todas las operaciones quedan registradas automáticamente:

- **Creación**: Usuario, timestamp, datos iniciales
- **Modificación**: Usuario, timestamp, datos anteriores y nuevos
- **Eliminación**: Soft delete con registro del responsable

### Seguridad

- Contraseñas encriptadas con bcrypt
- Protección CSRF en todos los formularios
- Control de throttling (bloqueo temporal tras intentos fallidos)
- Validación de datos en servidor y cliente
- Sesiones seguras

### Reportes

- Exportación a PDF con formato personalizado
- Exportación a Excel con filtros
- Reportes de auditoría detallados
- Filtrado por fechas y criterios

## 🛠️ Scripts Útiles

### Crear usuario administrador

```bash
python manage.py
```

### Verificar conexión a Supabase

```bash
python check_supabase_full.py
python check_supabase_users.py
```

### Poblar base de datos

```bash
python seed_empresas_extern.py
python seed_resp_ent_empresa.py
python seed_equipos.py
```

## 🐛 Solución de Problemas

### Error de conexión a base de datos

Verificar que las variables de entorno en `.env` sean correctas:

```bash
python connect_supabase.py
```

### Error de dependencias

```bash
pip install --upgrade -r requirements.txt
```

### Error de permisos en PowerShell

```bash
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## 📝 Notas de Desarrollo

- El proyecto usa **Supabase** como base de datos PostgreSQL
- Puerto por defecto: **8095**
- El throttling bloquea por **60 segundos** después de **2 intentos fallidos**
- Todas las fechas se almacenan en UTC

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto fue desarrollado con fines académicos para la Universidad.

## 👥 Autores

- Proyecto desarrollado para el curso de Seguridad - Universidad

## 📞 Soporte

Para reportar problemas o solicitar características, por favor abre un issue en el repositorio.

---

⭐ Si este proyecto te fue útil, considera darle una estrella en GitHub
