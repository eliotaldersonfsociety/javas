const express = require('express');
const { Client } = require('pg'); // Cliente de PostgreSQL
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

// Cargar variables de entorno desde .env
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Configurar Express
app.use(express.json());

// Conexión a la base de datos de Turso
const db = new Client({
  connectionString: process.env.TURSO_CONNECTION_URL,
  ssl: true, // Es probable que necesites habilitar SSL para la conexión
  headers: {
    Authorization: `Bearer ${process.env.TURSO_AUTH_TOKEN}`,
  },
});

db.connect()
  .then(() => console.log('Conexión exitosa a la base de datos de Turso'))
  .catch(err => console.error('Error en la conexión a la base de datos:', err));

// Ruta de login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Faltan credenciales' });
  }

  try {
    // Buscar al usuario en la base de datos
    const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ message: 'Usuario no encontrado' });
    }

    // Comparar la contraseña cifrada con la ingresada
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(400).json({ message: 'Contraseña incorrecta' });
    }

    // Generar JWT
    const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET, {
      expiresIn: '1h', // El token expirará en 1 hora
    });

    res.json({ message: 'Login exitoso', token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Endpoint de prueba para verificar si la API está funcionando
app.get('/api', (req, res) => {
  res.json({ message: 'API funcionando correctamente' });
});

// Endpoint GET adicional para verificar el estado de la API
app.get('/api/status', (req, res) => {
  res.json({ message: 'La API está funcionando correctamente', time: new Date() });
});

// Iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});

module.exports = app;
