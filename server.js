// backend/server.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json());

const isSslRequired = process.env.DATABASE_URL.includes('ssl-mode=REQUIRED');
const dbConfig = {
    uri: process.env.DATABASE_URL,
    ...(isSslRequired && {
        ssl: { ca: fs.readFileSync(path.join(__dirname, 'ca.pem')) }
    })
};
const pool = mysql.createPool(dbConfig);

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// --- RUTAS DE LA API ---

// [PÚBLICA] Ruta de autenticación
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        if (users.length === 0) return res.status(401).json({ message: 'Credenciales incorrectas' });

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(401).json({ message: 'Credenciales incorrectas' });

        const payload = { id: user.id, username: user.username };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ token });
    } catch (error) {
        console.error("Error en login:", error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});


app.get('/api/usos-cfdi', async (req, res) => {
    const [rows] = await pool.query('SELECT id, clave, descripcion FROM usos_cfdi ORDER BY clave');
    res.json(rows);
});
app.get('/api/formas-pago', async (req, res) => {
    const [rows] = await pool.query('SELECT id, clave, descripcion FROM formas_pago ORDER BY clave');
    res.json(rows);
});

app.get('/api/client-data/:slug', async (req, res) => {
    try {
        const { slug } = req.params;
        const [datosFiscales] = await pool.query('SELECT * FROM datos_fiscales WHERE id = 1');
        if (datosFiscales.length === 0) return res.status(404).json({ message: 'Datos fiscales no encontrados' });

        const [clientData] = await pool.query(`
            SELECT
                c.name,
                c.attach_pdf, -- <-- 1. Obtenemos el nuevo campo de la base de datos.
                uc.clave       as uso_cfdi_clave,
                uc.descripcion as uso_cfdi_descripcion,
                fp.clave       as forma_pago_clave,
                fp.descripcion as forma_pago_descripcion
            FROM clients c
            LEFT JOIN usos_cfdi uc ON c.default_uso_cfdi_id = uc.id
            LEFT JOIN formas_pago fp ON c.default_forma_pago_id = fp.id
            WHERE c.slug = ?`, [slug]);

        if (clientData.length === 0) return res.status(404).json({ message: 'Cliente no encontrado' });
        res.json({ datosFijos: datosFiscales[0], cliente: clientData[0] });
    } catch (error) {
        console.error("Error fetching client data:", error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});


// <-- 2. ¡NUEVO ENDPOINT PARA DESCARGAR EL PDF! ---
// Esta ruta es pública para que cualquiera con el enlace pueda descargar el archivo.
app.get('/api/download/constancia', (req, res) => {
    const filePath = path.join(__dirname, 'assets', 'Constancia_Situacion_Fiscal.pdf');

    // res.download() se encarga de todo: establece las cabeceras correctas
    // para que el navegador inicie una descarga en lugar de mostrar el archivo.
    res.download(filePath, 'CONSTANCIA_FISCAL_25082025.pdf', (err) => {
        if (err) {
            // Maneja el error si el archivo no se encuentra o no se puede leer.
            console.error("Error al descargar el archivo:", err);
            res.status(404).send('Archivo no encontrado.');
        }
    });
});

// --- RUTAS DE ADMINISTRACIÓN [PROTEGIDAS] ---
app.get('/api/admin/clients', authenticateToken, async (req, res) => {
    const [clients] = await pool.query('SELECT id, name, slug FROM clients ORDER BY created_at DESC');
    res.json(clients);
});

app.post('/api/admin/clients', authenticateToken, async (req, res) => {
    // <-- 3. Recibimos el nuevo campo del frontend.
    const { name, usoCfdiId, formaPagoId, attachPdf } = req.body;

    if (!name || !usoCfdiId || !formaPagoId) {
        return res.status(400).json({ message: 'Todos los campos son requeridos.' });
    }
    const slug = uuidv4();
    try {
        // <-- 4. Insertamos el nuevo valor en la base de datos.
        await pool.query(
            'INSERT INTO clients (name, slug, default_uso_cfdi_id, default_forma_pago_id, attach_pdf) VALUES (?, ?, ?, ?, ?)',
            [name, slug, usoCfdiId, formaPagoId, attachPdf || false] // Aseguramos que sea un booleano.
        );
        res.status(201).json({ message: 'Cliente creado', slug });
    } catch (error) {
        console.error("Error creating client:", error);
        res.status(500).json({ message: 'Error al crear el cliente' });
    }
});

app.delete('/api/admin/clients/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM clients WHERE id = ?', [id]);
        if (result.affectedRows > 0) res.json({ message: 'Cliente eliminado' });
        else res.status(404).json({ message: 'Cliente no encontrado' });
    } catch (error) {
        console.error("Error deleting client:", error);
        res.status(500).json({ message: 'Error al eliminar' });
    }
});
// --- Iniciar servidor ---
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`🚀 Servidor API corriendo en http://localhost:${PORT}`);
});