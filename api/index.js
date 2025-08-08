/ api/index.js - Archivo principal para Vercel
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');

const app = express();

// Variables de entorno
const JWT_SECRET = process.env.JWT_SECRET || 'tu_secreto_muy_seguro_aqui';

// Middleware
app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:8000', 'https://tu-frontend.vercel.app'],
    credentials: true
}));
app.use(express.json());

// Configuración de la base de datos para Vercel
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    ssl: process.env.NODE_ENV === 'production' ? {
        rejectUnauthorized: false
    } : false,
    connectTimeout: 60000,
    acquireTimeout: 60000,
    timeout: 60000
};

// Pool de conexiones (reutilizable)
let pool;

const getConnection = async () => {
    if (!pool) {
        pool = mysql.createPool({
            ...dbConfig,
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0
        });
    }
    return pool;
};

// Middleware de autenticación
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Token de acceso requerido' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const connection = await getConnection();
        const [rows] = await connection.execute(
            'SELECT id, nombre_completo, email, dni FROM usuarios WHERE id = ?',
            [decoded.userId]
        );

        if (rows.length === 0) {
            return res.status(403).json({ message: 'Token inválido' });
        }

        req.user = rows[0];
        next();
    } catch (error) {
        console.error('Error en authenticateToken:', error);
        return res.status(403).json({ message: 'Token inválido' });
    }
};

// === RUTAS DE AUTENTICACIÓN ===

// Registro de usuario
app.post('/api/auth/register', async (req, res) => {
    let connection;
    try {
        const { nombre_completo, dni, email, password } = req.body;

        // Validaciones básicas
        if (!nombre_completo || !dni || !email || !password) {
            return res.status(400).json({ message: 'Todos los campos son obligatorios' });
        }

        if (password.length < 6) {
            return res.status(400).json({ message: 'La contraseña debe tener al menos 6 caracteres' });
        }

        connection = await getConnection();

        // Verificar si el usuario ya existe
        const [existingUsers] = await connection.execute(
            'SELECT id FROM usuarios WHERE email = ? OR dni = ?',
            [email, dni]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({ 
                message: 'Ya existe un usuario con ese email o DNI' 
            });
        }

        // Encriptar contraseña
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insertar nuevo usuario
        const [result] = await connection.execute(
            'INSERT INTO usuarios (nombre_completo, dni, email, password, created_at) VALUES (?, ?, ?, ?, NOW())',
            [nombre_completo, dni, email, hashedPassword]
        );

        res.status(201).json({
            message: 'Usuario creado exitosamente',
            userId: result.insertId
        });

    } catch (error) {
        console.error('Error en registro:', error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});

// Login de usuario
app.post('/api/auth/login', async (req, res) => {
    let connection;
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email y contraseña son obligatorios' });
        }

        connection = await getConnection();

        // Buscar usuario
        const [rows] = await connection.execute(
            'SELECT id, nombre_completo, email, dni, password FROM usuarios WHERE email = ?',
            [email]
        );

        if (rows.length === 0) {
            return res.status(401).json({ message: 'Credenciales inválidas' });
        }

        const user = rows[0];

        // Verificar contraseña
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Credenciales inválidas' });
        }

        // Generar token JWT
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Remover contraseña de la respuesta
        delete user.password;

        res.json({
            message: 'Login exitoso',
            token,
            user
        });

    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});

// === RUTAS DE PRODUCTOS ===

// Obtener todos los productos
app.get('/api/products', authenticateToken, async (req, res) => {
    let connection;
    try {
        connection = await getConnection();
        const [rows] = await connection.execute(
            'SELECT * FROM productos ORDER BY created_at DESC'
        );

        res.json({
            products: rows
        });

    } catch (error) {
        console.error('Error al obtener productos:', error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});

// Crear nuevo producto
app.post('/api/products', authenticateToken, async (req, res) => {
    let connection;
    try {
        const { name, price, category, stock, description, image } = req.body;

        // Validaciones
        if (!name || !price || !category || stock === undefined) {
            return res.status(400).json({ 
                message: 'Nombre, precio, categoría y stock son obligatorios' 
            });
        }

        if (price < 0 || stock < 0) {
            return res.status(400).json({ 
                message: 'El precio y stock deben ser valores positivos' 
            });
        }

        connection = await getConnection();

        // Insertar producto
        const [result] = await connection.execute(
            'INSERT INTO productos (name, price, category, stock, description, image, user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())',
            [name, price, category, stock, description || '', image || '', req.user.id]
        );

        // Obtener el producto creado
        const [newProduct] = await connection.execute(
            'SELECT * FROM productos WHERE id = ?',
            [result.insertId]
        );

        res.status(201).json({
            message: 'Producto creado exitosamente',
            product: newProduct[0]
        });

    } catch (error) {
        console.error('Error al crear producto:', error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});

// Actualizar producto
app.put('/api/products/:id', authenticateToken, async (req, res) => {
    let connection;
    try {
        const productId = req.params.id;
        const { name, price, category, stock, description, image } = req.body;

        // Validaciones
        if (!name || !price || !category || stock === undefined) {
            return res.status(400).json({ 
                message: 'Nombre, precio, categoría y stock son obligatorios' 
            });
        }

        if (price < 0 || stock < 0) {
            return res.status(400).json({ 
                message: 'El precio y stock deben ser valores positivos' 
            });
        }

        connection = await getConnection();

        // Verificar si el producto existe
        const [existingProduct] = await connection.execute(
            'SELECT id FROM productos WHERE id = ?',
            [productId]
        );

        if (existingProduct.length === 0) {
            return res.status(404).json({ message: 'Producto no encontrado' });
        }

        // Actualizar producto
        await connection.execute(
            'UPDATE productos SET name = ?, price = ?, category = ?, stock = ?, description = ?, image = ? WHERE id = ?',
            [name, price, category, stock, description || '', image || '', productId]
        );

        // Obtener producto actualizado
        const [updatedProduct] = await connection.execute(
            'SELECT * FROM productos WHERE id = ?',
            [productId]
        );

        res.json({
            message: 'Producto actualizado exitosamente',
            product: updatedProduct[0]
        });

    } catch (error) {
        console.error('Error al actualizar producto:', error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});

// Eliminar producto
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    let connection;
    try {
        const productId = req.params.id;

        connection = await getConnection();

        // Verificar si el producto existe
        const [existingProduct] = await connection.execute(
            'SELECT id FROM productos WHERE id = ?',
            [productId]
        );

        if (existingProduct.length === 0) {
            return res.status(404).json({ message: 'Producto no encontrado' });
        }

        // Eliminar producto
        await connection.execute(
            'DELETE FROM productos WHERE id = ?',
            [productId]
        );

        res.json({ message: 'Producto eliminado exitosamente' });

    } catch (error) {
        console.error('Error al eliminar producto:', error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});

// === RUTAS DE USUARIOS ===

// Obtener todos los usuarios
app.get('/api/users', authenticateToken, async (req, res) => {
    let connection;
    try {
        connection = await getConnection();
        const [rows] = await connection.execute(
            'SELECT id, nombre_completo, dni, email, created_at FROM usuarios ORDER BY created_at DESC'
        );

        res.json({
            users: rows
        });

    } catch (error) {
        console.error('Error al obtener usuarios:', error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});

// Ruta de prueba
app.get('/api/health', (req, res) => {
    res.json({ 
        message: 'Servidor funcionando correctamente en Vercel',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV
    });
});

// Ruta raíz
app.get('/api', (req, res) => {
    res.json({
        message: '🏪 API Sistema de Gestión de Productos',
        version: '1.0.0',
        endpoints: {
            auth: {
                register: 'POST /api/auth/register',
                login: 'POST /api/auth/login'
            },
            products: {
                list: 'GET /api/products',
                create: 'POST /api/products',
                update: 'PUT /api/products/:id',
                delete: 'DELETE /api/products/:id'
            },
            users: {
                list: 'GET /api/users'
            },
            health: 'GET /api/health'
        }
    });
});

// Manejo de errores globales
app.use((err, req, res, next) => {
    console.error('Error no manejado:', err);
    res.status(500).json({ 
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// Para rutas no encontradas
app.use((req, res) => {
    res.status(404).json({ 
        message: 'Ruta no encontrada',
        availableRoutes: ['/api', '/api/health', '/api/auth/login', '/api/auth/register', '/api/products', '/api/users']
    });
});

module.exports = app;
