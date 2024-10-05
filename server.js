const cors = require('cors');

app.use(cors({
  origin: 'https://shop-react-jbg3.onrender.com', // ระบุโดเมนของ frontend
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();

const pool = new Pool({
  host: 'dpg-crsmt168ii6s73ef22dg-a.singapore-postgres.render.com',
  user: 'root',
  password: '15sdaU7JqCQyw5JrkBAwb4QxfVGExwEY',
  database: 'shop_backend',
  port: 5432,
  ssl: {
    rejectUnauthorized: false
  }
});

pool.connect()
  .then(() => {
    console.log('Connected to PostgreSQL!');
  })
  .catch(err => {
    console.error('Connection error', err.stack);
  });


app.use(express.json());
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter: (req, file, cb) => {
    const fileTypes = /jpeg|jpg|png|gif/;
    const mimetype = fileTypes.test(file.mimetype);
    const extname = fileTypes.test(path.extname(file.originalname).toLowerCase());

    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('Error: File upload only supports the following filetypes - ' + fileTypes));
  }
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ message: err.message });
  } else if (err) {
    return res.status(400).json({ message: err.message });
  }
  next();
});


app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);

  pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword], (err, result) => {
    if (err) return res.status(500).send(err);
    res.status(201).json({ message: 'User registered' });
  });
});

app.post('/login', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://shop-react-jbg3.onrender.com');
  const { username, password } = req.body;

  pool.query('SELECT * FROM users WHERE username = $1', [username], (err, results) => {
    if (err) return res.status(500).send(err);
    if (results.length === 0) return res.status(404).json({ message: 'User not found' });

    const user = results[0];
    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, role: user.role, name: username, id: user.id });
  });
});

const isAdmin = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(403);

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.sendStatus(403);
    if (decoded.role !== 'admin') return res.sendStatus(403);
    next();
  });
};

app.post('/products', upload.single('prod_image'), isAdmin, (req, res) => {
  const { prod_name, prod_desc, prod_price, prod_ctgr } = req.body;
  const prod_image = req.file?.buffer;

  console.log('Received product:', { prod_name, prod_desc, prod_price, prod_ctgr, prod_image });

  if (!prod_name || !prod_desc || !prod_price || !prod_ctgr || !prod_image) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  pool.query(
    'INSERT INTO products (prod_name, prod_desc, prod_price, prod_ctgr, prod_image) VALUES ($1, $2, $3, $4, $5)',
    [prod_name, prod_desc, prod_price, prod_ctgr, prod_image],
    (err, result) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ message: 'Database error', error: err });
      }
      res.status(201).json({ message: 'Product added successfully' });
    }
  );
});

app.get('/GetProduct', (req, res) => {
  pool.query('SELECT id, prod_name, prod_price, prod_image FROM products', (err, results) => {
    if (err) return res.status(500).send(err);

    if (Array.isArray(results)) {
      const products = results.rows.map(product => ({
        ...product,
        prod_image: product.prod_image.toString('base64') // Convert BLOB to base64
      }));
    } else {
      console.error('Expected results to be an array, but got:', results);
    }


    res.json(products);
  });
});

app.get('/searchProducts', (req, res) => {
  const { name = '', category = '' } = req.query;

  const sql = `
    SELECT id, prod_name, prod_price, prod_image 
    FROM products 
    WHERE prod_name LIKE $1 AND prod_ctgr LIKE $2
  `;

  pool.query(sql, [`%${name}%`, `%${category}%`], (err, results) => {
    if (err) return res.status(500).send(err);

    const products = results.rows.map(product => ({
      ...product,
      prod_image: product.prod_image.toString('base64'), // Convert BLOB to base64
    }));

    res.json(products);
  });
});

app.post('/addToBasket', (req, res) => {
  const { userId, productId, quantity } = req.body;

  console.log('Received request to add to basket:', { userId, productId, quantity });

  // Check if the product already exists in the user's basket
  pool.query(
    'SELECT * FROM basket WHERE user_id = $1 AND product_id = $2',
    [userId, productId],
    (err, results) => {
      if (err) {
        console.error('Error selecting from basket:', err);
        return res.status(500).send(err);
      }

      if (results.length > 0) {
        // Update the existing quantity
        pool.query(
          'UPDATE basket SET quantity = quantity + $1 WHERE user_id = $2 AND product_id = $3',
          [quantity, userId, productId],
          (err, result) => {
            if (err) {
              console.error('Error updating basket:', err);
              return res.status(500).send(err);
            }
            res.json({ message: 'Basket updated successfully' });
          }
        );
      } else {
        // Add a new entry to the basket
        pool.query(
          'INSERT INTO basket (user_id, product_id, quantity) VALUES ($1, $2, $3)',
          [userId, productId, quantity],
          (err, result) => {
            if (err) {
              console.error('Error inserting into basket:', err);
              return res.status(500).send(err);
            }
            res.json({ message: 'Product added to basket successfully' });
          }
        );
      }
    }
  );
});

app.get('/getBasketItems', (req, res) => {
  const { userId } = req.query;

  pool.query(
    `SELECT products.id, products.prod_name, products.prod_price, products.prod_image, basket.quantity 
     FROM basket 
     JOIN products ON basket.product_id = products.id 
     WHERE basket.user_id = $1`,
    [userId],
    (err, results) => {
      if (err) return res.status(500).send(err);

      const basketItems = results.map(item => ({
        ...item,
        prod_image: item.prod_image.toString('base64')
      }));

      res.json(basketItems);
    }
  );
});

app.delete('/removeFromBasket', (req, res) => {
  const { userId, productId } = req.query;

  console.log('user: ', userId, 'prod: ', productId);
  pool.query('DELETE FROM basket WHERE user_id = $1 AND product_id = $2', [userId, productId], (err) => {
    if (err) return res.status(500).send(err);
    res.json({ message: 'Item removed from basket' });
  });
});

app.get('/GetProductById', (req, res) => {
  const { id } = req.query;

  pool.query('SELECT * FROM products WHERE id = $1', [id], (err, results) => {
    if (err) return res.status(500).send(err);
    const product = results[0];
    if (product) {
      product.prod_image = product.prod_image.toString('base64'); // แปลง BLOB เป็น base64
      res.json(product);
    } else {
      res.status(404).send('Product not found');
    }
  });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
