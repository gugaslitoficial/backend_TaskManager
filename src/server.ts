import express, { Request, Response, NextFunction } from 'express';
import mysql from 'mysql2';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';  
import bcrypt from 'bcryptjs';
import cors from 'cors';
import dotenv from 'dotenv';
import multer from 'multer';

// Carregar variáveis de ambiente
dotenv.config();

// Extensão direta da interface Request
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: number;
        email: string;
      };
    }
  }
}

// Middleware para verificar o token JWT
function authenticateToken(req: Request, res: Response, next: NextFunction) {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Token não fornecido' });

    jwt.verify(token, secretKey || '', (err: any, user: any) => {
        if (err) return res.status(403).json({ message: 'Token inválido ou expirado' });

        req.user = user as { id: number; email: string };
        next();
    });
}

// Configurações
const app = express();
const port = process.env.PORT;
const secretKey = process.env.SECRET_KEY;

if (!secretKey) {
    throw new Error('Chave secreta não definida nas variáveis de ambiente.');
}

app.use(cors({
    origin: ['https://frontend-task-manager-three.vercel.app/', 'https://localhost:3000']
}));  

// Conexão com o banco de dados
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) {
        console.error('Erro ao conectar ao banco de dados:', err);
        return process.exit(1);
    }
    console.log('Conectado ao banco de dados MySQL');
});

// Middleware
app.use(bodyParser.json());

// Interface para o usuário
interface User {
    id: number;
    username: string;
    email: string;
    password: string;
}

// Rota de Registro
app.post('/api/register', async (req: Request, res: Response) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
        db.query(query, [username, email, hashedPassword], (error) => {
            if (error) {
                return res.status(500).json({ message: 'Erro ao registrar usuário.' });
            }
            res.status(201).json({ message: 'Cadastro realizado com sucesso!' });
        });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao registrar usuário.' });
    }
});

// Rota de Login
app.post('/api/login', async (req: Request, res: Response) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
    }

    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], async (error, results: mysql.RowDataPacket[]) => {
        if (error) {
            console.error('Erro ao processar login:', error);
            return res.status(500).json({ message: 'Erro ao processar login.' });
        }

        const users = results as User[];

        if (users.length === 0) {
            return res.status(401).json({ message: 'Credenciais inválidas.' });
        }

        const user = users[0];
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return res.status(401).json({ message: 'Credenciais inválidas.' });
        }

        // Geração do token JWT
        const token = jwt.sign({ id: user.id, email: user.email }, secretKey, { expiresIn: '1h' });
        res.status(200).json({ accessToken: token });
    });
});

// => Rota Inicial
// => (Return) Hello World - message
app.get('/', (_req, res) => { return res.status(200).send('Hello World!')} )

// Rota protegida do dashboard
app.get('/api/dashboard', authenticateToken, (req: Request, res: Response) => {
    res.json({ message: `Bem-vindo, usuário ${req.user?.email}` });
});

// Rota para adicionar um novo lembrete
app.post('/api/reminders', authenticateToken, (req: Request, res: Response) => {
    const { title, date, category, description } = req.body;
    const userId = req.user?.id;

    if (!title || !date || !category || !description || !userId) {
        return res.status(400).json({ message: 'Título, data, categoria e conteúdo são obrigatórios.' });
    }

    const query = 'INSERT INTO reminders (title, date, category, description, user_id) VALUES (?, ?, ?, ?, ?)';
    db.query(query, [title, date, category, description, userId], (error) => {
        if (error) {
            console.error('Erro ao adicionar lembrete:', error);
            return res.status(500).json({ message: 'Erro ao adicionar lembrete.' });
        }
        res.status(201).json({ message: 'Lembrete adicionado com sucesso!' });
    });
});

// Rota para obter todos os lembretes do usuário
app.get('/api/reminders', authenticateToken, (req: Request, res: Response) => {
    const userId = req.user?.id; // Supondo que o ID do usuário está no token

    const query = 'SELECT * FROM reminders WHERE user_id = ?';
    db.query(query, [userId], (error, results: mysql.RowDataPacket[]) => {
        if (error) {
            return res.status(500).json({ message: 'Erro ao obter lembretes.' });
        }
        res.status(200).json(results);
    });
});

app.delete('/api/reminders/:id', authenticateToken, (req: Request, res: Response) => {
    const reminderId = req.params.id;
    const userId = req.user?.id;

    if (!reminderId || !userId) {
        console.log('Faltando reminderId ou userId');
        return res.status(400).json({ message: 'ID do lembrete e ID do usuário são obrigatórios.' });
    }

    console.log(`Tentando excluir o lembrete com id: ${reminderId} do usuário: ${userId}`);

    const query = 'DELETE FROM reminders WHERE id = ? AND user_id = ?';
    db.query(query, [reminderId, userId], (error, result) => {
        if (error) {
            console.error('Erro ao excluir lembrete:', error);
            return res.status(500).json({ message: 'Erro ao excluir lembrete.' });
        }

        // Type assertion to assert that result is OkPacket
        const okResult = result as mysql.OkPacket;

        console.log(`Rows afetadas: ${okResult.affectedRows}`);

        if (okResult.affectedRows === 0) {
            console.log('Nenhum lembrete encontrado para exclusão.');
            return res.status(404).json({ message: 'Lembrete não encontrado ou não pertence ao usuário.' });
        }

        console.log('Lembrete excluído com sucesso.');
        res.status(200).json({ message: 'Lembrete excluído com sucesso.' });
    });
});

// Rota para obter informações do usuário logado
app.get('/api/user', authenticateToken, (req: Request, res: Response) => {
    const userId = req.user?.id;  // Verifique se o userId existe no token decodificado

    if (!userId) {
        return res.status(401).json({ message: 'Usuário não autenticado' });
    }

    const query = 'SELECT username FROM users WHERE id = ?';
    db.query(query, [userId], (error, results: mysql.RowDataPacket[]) => {
        if (error) {
            console.error('Erro ao buscar informações do usuário no banco de dados:', error);
            return res.status(500).json({ message: 'Erro ao buscar informações do usuário.' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }

        const user = results[0];
        res.json({ username: user.username });
    });
});

// Rota para buscar lembretes por título
app.get('/api/reminders/search', authenticateToken, (req: Request, res: Response) => {
    const userId = req.user?.id;
    const title = req.query.title as string;

    if (!userId) {
        return res.status(401).json({ message: 'Usuário não autenticado' });
    }

    if (!title) {
        return res.status(400).json({ message: 'O título é obrigatório.' });
    }

    // Utilize um operador SQL LIKE para buscar o título parcialmente
    const query = 'SELECT * FROM reminders WHERE user_id = ? AND title LIKE ?';
    db.query(query, [userId, `%${title}%`], (error, results: mysql.RowDataPacket[]) => {
        if (error) {
            console.error('Erro ao buscar lembretes:', error);
            return res.status(500).json({ message: 'Erro ao buscar lembretes.' });
        }
        res.status(200).json(results);
    });
});

// Configuração do multer para receber imagens
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Rota para fazer upload da imagem do usuário
app.post('/api/user/upload-image', authenticateToken, upload.single('image'), (req: Request, res: Response) => {
    const userId = req.user?.id;

    if (!userId) {
        return res.status(401).json({ message: 'Usuário não autenticado' });
    }

    const newImage = req.file?.buffer;

    if (!newImage) {
        return res.status(400).json({ message: 'Nenhuma imagem foi enviada' });
    }

    // Excluir a imagem anterior
    const deleteQuery = 'DELETE FROM user_images WHERE user_id = ?';
    db.query(deleteQuery, [userId], (error) => {
        if (error) {
            console.error('Erro ao excluir imagem anterior:', error);
            return res.status(500).json({ message: 'Erro ao excluir imagem anterior.' });
        }

        // Inserir a nova imagem
        const insertQuery = 'INSERT INTO user_images (user_id, image) VALUES (?, ?)';
        db.query(insertQuery, [userId, newImage], (error) => {
            if (error) {
                console.error('Erro ao armazenar a nova imagem:', error);
                return res.status(500).json({ message: 'Erro ao armazenar a nova imagem.' });
            }

            res.status(200).json({ message: 'Imagem atualizada com sucesso.' });
        });
    });
});

// Rota para obter a imagem do usuário
app.get('/api/user/image', authenticateToken, (req: Request, res: Response) => {
    const userId = req.user?.id;

    if (!userId) {
        return res.status(401).json({ message: 'Usuário não autenticado' });
    }

    const query = 'SELECT image FROM user_images WHERE user_id = ?';
    db.query(query, [userId], (error, results: mysql.RowDataPacket[]) => {
        if (error) {
            console.error('Erro ao buscar imagem do usuário:', error);
            return res.status(500).json({ message: 'Erro ao buscar imagem do usuário.' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'Imagem não encontrada.' });
        }

        const image = results[0].image;
        res.setHeader('Content-Type', 'image/'); // Ajuste conforme o tipo de imagem
        res.send(image);
    });
});


// Inicia o servidor
app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});