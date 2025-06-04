require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

//Configuração do Express para aceitar JSON
app.use(express.json())

//Importando o modelo de usuário
const User = require('./models/User')

// Open Route - Public Route
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Welcome to the API!' })
})

// Private Route - Middleware de autenticação
app.get("/auth/:id", checkToken, async (req, res) => {
    const id = req.params.id

    //Verificando se o usuário existe
    const user = await User.findById(id, '-password')

    if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado!' })
    }

    res.status(200).json({user})
})

function checkToken(req, res, next){
    
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.status(401).json({ msg: 'Acesso negado, token não fornecido!' })
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
    } catch (error) {
        return res.status(403).json({ msg: 'Token inválido!' })
    }
}

//Registrando o usuário no banco de dados
app.post('/auth/register', async (req, res) => {

    const { name, email, password, confirmpassword } = req.body

    //Validação de dados e obtendo retorno ao executar
    if (!name) {
        return res.status(422).json({ msg: 'O nome é obrigatório!' })
    }

    if (!email) {
        return res.status(422).json({ msg: 'O e-mail é obrigatório!' })
    }

    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatória!' })
    }

    if (password !== confirmpassword) {
        return res.status(422).json({ msg: 'As senhas não conferem!' })
    }

    //Verificando se o usuário já existe
    const userExists = await User.findOne({ email: email })

    if (userExists) {
        return res.status(422).json({ msg: 'E-mail já cadastrado, ou já existe!' })
    }

    //Criando a senha
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //Criando o usuário
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {

        await user.save()

        res.status(201).json({ msg: 'Usuário registrado com sucesso!' })
    } catch (error) {
        console.log(error)
        return res.status(500).json({ msg: 'Erro ao registrar usuário, tente novamente mais tarde!' })
    }
})

// Login do usuário no sistema
app.post("/auth/login", async (req, res) => {

    const { email, password } = req.body

    //Validação de dados e obtendo retorno ao executar
    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatório!' })
    }

    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatória!' })
    }

    //Verificando se o usuário existe
    const user = await User.findOne({ email: email })

    if (!user) {
        return res.status(422).json({ msg: 'Usuário não encontrado, por favor utilize outro email...!' })
    }

    //Verificando se a senha está correta
    const checkPassword = await bcrypt.compare(password, user.password)

    if (!checkPassword) {
        return res.status(422).json({ msg: 'Senha inválida, tente novamente!' })
    }

    try {

        const secret = process.env.SECRET
        const token = jwt.sign(
            {
                id: user._id,
            }, secret,
        )

        res.status(200).json({ msg: 'Autenticação realizada com sucesso!', token})

    } catch (error) {
        console.log(error)
        return res.status(500).json({ msg: 'Erro ao fazer login, tente novamente mais tarde!' })
    }
})

//Credential que conecta ao banco de dados mongoDB através da senha
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

//Conexão com o mongoDB
mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@api-auth.qkpq3k1.mongodb.net/?retryWrites=true&w=majority&appName=API-AUTH`,
)
.then(() => {
    app.listen(3000)
    console.log('Conectamos com sucesso ao MongoDB!')
})
.catch((err) => console.log (err))