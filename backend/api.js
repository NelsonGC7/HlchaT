

//API requires ----------------------------------
import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import cors from 'cors';

//base de datos-----------------------------------
import { createClient } from '@libsql/client';

const bd = createClient({
    url:"libsql://chatmeet-nelsongc7.turso.io",
    authToken:'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MjM4NDI3MTYsImlkIjoiZTZjOGNiZGQtOTQyNy00ODNhLWI4ZTUtZDJhZjc4MWEwZDEyIn0.XCwL3PxDbLhYU_Ou8bwSgbKyyCd3OPykxtMG7CaPekkA_q8axW6k_oEZc9J5LufGGMzhlvPaJwS2kHuRtifdCA'
})





//socket.io requires-----------------------------------------------------

import logger from 'morgan';
import {Server} from 'socket.io';
import { createServer } from 'http';
import{ dirname ,join} from 'path';
import { fileURLToPath } from 'url';


//API de comucicacion con el front------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const file = join (__dirname,'data.json')

const app = express();
app.use(logger('dev'));

app.use(cors());
app.use(express.json());


app.get('/chat', (req, res) => {
    res.sendFile(process.cwd() + '/public/index.html');
});

app.get('/login',(req,res)=>{
    res.sendFile(process.cwd() + '/schemas/login.html');
})
/*
app.get('/users',(req,res)=>{
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    res.status(200).json(jsonData);
})
*/
app.post('/users/new',(req,res)=>{  
    const {userName, email, password} = req.body;
    const userExist = jsonData.find(user => {
        if(user.email === email){
            return user;
        }else if(user.userName === userName){
            return user
        }
    });
    if(userExist){
        return res.status(409).json({msg: 'User already exist'})
    }
    console.log(userExist)
    if(!userName || !email || !password){
        return res.status(422).json({msg: 'Please include userName, email and pass'})
    }
    const new_user ={
        id: crypto.randomInt(1000,9999),
        userName,
        email,
        password
    }
    jsonData.push(new_user);
    const updateData  = JSON.stringify(jsonData,null,2);
    fs.writeFileSync(file,updateData);
    res.status(201).json(new_user);
})
app.post('/users',(req,res)=>{
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    const{ userName,password }= req.body;
    const userExist = jsonData.find(user =>{
        if(user.userName === userName && user.password === password){
            return user;
        }
    })
    if(!userExist || userExist.length === 0){
        return res.status(401).json({msg: 'User not found'})
    }else{
        return res.status(203).json({msg:"user found"});
    };
});


//socket.io--------------------------------------------------------------
const PORTsocket = process.env.PORT || 42066;
const socketServer = createServer(app);


const io = new Server(socketServer,{
    connectionStateRecovery: true,
  });

io.on('connection',(socket)=>{
    console.log("user connected")
    socket.on('disconnect',()=>{
        console.log('USUARIO DESCONECTADO')
    })
    socket.on('chat message', (msg)=>{
        io.emit('chat message',msg)
    })
})

socketServer.listen(PORTsocket,()=>{
    console.log("server socket and API running on:",PORTsocket)
})


