import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import bcrypt from 'bcrypt';
import { createClient } from '@libsql/client';
import  jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { randomUUID } from 'node:crypto';
dotenv.config();


const tknJsn = process.env.JSNTKN;

const db = createClient({
    url:process.env.DBHOST,
    authToken:process.env.DBTOKEN
});
/* creacion de trablas para los usuarios y los mensajes en la base de datos*/
async function createTable(){
    try{
        await db.execute(`
            DROP TABLE IF EXISTS users;
          `);
      
          // Luego, crear la tabla
          await db.execute(`
            CREATE TABLE users (
              user_id TEXT NOT NULL UNIQUE,
              user_name VARCHAR(25) UNIQUE,
              user_email VARCHAR(100) UNIQUE,
              user_pass VARCHAR(50) NOT NULL,
              user_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
          `);
            console.log("TABLE CREATED")

        await db.execute(`
            DROP TABLE IF EXISTS mesages;`
        );
        await db.execute(`
        CREATE TABLE IF NOT EXISTS mesages(
            mesage_id INTEGER  PRIMARY KEY,
            send_id INTEGER NOT NULL,
            rec_id INTEGER NOT NULL,
            mesage TEXT NOT NULL,
            send_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (send_id) REFERENCES users(user_id),
            FOREIGN KEY (rec_id) REFERENCES users(user_id)
        );          
        `)
        console.log("TABLE CREATED MESSAGES")
        await db.execute(`
            DROP TABLE IF EXISTS friendsships;    
        `);
        await db.execute(`
        CREATE TABLE IF NOT EXISTS friendships(
            friends_id INTEGER PRIMARY KEY,
            user1_id INTEGER NOT NULL,
            user2_id INTEGER NOT NULL,
            friends_since TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user1_id) REFERENCES users(user_id),
            FOREIGN KEY (user2_id) REFERENCES users(user_id)
        );
            
        `)
    }
    catch(err){
        console.log(err)
    }
};


const app = express();
const PORT = process.env.PORT || 42066;


app.use(express.json())
app.use(cookieParser())
app.use(cors());


app.get('/',(req,res)=>{
    res.send("started page")
})
app.get('/loginre',(req,res)=>{
    res.sendFile(process.cwd()+ '/schemas/login.html')
})

app.post('/users', async(req,res)=>{
    try{
        const {user,correo,password} = req.body;
        const hashedPassword = await bcrypt.hash(password,8);  
        await db.execute(
                {
                    sql:"INSERT INTO users (user_id,user_name,user_email,user_pass) VALUES (:id,:user,:correo,:password)",
                    args:{
                        id:randomUUID(),
                        user:user,
                        correo:correo,
                        password:hashedPassword,
                    },
                },
        );
        res.status(203).json({msg:"user created"});   
    }
    catch(err){
        res.status(409).json({msg:"user not created"})
    }
})

//creo una funcion middleware para verificar el token

async function midelToken(req,res,next){
    const token = req.cookies.access_token;
    const user = req.params.user;
    if(!token){
        return res.status(401).send("Access Denied")
    }
    //console.log("este es token de: "+ user ,token);
    try{
        const data = jwt.verify(token,tknJsn);
        if(!data) return res.status(401).send("Access Denied");
        req.user = data;
        next();
    }
    catch(err){
        res.status(401).send("Access Denied")
    }


} 
app.post('/login', async(req,res)=>{
    const {user,password} = req.body;
    try{
        const result = await db.execute(
            {
                sql:"SELECT user_pass,user_id,user_name FROM users WHERE user_name = :user",
                args:{
                    user:user,
                }
            }
        )
        const {rows} = result;
        
        if(rows.length > 0){
            const pass = rows[0].user_pass;
            const userId = rows[0].user_id;
            let valid = bcrypt.compareSync(password,pass);
            if(valid){
                const tkn = jwt.sign(
                    {usId:userId,password:pass},
                    tknJsn,
                    {expiresIn:"1h"}
                );
                res
                .status(200)
                .cookie('access_token',tkn,{
                    httpOnly:true,
                    secure:true,
                    sameSite:'strict',
                    maxAge: 60 * 60 * 1000, // 1 hour
                }).send({msg:"login success"})
            }
            else{
                res.status(401).json({msg:"password incorrect"});
            }
            
            
        }else{res.status(404).json({msg:"user not found"})};
        
        
    }
    catch(err){
        console.log(err)
    }
})
/* //cree mi propoio middleware para verificar el token el ruta deseada
app.use('/h!chat/char',(req,res,next)=>{
    const tokken = req.headers.Autorization;
    console.log("este es token ",tokken);
   
    console.log(tokken)
    if(!tokken) return res.status(401).json({msg:"Access Denied"});
    try{
        const data = jwt.verify(tokken,tknJsn);
        res.status(200).json({msg:"valid token"});
        next();
    }
    catch(err){
        console.log(tokken)
        res.status(401).send('access no autorized')
    }

})
    */

app.get('/:user/chat', midelToken, async (req,res)=>{
    const userValid = req.user
    const user = req.params.user;
    const token = req.cookies.access_token;

    const userid = req.cookies.user_id;
    const data = jwt.verify(token,tknJsn);
    if(!data) return res.status(401).send("Access denied no token ");
    if(!userValid) return res.status(403).send("token no coincide con el usuario");
     const result = await db.execute(
        {
            sql:"SELECT user_name,user_id FROM users WHERE user_name = :user",
            args:{
                user:user,
            }
        }
    )
    const {rows} = result;

    if(result.rows.length === 0 ) return res.status(404).send("el usuario no existe");
    const user_id = rows[0].user_id;
    const user_name = rows[0].user_name;

    if(!user_id || !user_name) return res.status(404).json({msg:"user not found dbX2 "});

    if(data.usId === user_id && data.password === userValid.password && user_id === userValid.usId){
        res.status(200)
        res.sendFile(process.cwd() + '/public/index.html')
       
    }else{
        if(user_id !== data.usId) return res.status(403).send("user no coincide con el token");
        return res.status(401).json({msg:"Access Denied noo token !!"}) 
    }
});

app.listen(PORT,()=>{
    console.log(`Server running on port ${PORT}`)
});