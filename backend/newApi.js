import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import bcrypt from 'bcrypt';
import { createClient } from '@libsql/client';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { randomUUID } from 'node:crypto';
import rateLimit from 'express-rate-limit';

const rejisterLimiter = rateLimit({
    windowMs: 2 * 60 * 1000, // 2 minutes
    max:6,
    message: "too many request from this ip, please try again in 2 minutes"

})
const loginLimiter = rateLimit({
    windowMs: 2 * 60 * 1000, // 2 minutes
    max:6,
    message: "too many request from this ip, please try again in 2 minutes"
})
//socket requeriments
import { Server } from 'socket.io';
import logger  from 'morgan';
import { createServer } from 'http';
import  { z } from 'zod';
const userSchema = z.object({

    user:z.string().min(3).max(15),
    correo:z.string().email(),
    password:z.string().min(8).max(20)
})

function validateUser(object){
    return userSchema.safeParse(object)
}

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
            DROP TABLE IF EXISTS friendships;`
        );
        await db.execute(`
            CREATE TABLE IF NOT EXISTS friendships(
                ab_id TEXT PRIMARY KEY,
                ab_status TEXT  NOT NULL DEFAULT 'pending',
                a_id TEXT NOT NULL,
                b_id TEXT NOT NULL,
                ab_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (a_id) REFERENCES users(user_id),
                FOREIGN KEY (b_id) REFERENCES users(user_id)
            );          
        `)
    }
    catch(err){
        console.log(err)
    }
};


const app = express();
const socketServer = createServer(app);

const io = new Server(socketServer,{
    connectionStateRecovery:{},
});


const PORT = process.env.PORT || 42066;
app.use(logger('dev'));
app.use(cors());
app.use(express.json())
app.use(cookieParser())



//creo una funcion middleware para verificar el token

async function midelToken(req,res,next){
    const token = req.cookies.access_token;
    console.log("midelware")
    if(!token){
        return res.status(401).send("Access Denied desde middleware");
    }
    //console.log("este es token de: "+ user ,token);
    try{
        const data = jwt.verify(token,tknJsn);
        if(!data) return res.status(401).send("Access Denied desde middleware-");
        req.user = data;
        next();
    }
    catch(err){
        res.status(401).send("Access Denied")
    }


} 


app.get('/',(req,res)=>{
    res.send("started page")
})
app.get('/loginre',(req,res)=>{
    res.sendFile(process.cwd()+ '/schemas/login.html')
})

app.post('/users', rejisterLimiter , async(req,res)=>{
    try{
        const {password} = req.body;
        const result = validateUser(req.body);
        if(result.error){
            return res.status(400).send("invalid data")
        }
        const hashedPassword = await bcrypt.hash(password,8);  
        await db.execute(
                {
                    sql:"INSERT INTO users (user_id,user_name,user_email,user_pass) VALUES (:id,:user,:correo,:password)",
                    args:{
                        id:randomUUID(),
                        user:result.data.user,
                        correo:result.data.correo,
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


app.post('/login', loginLimiter  ,async(req,res)=>{
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
                    sameSite:'none',
                    maxAge: 60 * 60 * 1000, // 1 hour
                })
                .send({msg:"login success"})
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
        .sendFile(process.cwd() + '/public/index.html')
        res.cookie('access_token',token,{
            httpOnly:true,
            secure:true,
            sameSite:'none',
            maxAge: 60 * 60 * 1000, // 1 hour
        })
        .cookie("user",user,{
            sameSite: 'none',
            secure:true,
        })

        
    }else{
        if(user_id !== data.usId) return res.status(403).send("user no coincide con el token");
        return res.status(401).json({msg:"Access Denied noo token !!"}) 
    }
});

app.post('/search',midelToken,async(req,res)=>{
    const {userSearch} = req.body;
    const token = req.cookies.access_token;
    const data = jwt.verify(token,tknJsn);
    if(!data) return res.status(401).send("Access denied no token ");
    if(!userSearch) return res.status(203).send("no search data1");
    if(userSearch.length < 3) return res.status(400).send("search data too short");
   try{
    //console.log("buscando a: "+ userSearch);
    const result = await db.execute(
        {
            sql:`SELECT user_name
                 FROM users 
                 WHERE user_name LIKE :search
                 AND user_id != :userId
                 AND user_id NOT IN (
                    SELECT b_id FROM friendships
                    WHERE a_id = :userId
                    AND ab_status = 'pending'

                 )` ,
            args:{
                search:`%${userSearch}%`,
                userId:data.usId,
            }
        }
        
    );
    if(result.rows.length === 0) return res.status(206).json({msg:"no user found"});
    res.status(226).json(result.rows);

   }
   catch(err){
       console.log("error en el TRY search",err)
   }

})
app.post('/addfriend',midelToken, async(req,res)=>{
     const validUser =req.user;
     const {addFriend} = req.body;
     const cokie = req.cookies.access_token;
     const validation = jwt.verify(cokie,tknJsn);
     console.log(addFriend)
    if(!validation) return res.status(401).json({msg:"Access Denied no token"});  
   // console.log(validation.usId)
    //console.log(validUser.usId)
    if(validUser.usId!== validation.usId) return res.status(402).json({msg:"user not valid"});
       
   // console.log(addFriend);
    const result = await db.execute({
        sql:"SELECT user_id,user_name FROM users WHERE user_name = :user",
        args:{
            user:`${addFriend}`,
        }
    });
    if(result.rows.length === 0) return res.status(404).json({msg:"user not found"});
    const {user_id}= result.rows[0];
    if(!user_id) return res.status(404).json({msg:"user not found"});

    //console.log(result)
    const result2 = await db.execute(
        {
            sql:"SELECT ab_id FROM friendships WHERE a_id = :sender AND b_id = :recive",
            args:{
                sender:validUser.usId,
                recive:user_id,
            }
        }
    )
    if(result2.rows.length > 0) return res.status(203).json({msg:"friendship already exist"});
    
    const idAmistad = randomUUID();

    const result3 = await db.execute(
        {
            sql:"INSERT INTO friendships (ab_id,ab_status,a_id,b_id) VALUES (:id,:status,:send,:recive)",
            args:{
                id:idAmistad,
                status:`pending`,
                send:validUser.usId,
                recive:user_id,
            },
        }
    )
    console.log(result3.rowsAffected)
    if(result3.rowsAffected > 0) return res.status(200).json({msg:"friendship created"});


})
app.post('/friends',midelToken,async(req,res)=>{
   
    const validUser = req.user
    console.log(req.params)
    const cokie = req.cookies.access_token;
    const valid = jwt.verify(cokie,tknJsn)
    if(validUser.usId !== valid.usId)return res.status(400).json({"msj":"send catch"})
    if(!valid) return res.status(401).json({"msj":"error 400"});
    console.log(validUser)

    try{
        const result = await db.execute({
            sql:
            `
                SELECT users.user_name,users.user_id
                FROM users 
                WHERE users.user_id IN (
                    SELECT friendships.a_id FROM friendships
                    WHERE friendships.b_id = :mser
                )
            `,
            args:{
                mser:`${validUser.usId}`
            }
        })
        //console.log(result.rows.length)
        console.log(result.rows)
        if(result.rows.length == 0) return res.status(204).json({"msj":"err en db in1"})
        
        res.status(202).json({"asept":result.rows})


    }catch{
        res.status(405).send("err in db in2");
    }

    

    
})



app.post('/logout',midelToken,(req,res)=>{
    const token = req.cookies.access_token;
    if(!token) return res.status(401).send("Access Denied no token");
    res.clearCookie('access_token');
    res.status(200).send("logout success");
});


//sockets de comunicacion

io.on('connection',(socket)=>{
    console.log(`user connected`);


    socket.on('disconnect',()=>{
     console.log(`user disconnected`);
    })

    socket.on('chat message',(msg)=>{
        io.emit('chat message',msg);
        
    })

})


socketServer.listen(PORT,()=>{
    console.log("server started on port: "+PORT)
    
})