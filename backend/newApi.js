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
              user_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
              user_status TEXT NOT NULL)
          `);
            console.log("TABLE CREATED")
    
        await db.execute(`DROP TABLE IF EXISTS mesages`);

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
            DROP TABLE IF EXISTS friendships`
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
    try{
   
    
    if(!token){
        return res.status(401).json({"error1":"Access Denied desde middleware"});
    }
    //console.log("este es token de: "+ user ,token);
    
        const data = jwt.verify(token,tknJsn);
        if(!data) return res.status(401).send({"error2":"token no valido"});
        req.user = data;
        next();
    }
    catch(err){
        if(err instanceof jwt.TokenExpiredError){
            return res.status(401).json({"error3:":"Token expirado"})
        }
    }


} 


app.get('/',(req,res)=>{
    res.sendFile(process.cwd()+ '/schemas/login.html')
});
app.post('/users', rejisterLimiter , async(req,res)=>{
    try{
        const {password} = req.body;
        const result = validateUser(req.body);
        if(result.error){
            return res.status(400).send("invalid data")
        }
        const resultUser = await db.execute({
            sql:"SELECT user_name FROM users WHERE user_name = :user",
            args:{
                user:result.data.user
            }
        })
        if(resultUser.rows.length > 0) return res.status(409).json({msg:"El usuario ya existe"})
        const hashedPassword = await bcrypt.hash(password,8);  
        await db.execute(
                {
                    sql:"INSERT INTO users (user_id,user_name,user_email,user_pass,user_status) VALUES (:id,:user,:correo,:password,:status)",
                    args:{
                        id:randomUUID(),
                        user:result.data.user,
                        correo:result.data.correo,
                        password:hashedPassword,
                        status:"online"
                    },
                },
        );
        res.status(203).json({msg:"usuario creado"});   
    }
    catch(err){
        res.status(401).json({msg:"error al crear Usuario"})
    }
});
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
                res.status(401).json({msg:"constraseña incorrecta"});
            }
            
            
        }else{res.status(404).json({msg:"usuario no econtrado"})};
        
        
    }
    catch(err){
        console.log(err)
    }
});
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
            httpOnly:false,
            secure:true,
            sameSite:'none',
            maxAge: 60 * 60 * 2000, // 1 hour
        })
        .cookie("user",`${user} = ${user_id}`,{
            httpOnly:false,
            secure:true,
            sameSite:'none',
            
        });


        
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
            sql:`
                    SELECT user_name
                    FROM users
                    WHERE user_name LIKE :search
                    AND user_id != :userId
                    AND user_id NOT IN (
                        SELECT b_id FROM friendships
                        WHERE a_id = :userId
                        AND (ab_status = 'pending' OR ab_status = 'assept')
                    )
                    AND user_id NOT IN (
                        SELECT a_id FROM friendships
                        WHERE b_id = :userId
                        AND (ab_status = 'pending' OR ab_status = 'assept')
                    )
            ` ,
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

});
app.post('/addfriend',midelToken, async(req,res)=>{
     const validUser =req.user;
     const {addFriend} = req.body;
     const cokie = req.cookies.access_token;
     const validation = jwt.verify(cokie,tknJsn);

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
    if(result2.rows.length > 0) {
        /*
        await db.execute({
            sql:
            `
                UPDATE friendships set ab_status = 'assept'
                WHERE b_id = :recive AND a_id = :sender
            `,
            args:{
                sender:validUser.usId,
                recive:user_id,
            }
        })
         */   
        return res.status(404).json({msg:"friendship already exist"})
    };
    const result2_2 = await db.execute(
        {
            sql:`
            SELECT ab_id FROM friendships 
            WHERE b_id = :asepta  AND a_id = :aseptado
            `,
            args:{
                asepta:validUser.usId,
                aseptado:user_id
            }
        }
    )
    if(result2_2.rows.length > 0 ){
        await db.execute({
            sql:
            `
                UPDATE friendships set ab_status = 'assept'
                WHERE b_id = :asepta AND a_id = :aseptado
            `,
            args:{
                asepta:validUser.usId,
                aseptado:user_id
            }
        })
        return res.status(203).json({"msj":"error en result2_2"})
    }
    
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

    if(result3.rowsAffected > 0) return res.status(200).json({msg:"friendship created"});


});
app.get('/friends',midelToken,async(req,res)=>{
   
    const validUser = req.user
    const cokie = req.cookies.access_token;
    const valid = jwt.verify(cokie,tknJsn)
    if(validUser.usId !== valid.usId)return res.status(400).json({"msj":"send catch"})
    if(!valid) return res.status(401).json({"msj":"error 400"});
  

    try{
        const result = await db.execute({
            sql:
            `
                SELECT users.user_name,users.user_id
                FROM users 
                WHERE users.user_id IN (
                    SELECT friendships.a_id FROM friendships
                    WHERE friendships.b_id = :mser
                    AND friendships.ab_status = 'pending'
                   
                 
                )
            `,
            args:{
                mser:`${validUser.usId}`
            }
        })
        //console.log(result.rows.length)
        // console.log(result.rows)
        const result2 = await db.execute({
            sql:
            `
                SELECT users.user_name,users.user_id,users.user_status
                FROM users 
                WHERE users.user_id IN (
            
                    SELECT friendships.a_id FROM friendships
                    WHERE friendships.b_id = :mser
                    AND friendships.ab_status = 'assept'
                    )
                    OR  users.user_id IN (
                    SELECT friendships.b_id FROM friendships
                    WHERE friendships.a_id = :mser
                    AND friendships.ab_status = 'assept'     
                )
            `,
            args:{
                mser:`${validUser.usId}`
            }
        })
        if(result.rows.length == 0 && result2.rows.length == 0){ 
            return res.status(204).json({"msj":"err en db in1"})
        }    
        res.status(202).json({
            "pending":result.rows,
            "assepted":result2.rows

        })
    }catch{
        res.status(405).send("err in db in2");
    }    
});
app.post('/logout',midelToken,(req,res)=>{
    const token = req.cookies.access_token;
    if(!token) return res.status(401).send("Access Denied no token");
    res.clearCookie('access_token');
    res.status(200).send("logout success");
});

//sockets de comunicacion
async function consulUbication (ubication){
    let ubicacionTotal = null;
   try{

        const result = await db.execute(
            {
                sql:`SELECT ubication_id,ubication_name 
                FROM ubications
                WHERE ubication_name = :ubicacion
                `,
                args:{
                    ubicacion:ubication
                }
            }
        )
        if(result.rows.length === 0 ){
            try{
                const resultado = await db.execute(
                    {
                        sql:
                        `
                            INSERT INTO ubications
                            (ubication_id,ubication_name)
                            VALUES (:id,:name);
                        `,
                        args:{
                            id:randomUUID(),
                            name:ubication
                        }
                    }
                )
                if(resultado.rowsAffected === 1){
                    const resultado2 = await db.execute({
                        sql:`SELECT ubication_id,ubication_name 
                            FROM ubications
                            WHERE ubication_name = :ubicacion`,
                        args:{
                            ubicacion:ubication
                        }
                    })
                   // console.log(resultado2.rows,"segundo")
                   return ubicacionTotal = resultado2.rows[0].ubication_id;
                   
                }
            }catch(err){
                console.log("err2",err)
            }
        }else{
            //console.log(result.rows,"primer")
          return  ubicacionTotal = result.rows[0].ubication_id;
        }
   }
   catch(err){
    console.log("err1",err)
   }

}
async function consultaMensajes(idSala,nameSala){
    const result = await db.execute({
        sql:
        `
        SELECT message,sender_name,message_at FROM messages_ubications
        WHERE ubication_id = :id
        AND ubication_name = :name
        `,
        args:{
            id:idSala,
            name:nameSala
        }
    })
    return result.rows

}

const usuarios_en_salas= {};//almacenamiento de usuarios conectados  para todas las salas


io.on('connection',async(socket)=>{
    console.log(`user connected`);
    let room = null;
    let room2 = null;
    let location = null;
    const  tk = socket.handshake.auth.token;
   try{
    if(!tk){
        socket.disconnect()
        return;
    };
        const data = jwt.verify(tk,tknJsn);

        if(!data) return socket.disconnect();
        const usC = data.usId;
        
        if(!usC) return console.log("no tienes el usId")
        const verAmistad = async(sender,recive)=>{
            const result = await db.execute({
                sql:`
                SELECT ab_id FROM friendships 
                WHERE a_id = :sendId AND b_id = :reciId
                OR a_id = :reciId AND b_id = :sendId 
                `,
                args:{
                    sendId:sender,
                    reciId:recive
                }
            });
            return result.rows

            
        }
        socket.on('maps',async(data)=>{
            if(room2) socket.leave(room2);
         
            const result  = await fetch(`https://us1.locationiq.com/v1/reverse?key=${process.env.LOCATION_KEY}&lat=${data.latJ}&lon=${data.lonj}&format=json&`)
            const dat = await result.json()
            if(dat.address.county){
                location =  dat.address.county
                room2 = await consulUbication(dat.address.county);
                if(room2) socket.leave(room2);
                socket.join(room2);
                if(!usuarios_en_salas[room2]) usuarios_en_salas[room2] = [];
                
                if(usuarios_en_salas[room2].includes(data.user)){
                   const indexDelete =  usuarios_en_salas[room2].indexOf(data.user);
                    usuarios_en_salas[room2].splice(indexDelete,1)
                };
                usuarios_en_salas[room2].push(data.user);
                const messages = await consultaMensajes(room2,location);
                io.to(room2).emit(`${usC}Map`,messages,location);


                io.to(room2).emit(location, usuarios_en_salas[room2]);
               

            }else if(dat.address.city){
                location = dat.address.city;
                room2 = await consulUbication(dat.address.city);
                if(room2) socket.leave(room2);
                socket.join(room2);
                if(!usuarios_en_salas[room2])usuarios_en_salas[room2] = [];

                if(usuarios_en_salas[room2].includes(data.user)){
                    const indexDelete = usuarios_en_salas[room2].indexOf(data.user);
                   usuarios_en_salas[room2].splice(indexDelete,1)
                }
                usuarios_en_salas[room2].push(data.user)
                const messages = await consultaMensajes(room2,location);
                io.to(room2).emit(`${usC}Map`,messages,location);


                io.to(room2).emit(location, usuarios_en_salas[room2]);
             
            }else if(dat.address.state){
                location = dat.address.state;
                room2 = await consulUbication(dat.address.state);
                if(room2) socket.leave(room2);
                socket.join(room2);
                if(!usuarios_en_salas[room2])usuarios_en_salas[room2] = [];
                if(usuarios_en_salas[room2].includes(data.user)){
                    const indexDelete =  usuarios_en_salas[room2].indexOf(data.user)
                    usuarios_en_salas[room2].splice(indexDelete,1)
                }
                usuarios_en_salas[room2].push(data.user)
                const messages = await consultaMensajes(room2,location);
                io.to(room2).emit(`${usC}Map`,messages,location);

                io.to(room2).emit(location, usuarios_en_salas[room2]); 
                
                
            };

        });
        socket.on('place',async(data)=>{
            io.to(room2).emit('place',data)
            if(data.valor.length === 0){
                return console.log("intento de mensaje vacio")
            }
            const newMesage = data.valor.trim()
    
            try{
                await db.execute({
                    sql:
                    `
                    INSERT INTO messages_ubications
                    (ubication_id,ubication_name,message,sender_id,sender_name,message_at)
                    VALUES(:ubication_id,:ubication_name,:message,:sender_id,:sender_name,:message_at);
                    `,
                    args:{
                        ubication_id:room2,
                        ubication_name:location,
                        message:newMesage,
                        sender_id:usC,
                        sender_name:data.userr,
                        message_at:data.time,
  
                    }
                })
            }
            catch(e){
                console.log({erroraddbmesaje:e})
            }
         
        })


        socket.on('joinC',async(data)=>{
            if(room) socket.leave(room);//si ya esta en una sala la deja 
           const result = await verAmistad(usC,data.recive_id);
            if(result.length === 0) return console.log("no eres amigo");        
            room = result[0].ab_id;
            socket.join(room);
            
            const recarge = await db.execute({
                sql:`SELECT send_id,rec_id,mesage,send_at
                    FROM mesages 
                    WHERE (send_id = :sendId AND rec_id = :reciveId )
                    OR (send_id = :reciveId AND rec_id = :sendId)
                `,
                args:{
                    sendId:usC,
                    reciveId:data.recive_id
                }
            });
            //console.log(recarge.rows)debug
            const messages = [...recarge.rows];
            io.to(room).emit(usC,messages);

        });
        socket.on('privmsj', async(data)=>{
            try{
                const { msj } = data;
                if(msj.length === 0 ) return console.log("intento de mensaje vacio");
                const result = await verAmistad(usC,data.recive_id)
                if(result.length === 0) return console.log("no eres amigo");
                room = result[0].ab_id;
                const hora = data.time.split("-")[1];
                const newDate = `${hora.split(":")[0]}:${hora.split(":")[1]}`
                io.to(room).emit('privmsj',msj,newDate,usC)
                await db.execute({
                    sql:`
                    INSERT INTO mesages 
                    (send_id,rec_id,mesage,send_at)
                    VALUES (:envia,:recive,:msj,:date)`,
                    args:{
                        envia:usC,
                        recive:data.recive_id,
                        msj:msj.trim(),
                        date:data.time
                    }
                });
            }catch(e){
                console.log({"error":e})
            }
           
        });

    socket.on('disconnect',()=>{
     console.log(`user disconnected`);
    });



   }
   catch(e){
    console.log(e)
   }


})


socketServer.listen(PORT,()=>{
    console.log("server started on port: "+PORT)
    
})