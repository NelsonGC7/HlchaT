import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import bcrypt from 'bcrypt';
import { createClient } from '@libsql/client';

dotenv.config();

const db = createClient({
    url:process.env.DBHOST,
    authToken:process.env.DBTOKEN
});

async function createTable(){
    try{
        await db.execute(`
            DROP TABLE IF EXISTS users;
          `);
      
          // Luego, crear la tabla
          await db.execute(`
            CREATE TABLE users (
              user_id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
              user_name VARCHAR(25) UNIQUE,
              user_email VARCHAR(50) UNIQUE,
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
app.use(cors());
app.use(express.json());

app.get('/Login_rejisteR',(req,res)=>{
    res.sendFile(process.cwd()+ '/schemas/login.html')
})
app.post('/users', async(req,res)=>{
    try{
        const {user,correo,password} = req.body;
        const hashedPassword = await bcrypt.hash(password,10);  
    console.log(user,correo,password)
        const result = await db.execute(
                {
                    sql:"INSERT INTO users (user_name,user_email,user_pass) VALUES (:user,:correo,:password)",
                    args:{
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
app.post('/login', async(req,res)=>{
    const {user,password} = req.body;
    try{
        const result = await db.execute(
            {
                sql:"SELECT user_pass FROM users WHERE user_name = :user",
                args:{
                    user:user,
                }
            }
        )
        const {rows} = result;
        if(rows.length === 0){
           return res.status(404).json({msg:"user not found"})
        }
        const pass = rows[0].user_pass;

        let valid = await bcrypt.compare(password,pass);
        
        console.log(valid)

        if(valid){
            res.status(200).json({msg:"login success"})
        }
        else{
            res.status(401).json({msg:"login failed"})
        }

    }
    catch(err){
        console.log(err)
    }
})

app.listen(PORT,()=>{
    console.log(`Server running on port ${PORT}`)
})