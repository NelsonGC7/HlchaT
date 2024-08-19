import express from 'express';
import dotenv from 'dotenv';
import bycrypt from 'bcrypt';
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


}

const userSchema = {
    user:String,
    email:String,
    pass:String,
}
const app = express();
const PORT = process.env.PORT || 42066;
app.use(express.json());

app.post('/users', async(req,res)=>{
    try{
    const {user,correo,password} = req.body;
        const result = await db.execute(
            [
            {
                sql:"INSERT INTO users (user_name,user_email,user_pass) VALUES (:user,:correo,:password)",
                args:{
                    user,
                    correo,
                    password
                },
            }
            ],
            "write"

        );
        res.status(201).json({msg:"user created"});   
    }
    catch(err){
        console.log("error al tratar de crear usuario")
    }
})




app.listen(PORT,()=>{
    console.log(`Server running on port ${PORT}`)
})