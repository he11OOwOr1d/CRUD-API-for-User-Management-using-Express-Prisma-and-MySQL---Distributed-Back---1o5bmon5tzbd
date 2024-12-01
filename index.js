const express = require('express');
const dotenv = require('dotenv'); 
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const {prisma} = require('./db/config');
dotenv.config(); 

const app = express();

app.use(express.json()); 

const genToken = (userId,name,email) =>{
  return jwt.sign({userId,name,email},process.env.JWT_SECRET,{expiresIn: '2h'})
}

app.post('/api/auth/signup',async (req,res)=>{
  const {name,email,password} = req.body
  if (!email || !password){
    return res.status(400).json({"error": "Email is required"})
  }
  const hashedPass = await bcrypt.hash(password, parseInt(process.env.BCRYPT_SALT_ROUNDS))
  
  const Existuser = await prisma.user.findUnique({
    where: {
      email: req.body.email
    }
  })
  if(Existuser){
    return res.status(400).json({
      "error": "Email already in use"
    })
  }
  const user = await prisma.user.create({
    data: {
      name: name,
      email: email,
      password: hashedPass
    }
  })
  if (user){
    return res.status(200).json({"message": "User created successfully", "userId": user.id})
  }
  
})

app.post('/api/auth/login',async (req,res)=>{
  const {email,password} = req.body 
  if(!password || !email){
    return res.status(400).json({
      "error": "Email and password are required"
    })
  }
  const user = await prisma.user.findUnique({
    where: {
      email: req.body.email
    }
  })
  if(!user){
    return res.status(400).json({
      "error": "User not found"
    })
  }
  const accesstoken = genToken(user.id,user.name,user.email)
  const isCompare = await bcrypt.compare(password,user.password)
  if (!isCompare){
    return res.status(400).json({
      "error": "Invalid credentials"
    })
  }
  if (user){
    return res.status(200).json({
      userdata: {"id": user.id, "name": user.name, "email": user.email}, accesstoken: accesstoken
    })
  }
})

const PORT = process.env.PORT || 3000;  
app.listen(PORT, () => {
  console.log(`Backend server is running at http://localhost:${PORT}`);
});

module.exports =  app;