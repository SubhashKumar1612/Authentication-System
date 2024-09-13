const mongoose = require("mongoose");
const bcrypt=require("bcrypt");
const jwt=require("jsonwebtoken");


const registrationSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    contact: {
        type: String,
        required: true,
        //unique: true
    },
    date: {
        type: String,
        required: true
    },
    prn: {
        type: Number,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    branch: {
        type: String,
        required: true
    },
    roomReference: {
        type: String,
        enum: ['Ac', 'Non-Ac'],
        required: true
    },
    email: {
        type: String,
        required: true
    },
    preference: {
        type: String,
        required: true
    },
    //new fileds
    address: {
        type: String
    },
    roomNo: {
      type: Number
    },
    year: {
      type: Number
    },
    confirmPassword: {
        type: String,
        required: true
    },
    tokens:[{
      token:{
        type:String,
        required:true
      }
    }]
  
});



registrationSchema.methods.generateAuthToken=async function(){
    try{
      //console.log("student id "+this._id);
      const token=jwt.sign({_id:this._id.toString()},process.env.SECRET_KEY);
      this.tokens=this.tokens.concat({token:token})
      await this.save();
      return token;
  
    }catch(error){
      res.send("the error part"+error);
      console.log("the error part"+error);
    }
  }
  
  registrationSchema.pre("save",async function(next){
    if(this.isModified("password")){
       
       this.password=await bcrypt.hash(this.password,10);
      this.confirmPassword=await bcrypt.hash(this.password,10);
    }
    next();
  })
  

const Register = new mongoose.model("Register", registrationSchema);
module.exports = Register;
