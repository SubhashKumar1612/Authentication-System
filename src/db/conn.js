const mongoose=require("mongoose");
mongoose.connect("mongodb://127.0.0.1:27017/Auth")
.then(()=>{
    console.log("connection is successful")
}).catch((err)=>{
     console.log(`Not connected ${err}`)
})