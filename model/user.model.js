import _ from 'lodash';
const { lowerCase } = _;
import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name:{
        type:String,
        required:true,
        lowerCase:true,
    },
    email:{
        type:String,
        required:true,
        lowerCase:true,
        unique:true
    },
    password:{
        type:String,
        required:true,
        lowerCase:true,
    },
    age:{
        type:Number,
    },
    image: String
},{timestamps:true})

export const user = mongoose.model("user",userSchema)