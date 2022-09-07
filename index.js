import express from "express";
import { MongoClient } from "mongodb";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import cors from "cors";
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";
import handlebars from "handlebars";
import fs from "fs";

dotenv.config();

const app = express();
app.use(
  cors({
    origin: "*",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
  })
);

const PORT = process.env.PORT;
const MONGO_URL = process.env.MONGO_URL;

app.use(express.json());

async function createConnection() {
  const client = new MongoClient(MONGO_URL);
  await client.connect();
  console.log("Mongodb connected!!💖");

  return client;
}

const client = await createConnection();

//testing backend:
app.get("/", async (request, response) => {
  response.send({ msg: "Hello world!!" });
});

// users endpoints:
async function getHashedPassword(password) {
  const NO_OF_ROUNDS = 10;
  const salt = await bcrypt.genSalt(NO_OF_ROUNDS);
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
}

async function checkUser(username) {
  return await client
    .db("inventory-billing")
    .collection("users")
    .findOne({ username });
}

app.post("/register", async (request, response) => {
  const { username, password } = request.body;
  const isUserExist = await checkUser(username);

  if (isUserExist) {
    response.send({ msg: "user already exists!!" });
  } else if (password.length < 8) {
    response.send({ msg: "password must be more than 8 characters!!" });
  } else if (username.length < 5) {
    response.send({ msg: "username must be more than 4 characters long!!" });
  } else {
    const hashedPassword = await getHashedPassword(password);
    const result = await client.db("inventory-billing").collection("users").insertOne({
      username,
      password: hashedPassword,
    });

    result.acknowledged
      ? response.status(200).send({ msg: "Account created successfully!!" })
      : response.send({ msg: "Username already exists!!" });
  }
});

app.post("/login", async (request, response) => {
  const { username, password } = request.body;
  const isUserExist = await checkUser(username);

  if (isUserExist) {
    if (password.length < 8) {
      response
        .status(204)
        .send({ msg: "password must be more than 8 characters!!" });
    } else {
      const storedPassword = isUserExist.password;
      const isPasswordMatch = await bcrypt.compare(password, storedPassword);

      if (isPasswordMatch) {
        const token = jwt.sign({ id: isUserExist._id }, process.env.SECRET_KEY);
        response.status(200).send({ msg: "login successful!!" });
      } else {
        response.status(204).send({ msg: "Incorrect credentials!!" });
      }
    }
  } else {
    response.status(204).send({ msg: "please sign up!!" });
  }
});

// bill endpoints
app.post("/bill", async (request, response) => {
  const data = request.body;
  const result = await client
    .db("inventory-billing")
    .collection("bill")
    .insertOne(data);

  result.acknowledged
    ? response
        .status(200)
        .send({ msg: "Please wait while your Invoice is being prepared!!" })
    : response.status(404).send({ msg: "Something went wrong !!" });
});

// sales endpoints:

//get all items
app.get("/sales", async (request, response) => {
  const result = await client
    .db("inventory-billing")
    .collection("sales")
    .find(request.query)
    .toArray();
  response.send(result);
});

//update items
app.put("/updateStocks/:itemName", async (request, response) => {
  const { itemName } = request.params;
  const data = request.body;
  const result = await client
    .db("inventory-billing")
    .collection("sales")
    .updateOne({ item: itemName }, { $set: data });

  result.modifiedCount > 0
    ? response.send({ msg: "Stocks updated sucessfully!!" })
    : response.status(404).send({ msg: "Item not found" });
});

//shopping confirmation
app.post("/shopping-success", async (request, response) => {
  const data = request.body;

  const mailTransporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.USER_MAIL,
      pass: process.env.USER_PASSWORD,
    },
  });

  const filePath = "./template.html";
  const source = fs.readFileSync(filePath, "utf-8").toString();
  const template = handlebars.compile(source);
  const replacements = {
    name: data.name,
    amount: data.amount,
  };
  const htmlToSend = template(replacements);

  const paymentDetails = {
    from: process.env.USER_MAIL,
    to: data.mail,
    subject: "My mart",
    html: htmlToSend,
  };

  mailTransporter.sendMail(paymentDetails, (error) => {
    error
      ? response.status(404).send({ msg: "Purchase failed!!" })
      : response.status(200).send({ msg: "Purchase successful!!" });
  });
});

app.listen(PORT, () => console.log(`App started in ${PORT}`));
