// Importing Packages
const express = require("express");
const dotenv = require("dotenv");
const connectToDB = require("./database/db.js");
const cors = require("cors");
const cloudinary = require("cloudinary").v2;
const acceptMultimedia = require("connect-multiparty");
const morgan = require("morgan");
const path = require("path");
const securityMiddleware = require("./middleware/securityMiddleware.js");
const { errorHandler } = require("./middleware/errorMiddleware.js");
const https = require("https");
const fs = require("fs");

const app = express();

dotenv.config();

connectToDB();

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET,
});

// Middleware
app.use(morgan("dev")); // Use 'dev' for concise output during development
app.use(
  cors({
    origin: true,
    credentials: true,
    optionSuccessStatus: 200,
  })
);
app.use(express.json());
app.use(acceptMultimedia());
app.use(securityMiddleware);

// Define routes
app.use("/api/user", require("./routes/userRoute.js"));
app.use("/api/product", require("./routes/productRoutes.js"));

// Test route
app.get("/test", (req, res) => {
  res.status(200).json({ message: "Hello World test api is working" });
});

// Hello route
app.get("/hello", (req, res) => {
  res.status(200).send({
    message: "Hello World!",
  });
});

// Error handling middleware
app.use(errorHandler);
const options = {
  key: fs.readFileSync(path.resolve(__dirname, "server.key")),
  cert: fs.readFileSync(path.resolve(__dirname, "server.crt")),
}; // Define port
const PORT = process.env.PORT;
https.createServer(options, app).listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;
