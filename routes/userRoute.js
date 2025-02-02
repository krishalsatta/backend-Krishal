const router = require("express").Router();
const userController = require("../controller/userController");
const authGuard = require("../middleware/auth");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const User = require("../model/userModel"); // Adjust the path to your User model

// User routes
router.post("/create", userController.createUser);
router.post("/login", userController.loginUser);
router.post("/forgot/password", userController.forgotPassword);
router.put("/password/reset/:token", userController.resetPassword);
router.get("/getUsers/:id?", authGuard, userController.getUsers);
router.patch("/updateUser/:id?", authGuard, userController.updateUserProfile);

// Send Verification Email
router.post("/send-verification-email", async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Generate verification token
    const verificationToken = crypto.randomBytes(20).toString("hex");
    user.verificationToken = crypto
      .createHash("sha256")
      .update(verificationToken)
      .digest("hex");
    user.verificationTokenExpire = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    // Send verification email
    const verificationUrl = `http://localhost:3000/verify/${verificationToken}`;

    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const mailOptions = {
      from: "sijankasalawat3339@gmail.com",
      to: user.email,
      subject: "Email Verification",
      text: `Please verify your email by clicking on the following link: ${verificationUrl}`,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: "Verification email sent" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Verify Email
router.get("/verify-email/:token", async (req, res) => {
  const { token } = req.params;

  console.log("Received token:", token); // Log the received token

  try {
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    console.log("Hashed token:", hashedToken); // Log the hashed token

    const user = await User.findOne({
      verificationToken: hashedToken,
      verificationTokenExpire: { $gt: Date.now() }, // Check if token is still valid
    });

    if (!user) {
      console.log("User not found or token expired");
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpire = undefined;
    await user.save();

    console.log("Email successfully verified for user:", user.email);
    res.status(200).json({ message: "Email successfully verified" });
  } catch (error) {
    console.error("Error during email verification:", error);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
