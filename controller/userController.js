const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const User = require("../model/userModel");
const { sendEmail } = require("../middleware/sendEmail");
const cloudinary = require("cloudinary").v2;

const createUser = async (req, res) => {
  const { fName, lName, email, phoneNumber, password } = req.body;

  if (!fName || !lName || !email || !phoneNumber || !password) {
    return res.status(400).json({
      success: false,
      message: "Please enter all fields",
    });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists",
      });
    }

    const verificationCode = crypto.randomInt(10000, 99999); 

    const newUser = new User({
      fName,
      lName,
      email,
      phoneNumber,
      password, 
      verificationCode,
      isVerified: false,
    });

    await newUser.save();
    const frontendBaseUrl =
      process.env.FRONTEND_BASE_URL || "http://localhost:3000";
    const verificationUrl = `${frontendBaseUrl}/verify/${verificationCode}`;
    const message = `Please verify your email by clicking the link below:\n\n${verificationUrl}`;

    await sendEmail({
      email: newUser.email,
      subject: "Verify Your Email",
      message,
    });

    res.status(201).json({
      success: true,
      message:
        "User created successfully. Please check your email for verification.",
    });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({
      success: false,
      message: "Server Error",
    });
  }
};

// Verify user email
const verifyEmail = async (req, res) => {
  const { code } = req.params;

  try {
    const user = await User.findOne({ verificationCode: code });
    console.log(user);
    if (!user || user.isVerified) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired verification code",
      });
    }

    user.isVerified = true;
    user.verificationCode = undefined; 
    await user.save();

    res.status(200).json({
      success: true,
      message: "Email verified successfully",
    });
  } catch (error) {
    console.error("Error verifying email:", error);
    res.status(500).json({
      success: false,
      message: "Server Error",
    });
  }
};

// Login user
const loginUser = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: "Please enter all fields",
    });
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "User does not exist",
      });
    }

    if (user.isLocked) {
      const lockTimeLeft = Math.round(
        (user.lockUntil - Date.now()) / 1000 / 60
      );
      return res.status(423).json({
        success: false,
        message: `Account is temporarily locked. Try again in ${lockTimeLeft} minutes.`,
      });
    }
    const isPasswordMatch = await user.comparePassword(password);

    // Password comparison without hashing
    // if (user.password !== password) {
    if (!isPasswordMatch) {
      await user.incrementLoginAttempts();
      const attemptsLeft = 3 - user.loginAttempts;
      const message =
        user.loginAttempts >= 3
          ? "Too many failed login attempts. Try again in 1 minute."
          : `Invalid credentials. ${attemptsLeft} attempt(s) left.`;
      return res.status(400).json({
        success: false,
        message,
      });
    }

    user.loginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();

    const token = jwt.sign(
      { id: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({
      success: true,
      message: "User logged in successfully",
      userId: user._id,
      token,
      userData: user,
    });
  } catch (error) {
    console.error("Backend Error:", error);
    res.status(500).json({
      success: false,
      message: "Server Error",
      error: error.message, // This is important for debugging
    });
  }
};

// Handle forgot password
const forgotPassword = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Email not found",
      });
    }

    const resetToken = user.getResetPasswordToken();
    await user.save({ validateBeforeSave: false });

    const frontendBaseUrl =
      process.env.FRONTEND_BASE_URL || "http://localhost:3000";
    const resetUrl = `${frontendBaseUrl}/password/reset/${resetToken}`;

    const message = `Reset your password by clicking on the link below:\n\n${resetUrl}`;

    try {
      await sendEmail({
        email: user.email,
        subject: "Reset Password",
        message,
      });

      res.status(200).json({
        success: true,
        message: `Email sent to ${user.email}`,
      });
    } catch (error) {
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;
      await user.save({ validateBeforeSave: false });

      console.error("Error sending email:", error);
      res.status(500).json({
        success: false,
        message: "Email could not be sent. Please try again later.",
      });
    }
  } catch (error) {
    console.error("Error in forgotPassword:", error);
    res.status(500).json({
      success: false,
      message: "Server Error",
    });
  }
};

// Handle password reset
const resetPassword = async (req, res) => {
  try {
    const resetPasswordToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");

    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Token is invalid or has expired",
      });
    }

    user.password = req.body.password; 

    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save();

    res.status(200).json({
      success: true,
      message: "Password updated",
    });
  } catch (error) {
    console.error("Error in resetPassword:", error);
    res.status(500).json({
      success: false,
      message: "Server Error",
    });
  }
};

// Get user information
const getUsers = async (req, res) => {
  try {
    const userId = req.params.id || req.user.id;
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "User fetched successfully",
      user,
    });
  } catch (error) {
    console.error("Error in getUsers:", error);
    res.status(500).json({
      success: false,
      message: "Server Error",
    });
  }
};

// Update user profile
const updateUserProfile = async (req, res) => {
  try {
    const userId = req.params.id || req.user.id;
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    let avatarUrl = null;
    if (req.files && req.files.avatar) {
      const { avatar } = req.files;
      const uploadedAvatar = await cloudinary.uploader.upload(avatar.path, {
        folder: "avatars",
      });

      if (!uploadedAvatar || !uploadedAvatar.secure_url) {
        return res.status(500).json({
          success: false,
          message: "Failed to upload avatar to Cloudinary",
        });
      }

      avatarUrl = uploadedAvatar.secure_url;
    } else {
      avatarUrl = req.body.avatar;
    }

    const updateData = {
      ...req.body,
      avatar: avatarUrl,
    };

    const updatedUser = await User.findByIdAndUpdate(userId, updateData, {
      new: true,
    });

    res.status(200).json({
      success: true,
      message: "User profile updated successfully",
      user: updatedUser,
    });
  } catch (error) {
    console.error("Error in updateUserProfile:", error);
    res.status(500).json({
      success: false,
      message: "Server Error",
    });
  }
};

module.exports = {
  createUser,
  loginUser,
  forgotPassword,
  resetPassword,
  getUsers,
  updateUserProfile,
  verifyEmail,
};
