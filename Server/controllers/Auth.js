const User = require('../models/User');
const OTP = require('../models/OTP');
const bcrypt = require('bcrypt');
const Profile = require("../models/Profile");
const jwt = require('jsonwebtoken');
const mailSender = require('../utils/mailSender');
const otpGenerator = require('otp-generator');
require("dotenv").config();

const { passwordUpdated } = require("../mail/templates/passwordUpdate");

const SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT) || 10; // Set salt rounds

// Utility function to generate unique OTP
async function generateUniqueOTP() {
    let otp;
    let isUnique = false;
    
    while (!isUnique) {
        otp = otpGenerator.generate(6, {
            upperCaseAlphabets: false,
            lowerCaseAlphabets: false,
            specialChars: false,
        });
        const existingOTP = await OTP.findOne({ otp });
        if (!existingOTP) isUnique = true;
    }

    return otp;
}

// 📌 Send OTP API
exports.sendotp = async (req, res) => {
    try {
        const { email } = req.body;
        
        // Check if user already exists
        if (await User.findOne({ email })) {
            return res.status(409).json({ success: false, message: "User already registered" });
        }

        // Generate a unique OTP
        const otp = await generateUniqueOTP();

        // Save OTP to database
        await OTP.create({ email, otp });

        console.log("✅ OTP Generated & Saved:", otp);

        return res.status(200).json({ success: true, message: "OTP Sent Successfully" });

    } catch (err) {
        console.error("❌ Error while sending OTP:", err);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
}

// 📌 Signup API
exports.signup = async (req, res) => {
    try {
        const { firstName, lastName, email, password, confirmPassword, accountType, contactNumber, otp } = req.body;

        if (!firstName || !lastName || !email || !password || !confirmPassword || !otp) {
            return res.status(400).json({ success: false, message: "All fields are required" });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ success: false, message: "Passwords do not match" });
        }

        if (await User.findOne({ email })) {
            return res.status(409).json({ success: false, message: "User already registered" });
        }

        // Fetch the latest OTP
        const recentOtp = await OTP.findOne({ email }).sort({ createdAt: -1 });

        if (!recentOtp || recentOtp.otp !== otp) {
            return res.status(400).json({ success: false, message: "Invalid or Expired OTP" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        // Create user profile
        const profileDetails = await Profile.create({ gender: null, dateOfBirth: null, about: null, contactNumber: null });

        // Save user in DB
        const user = await User.create({
            firstName,
            lastName,
            email,
            accountType,
            contactNumber,
            password: hashedPassword,
            additionalDetails: profileDetails._id,
            image: `https://api.dicebear.com/7.x/initials/svg?seed=${firstName}`,
        });

        return res.status(201).json({ success: true, message: "Sign Up Successful", user });

    } catch (err) {
        console.error("❌ Signup Error:", err);
        return res.status(500).json({ success: false, message: "User registration failed" });
    }
}

// 📌 Login API
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, message: "All fields are required" });
        }

        const user = await User.findOne({ email }).populate("additionalDetails");
        if (!user) {
            return res.status(404).json({ success: false, message: "User does not exist" });
        }

        if (!await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ success: false, message: "Incorrect Password" });
        }

        const payload = { email: user.email, id: user._id, accountType: user.accountType };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "10h" });

        user.token = token;
        user.password = undefined;

        res.cookie("token", token, { expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000), httpOnly: true })
            .status(200)
            .json({ success: true, token, user, message: "Logged in successfully" });

    } catch (err) {
        console.error("❌ Login Error:", err);
        return res.status(500).json({ success: false, message: "Login Failed" });
    }
}

// 📌 Change Password API
exports.changePassword = async (req, res) => {
    try {
        const userDetails = await User.findById(req.user.id);
        const { oldPassword, newPassword, confirmNewPassword } = req.body;

        if (!await bcrypt.compare(oldPassword, userDetails.password)) {
            return res.status(401).json({ success: false, message: "Incorrect old password" });
        }

        if (newPassword !== confirmNewPassword) {
            return res.status(400).json({ success: false, message: "New passwords do not match" });
        }

        const encryptedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
        await User.findByIdAndUpdate(req.user.id, { password: encryptedPassword });

        try {
            await mailSender(userDetails.email, passwordUpdated(userDetails.email, `Password updated for ${userDetails.firstName}`));
        } catch (error) {
            console.error("❌ Email Sending Failed:", error);
        }

        return res.status(200).json({ success: true, message: "Password updated successfully" });

    } catch (error) {
        console.error("❌ Change Password Error:", error);
        return res.status(500).json({ success: false, message: "Password update failed" });
    }
}
