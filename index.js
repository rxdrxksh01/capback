const cors = require("cors");
const bcrypt = require("bcrypt");
const express = require("express");
const {prisma} = require("./db"); // make sure db.js exports new PrismaClient()
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors({
  origin: "*",
}));

const privatekey = process.env.JWT_SECRET;

// ========================= SIGNUP =========================
app.post("/signup", async (req, res) => {
  const { email, password, name } = req.body;

  // Basic manual checks
  if (!email || !password || !name) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return res.status(409).json({ message: "User already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user
    const newUser = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });

    // Generate token
    const token = jwt.sign({ id: newUser.id }, privatekey, { expiresIn: "1h" });

    res.status(201).json({
      message: "Signup successful",
      token,
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// ========================= LOGIN =========================
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email & password required" });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user.id }, privatekey, { expiresIn: "1h" });

    res.json({
      message: "Login successful",
      token,
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.listen(3000, () => console.log("🚀 Server running on port 3000"));
