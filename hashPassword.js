const bcrypt = require("bcryptjs");

async function hashPassword(plainPassword) {
  try {
    const hashedPassword = await bcrypt.hash(plainPassword, 5); // 10 is the salt rounds
    console.log("Hashed password:", hashedPassword);
  } catch (error) {
    console.error("Error hashing password:", error);
  }
}

hashPassword("admin"); // Replace with your actual password
