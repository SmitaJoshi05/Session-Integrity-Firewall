require('dotenv').config({ path: './config/.env' })
const express = require('express')
const app = express()

app.use(express.json())

// Health check — confirms server is running
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'SIF is running', time: new Date().toISOString() })
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`SIF server running on port ${PORT}`)
})

module.exports = app