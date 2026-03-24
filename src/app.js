// require('dotenv').config({ path: './config/.env' })
// const express = require('express')
// const authRouter = require('./routes/auth')
// const app = express()

// app.use(express.json())
// app.use('/auth', authRouter)

// // Health check — confirms server is running
// app.get('/health', (req, res) => {
//   res.status(200).json({ status: 'SIF is running', time: new Date().toISOString() })
// })

// const PORT = process.env.PORT || 3000
// app.listen(PORT, () => {
//   console.log(`SIF server running on port ${PORT}`)
// })

// module.exports = app

require('dotenv').config({ path: './config/.env' })

const express = require('express')
const app = express()

app.use(express.json())

// Trust proxy (important for correct IP detection)
app.set('trust proxy', true)

// Routes
const authRouter = require('./routes/auth')
app.use('/auth', authRouter)

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'SIF is running',
    time: new Date().toISOString()
  })
})

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' })
})

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack)
  res.status(500).json({ error: 'Something went wrong' })
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`SIF server running on port ${PORT}`)
})

module.exports = app