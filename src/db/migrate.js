require('dotenv').config({ path: './config/.env' })
const fs   = require('fs')
const path = require('path')
const pool = require('./connection')

const migrationsDir = path.join(__dirname, 'migrations')

async function runMigrations() {
  const files = fs.readdirSync(migrationsDir)
    .filter(f => f.endsWith('.sql'))
    .sort()

  console.log(`Found ${files.length} migration(s). Running...\n`)

  for (const file of files) {
    const filePath = path.join(migrationsDir, file)
    const sql = fs.readFileSync(filePath, 'utf8')
    try {
      await pool.query(sql)
      console.log(`✓  ${file}`)
    } catch (err) {
      console.error(`✗  ${file} — ${err.message}`)
      process.exit(1)
    }
  }

  console.log('\nAll migrations complete.')
  process.exit(0)
}

runMigrations()