import { PrismaClient } from '@prisma/client'

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined
}

/**
 * Create a Prisma client that works both locally and on Vercel.
 *
 * On Vercel with PostgreSQL (Neon): Uses the DATABASE_URL connection string.
 * If DATABASE_URL is empty/missing: Returns null — API routes check for this
 * and return graceful degradation messages instead of crashing.
 */

function createPrismaClient(): PrismaClient | null {
  const url = process.env.DATABASE_URL

  // No DATABASE_URL configured — return null (serverless mode)
  if (!url || url.trim() === '') {
    console.warn('[DB] DATABASE_URL not configured — running in serverless mode without database')
    return null
  }

  // SQLite URLs won't work on Vercel
  if (process.env.VERCEL === '1' && url.startsWith('file:')) {
    console.warn('[DB] SQLite DATABASE_URL not supported on Vercel — running without database')
    return null
  }

  try {
    return new PrismaClient({
      log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
    })
  } catch (err) {
    console.error('[DB] Failed to create Prisma client:', err)
    return null
  }
}

export const db = globalForPrisma.prisma ?? createPrismaClient()!

// In development, cache the client to avoid creating multiple instances
if (process.env.NODE_ENV !== 'production' && db) {
  globalForPrisma.prisma = db
}

/**
 * Check if the database is available.
 * Returns false if DATABASE_URL is not configured or connection fails.
 */
export async function isDatabaseAvailable(): Promise<boolean> {
  if (!db) return false

  try {
    await db.$queryRaw`SELECT 1`
    return true
  } catch {
    return false
  }
}
