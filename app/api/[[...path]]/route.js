import { MongoClient } from 'mongodb'
import { v4 as uuidv4 } from 'uuid'
import { NextResponse } from 'next/server'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

// MongoDB connection
let client
let db

async function connectToMongo() {
  if (!client) {
    client = new MongoClient(process.env.MONGO_URL)
    await client.connect()
    db = client.db(process.env.DB_NAME)
  }
  return db
}

// Helper function to handle CORS
function handleCORS(response) {
  response.headers.set('Access-Control-Allow-Origin', process.env.CORS_ORIGINS || '*')
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  response.headers.set('Access-Control-Allow-Credentials', 'true')
  return response
}

// JWT secret - in production, this should be a secure environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production'

// Helper to verify JWT token
function verifyToken(request) {
  try {
    const authHeader = request.headers.get('authorization')
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null
    }
    
    const token = authHeader.substring(7)
    const decoded = jwt.verify(token, JWT_SECRET)
    return decoded
  } catch (error) {
    return null
  }
}

// OPTIONS handler for CORS
export async function OPTIONS() {
  return handleCORS(new NextResponse(null, { status: 200 }))
}

// Route handler function
async function handleRoute(request, { params }) {
  const { path = [] } = params
  const route = `/${path.join('/')}`
  const method = request.method

  try {
    const db = await connectToMongo()

    // Root endpoint - GET /api/
    if (route === '/' && method === 'GET') {
      return handleCORS(NextResponse.json({ message: "PassKeeper API is running" }))
    }

    // User Registration - POST /api/auth/register
    if (route === '/auth/register' && method === 'POST') {
      const body = await request.json()
      const { email, password, name } = body

      if (!email || !password || !name) {
        return handleCORS(NextResponse.json(
          { error: "Name, email, and password are required" }, 
          { status: 400 }
        ))
      }

      // Check if user already exists
      const existingUser = await db.collection('users').findOne({ email })
      if (existingUser) {
        return handleCORS(NextResponse.json(
          { error: "User already exists with this email" }, 
          { status: 400 }
        ))
      }

      // Hash password
      const saltRounds = 12
      const hashedPassword = await bcrypt.hash(password, saltRounds)

      // Create user
      const user = {
        id: uuidv4(),
        name,
        email,
        password: hashedPassword,
        createdAt: new Date(),
        updatedAt: new Date()
      }

      await db.collection('users').insertOne(user)

      // Generate JWT token
      const token = jwt.sign(
        { userId: user.id, email: user.email }, 
        JWT_SECRET, 
        { expiresIn: '7d' }
      )

      // Return user data without password
      const { password: _, _id, ...userResponse } = user
      return handleCORS(NextResponse.json({ 
        user: userResponse, 
        token 
      }))
    }

    // User Login - POST /api/auth/login
    if (route === '/auth/login' && method === 'POST') {
      const body = await request.json()
      const { email, password } = body

      if (!email || !password) {
        return handleCORS(NextResponse.json(
          { error: "Email and password are required" }, 
          { status: 400 }
        ))
      }

      // Find user
      const user = await db.collection('users').findOne({ email })
      if (!user) {
        return handleCORS(NextResponse.json(
          { error: "Invalid email or password" }, 
          { status: 401 }
        ))
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.password)
      if (!isValidPassword) {
        return handleCORS(NextResponse.json(
          { error: "Invalid email or password" }, 
          { status: 401 }
        ))
      }

      // Generate JWT token
      const token = jwt.sign(
        { userId: user.id, email: user.email }, 
        JWT_SECRET, 
        { expiresIn: '7d' }
      )

      // Return user data without password
      const { password: _, _id, ...userResponse } = user
      return handleCORS(NextResponse.json({ 
        user: userResponse, 
        token 
      }))
    }

    // Verify Token - GET /api/auth/verify
    if (route === '/auth/verify' && method === 'GET') {
      const decoded = verifyToken(request)
      if (!decoded) {
        return handleCORS(NextResponse.json(
          { error: "Invalid or expired token" }, 
          { status: 401 }
        ))
      }

      // Get user data
      const user = await db.collection('users').findOne({ id: decoded.userId })
      if (!user) {
        return handleCORS(NextResponse.json(
          { error: "User not found" }, 
          { status: 404 }
        ))
      }

      const { password: _, _id, ...userResponse } = user
      return handleCORS(NextResponse.json({ user: userResponse }))
    }

    // Get Vault Items - GET /api/vault
    if (route === '/vault' && method === 'GET') {
      const decoded = verifyToken(request)
      if (!decoded) {
        return handleCORS(NextResponse.json(
          { error: "Authentication required" }, 
          { status: 401 }
        ))
      }

      const vaultItems = await db.collection('vault_items')
        .find({ userId: decoded.userId })
        .toArray()

      // Remove MongoDB's _id field from response
      const cleanedItems = vaultItems.map(({ _id, ...rest }) => rest)
      
      return handleCORS(NextResponse.json(cleanedItems))
    }

    // Create Vault Item - POST /api/vault
    if (route === '/vault' && method === 'POST') {
      const decoded = verifyToken(request)
      if (!decoded) {
        return handleCORS(NextResponse.json(
          { error: "Authentication required" }, 
          { status: 401 }
        ))
      }

      const body = await request.json()
      const { title, username, encryptedPassword, url, notes } = body

      if (!title || !encryptedPassword) {
        return handleCORS(NextResponse.json(
          { error: "Title and password are required" }, 
          { status: 400 }
        ))
      }

      const vaultItem = {
        id: uuidv4(),
        userId: decoded.userId,
        title,
        username: username || '',
        encryptedPassword, // This is already encrypted on client side
        url: url || '',
        notes: notes || '',
        createdAt: new Date(),
        updatedAt: new Date()
      }

      await db.collection('vault_items').insertOne(vaultItem)
      
      // Remove MongoDB's _id field from response
      const { _id, ...itemResponse } = vaultItem
      return handleCORS(NextResponse.json(itemResponse))
    }

    // Update Vault Item - PUT /api/vault/:id
    if (route.startsWith('/vault/') && method === 'PUT') {
      const decoded = verifyToken(request)
      if (!decoded) {
        return handleCORS(NextResponse.json(
          { error: "Authentication required" }, 
          { status: 401 }
        ))
      }

      const itemId = route.split('/vault/')[1]
      const body = await request.json()
      const { title, username, encryptedPassword, url, notes } = body

      const updateData = {
        ...(title && { title }),
        ...(username !== undefined && { username }),
        ...(encryptedPassword && { encryptedPassword }),
        ...(url !== undefined && { url }),
        ...(notes !== undefined && { notes }),
        updatedAt: new Date()
      }

      const result = await db.collection('vault_items').updateOne(
        { id: itemId, userId: decoded.userId },
        { $set: updateData }
      )

      if (result.matchedCount === 0) {
        return handleCORS(NextResponse.json(
          { error: "Vault item not found" }, 
          { status: 404 }
        ))
      }

      return handleCORS(NextResponse.json({ message: "Vault item updated successfully" }))
    }

    // Delete Vault Item - DELETE /api/vault/:id
    if (route.startsWith('/vault/') && method === 'DELETE') {
      const decoded = verifyToken(request)
      if (!decoded) {
        return handleCORS(NextResponse.json(
          { error: "Authentication required" }, 
          { status: 401 }
        ))
      }

      const itemId = route.split('/vault/')[1]
      
      const result = await db.collection('vault_items').deleteOne(
        { id: itemId, userId: decoded.userId }
      )

      if (result.deletedCount === 0) {
        return handleCORS(NextResponse.json(
          { error: "Vault item not found" }, 
          { status: 404 }
        ))
      }

      return handleCORS(NextResponse.json({ message: "Vault item deleted successfully" }))
    }

    // Route not found
    return handleCORS(NextResponse.json(
      { error: `Route ${route} not found` }, 
      { status: 404 }
    ))

  } catch (error) {
    console.error('API Error:', error)
    return handleCORS(NextResponse.json(
      { error: "Internal server error" }, 
      { status: 500 }
    ))
  }
}

// Export all HTTP methods
export const GET = handleRoute
export const POST = handleRoute
export const PUT = handleRoute
export const DELETE = handleRoute
export const PATCH = handleRoute