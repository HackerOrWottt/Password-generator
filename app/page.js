'use client'

import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Slider } from '@/components/ui/slider'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Copy, RefreshCw, Shield, Eye, EyeOff, CheckCircle, Plus, Edit, Trash2, LogOut, Search, User, Lock } from 'lucide-react'
import { toast } from 'sonner'
import CryptoJS from 'crypto-js'

const AuthPage = ({ onLogin }) => {
  const [isLogin, setIsLogin] = useState(true)
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: ''
  })
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    
    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register'
      const payload = isLogin 
        ? { email: formData.email, password: formData.password }
        : formData

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Something went wrong')
      }

      // Store token and user data
      localStorage.setItem('token', data.token)
      localStorage.setItem('user', JSON.stringify(data.user))
      
      toast.success(isLogin ? 'Welcome back!' : 'Account created successfully!')
      onLogin(data.user, data.token)
      
    } catch (error) {
      toast.error(error.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-primary flex items-center justify-center p-4">
      <Card className="w-full max-w-md bg-black/40 border-red-900/50 backdrop-blur-sm">
        <CardHeader className="text-center">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="h-8 w-8 text-red-400" />
            <h1 className="text-3xl font-bold text-white">PassKeeper</h1>
          </div>
          <CardTitle className="text-white">
            {isLogin ? 'Welcome Back' : 'Create Account'}
          </CardTitle>
          <CardDescription className="text-gray-400">
            {isLogin ? 'Sign in to access your secure vault' : 'Start securing your passwords today'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            {!isLogin && (
              <div className="space-y-2">
                <Label htmlFor="name" className="text-white">Full Name</Label>
                <Input
                  id="name"
                  type="text"
                  placeholder="John Doe"
                  value={formData.name}
                  onChange={(e) => setFormData({...formData, name: e.target.value})}
                  className="bg-gray-900/50 border-red-900/50 text-white placeholder:text-gray-500"
                  required={!isLogin}
                />
              </div>
            )}
            
            <div className="space-y-2">
              <Label htmlFor="email" className="text-white">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="john@example.com"
                value={formData.email}
                onChange={(e) => setFormData({...formData, email: e.target.value})}
                className="bg-gray-900/50 border-red-900/50 text-white placeholder:text-gray-500"
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="password" className="text-white">Password</Label>
              <Input
                id="password"
                type="password"
                placeholder="••••••••"
                value={formData.password}
                onChange={(e) => setFormData({...formData, password: e.target.value})}
                className="bg-gray-900/50 border-red-900/50 text-white placeholder:text-gray-500"
                required
              />
            </div>

            <Button 
              type="submit" 
              className="w-full bg-red-600 hover:bg-red-700 text-white"
              disabled={loading}
            >
              {loading ? 'Loading...' : (isLogin ? 'Sign In' : 'Create Account')}
            </Button>
          </form>

          <div className="mt-4 text-center">
            <button
              type="button"
              onClick={() => setIsLogin(!isLogin)}
              className="text-red-400 hover:text-red-300 text-sm"
            >
              {isLogin ? "Don't have an account? Sign up" : "Already have an account? Sign in"}
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

const PasswordGenerator = ({ user, token, onSaveToVault }) => {
  const [passwordLength, setPasswordLength] = useState([16])
  const [includeUppercase, setIncludeUppercase] = useState(true)
  const [includeLowercase, setIncludeLowercase] = useState(true)
  const [includeNumbers, setIncludeNumbers] = useState(true)
  const [includeSymbols, setIncludeSymbols] = useState(true)
  const [excludeSimilar, setExcludeSimilar] = useState(true)
  const [generatedPassword, setGeneratedPassword] = useState('')
  const [passwordStrength, setPasswordStrength] = useState(0)
  const [showPassword, setShowPassword] = useState(true)
  const [copied, setCopied] = useState(false)
  const [showSaveDialog, setShowSaveDialog] = useState(false)
  const [saveData, setSaveData] = useState({
    title: '',
    username: '',
    url: '',
    notes: ''
  })

  // Character sets
  const charsets = {
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lowercase: 'abcdefghijklmnopqrstuvwxyz', 
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
    similar: 'il1Lo0O'
  }

  const generatePassword = () => {
    let charset = ''
    
    if (includeUppercase) charset += charsets.uppercase
    if (includeLowercase) charset += charsets.lowercase
    if (includeNumbers) charset += charsets.numbers
    if (includeSymbols) charset += charsets.symbols
    
    if (excludeSimilar) {
      charset = charset.split('').filter(char => !charsets.similar.includes(char)).join('')
    }
    
    if (charset === '') {
      toast.error('Please select at least one character type!')
      return
    }
    
    const guaranteedChars = []
    if (includeUppercase) {
      const uppers = excludeSimilar ? 
        charsets.uppercase.split('').filter(c => !charsets.similar.includes(c)) : 
        charsets.uppercase.split('')
      guaranteedChars.push(uppers[Math.floor(Math.random() * uppers.length)])
    }
    if (includeLowercase) {
      const lowers = excludeSimilar ? 
        charsets.lowercase.split('').filter(c => !charsets.similar.includes(c)) : 
        charsets.lowercase.split('')
      guaranteedChars.push(lowers[Math.floor(Math.random() * lowers.length)])
    }
    if (includeNumbers) {
      const nums = excludeSimilar ? 
        charsets.numbers.split('').filter(c => !charsets.similar.includes(c)) : 
        charsets.numbers.split('')
      guaranteedChars.push(nums[Math.floor(Math.random() * nums.length)])
    }
    if (includeSymbols) {
      guaranteedChars.push(charsets.symbols[Math.floor(Math.random() * charsets.symbols.length)])
    }
    
    const length = passwordLength[0]
    for (let i = guaranteedChars.length; i < length; i++) {
      guaranteedChars.push(charset[Math.floor(Math.random() * charset.length)])
    }
    
    for (let i = guaranteedChars.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1))
      ;[guaranteedChars[i], guaranteedChars[j]] = [guaranteedChars[j], guaranteedChars[i]]
    }
    
    const password = guaranteedChars.join('')
    setGeneratedPassword(password)
    calculateStrength(password)
  }

  const calculateStrength = (password) => {
    let score = 0
    if (password.length >= 8) score += 20
    if (password.length >= 12) score += 15
    if (password.length >= 16) score += 15
    if (/[a-z]/.test(password)) score += 10
    if (/[A-Z]/.test(password)) score += 10
    if (/[0-9]/.test(password)) score += 10
    if (/[^A-Za-z0-9]/.test(password)) score += 15
    
    const uniqueChars = new Set(password).size
    if (uniqueChars > password.length * 0.7) score += 5
    
    setPasswordStrength(Math.min(100, score))
  }

  const getStrengthLabel = (strength) => {
    if (strength < 30) return { label: 'Weak', color: 'bg-red-500' }
    if (strength < 60) return { label: 'Fair', color: 'bg-yellow-500' }
    if (strength < 80) return { label: 'Good', color: 'bg-blue-500' }
    return { label: 'Strong', color: 'bg-green-500' }
  }

  const copyToClipboard = async () => {
    if (!generatedPassword) {
      toast.error('No password to copy!')
      return
    }
    
    try {
      // Try modern clipboard API first
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(generatedPassword)
      } else {
        // Fallback for older browsers or non-HTTPS
        const textArea = document.createElement('textarea')
        textArea.value = generatedPassword
        textArea.style.position = 'fixed'
        textArea.style.left = '-999999px'
        textArea.style.top = '-999999px'
        document.body.appendChild(textArea)
        textArea.focus()
        textArea.select()
        document.execCommand('copy')
        textArea.remove()
      }
      
      setCopied(true)
      toast.success('Password copied to clipboard!')
      
      // Auto-clear clipboard after 15 seconds (only if modern API available)
      setTimeout(() => {
        if (navigator.clipboard && window.isSecureContext) {
          navigator.clipboard.writeText('').catch(() => {})
        }
        toast.info('Clipboard cleared for security')
      }, 15000)
      
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Copy error:', err)
      toast.error('Failed to copy password. Please select and copy manually.')
    }
  }

  const handleSaveToVault = async () => {
    if (!generatedPassword) {
      toast.error('No password to save!')
      return
    }
    
    if (!saveData.title.trim()) {
      toast.error('Please enter a title for this password')
      return
    }
    
    try {
      // Encrypt the password client-side
      const encryptionKey = `passkeeper_${user.email}_${user.id.slice(0, 8)}`
      const encryptedPassword = CryptoJS.AES.encrypt(generatedPassword, encryptionKey).toString()
      
      const response = await fetch('/api/vault', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          title: saveData.title.trim(),
          username: saveData.username.trim(),
          encryptedPassword,
          url: saveData.url.trim(),
          notes: saveData.notes.trim()
        })
      })

      if (response.ok) {
        toast.success('Password saved to vault!')
        setShowSaveDialog(false)
        setSaveData({ title: '', username: '', url: '', notes: '' })
        if (onSaveToVault) onSaveToVault() // Refresh vault if callback provided
      } else {
        toast.error('Failed to save password')
      }
    } catch (error) {
      toast.error('Error saving password')
    }
  }

  useEffect(() => {
    generatePassword()
  }, [passwordLength, includeUppercase, includeLowercase, includeNumbers, includeSymbols, excludeSimilar])

  const strengthInfo = getStrengthLabel(passwordStrength)

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card className="bg-black/40 border-red-900/50 backdrop-blur-sm">
        <CardHeader>
          <CardTitle className="text-white">Generator Settings</CardTitle>
          <CardDescription className="text-gray-400">
            Customize your password requirements
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-3">
            <Label className="text-sm font-medium text-white">
              Length: {passwordLength[0]} characters
            </Label>
            <Slider
              value={passwordLength}
              onValueChange={setPasswordLength}
              max={128}
              min={4}
              step={1}
              className="w-full"
            />
            <div className="flex justify-between text-xs text-gray-500">
              <span>4</span>
              <span>128</span>
            </div>
          </div>

          <Separator className="bg-red-900/30" />

          <div className="space-y-4">
            <Label className="text-sm font-medium text-white">Character Types</Label>
            
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Label htmlFor="uppercase" className="text-sm text-gray-300">
                  Uppercase Letters (A-Z)
                </Label>
                <Switch
                  id="uppercase"
                  checked={includeUppercase}
                  onCheckedChange={setIncludeUppercase}
                />
              </div>

              <div className="flex items-center justify-between">
                <Label htmlFor="lowercase" className="text-sm text-gray-300">
                  Lowercase Letters (a-z)
                </Label>
                <Switch
                  id="lowercase"
                  checked={includeLowercase}
                  onCheckedChange={setIncludeLowercase}
                />
              </div>

              <div className="flex items-center justify-between">
                <Label htmlFor="numbers" className="text-sm text-gray-300">
                  Numbers (0-9)
                </Label>
                <Switch
                  id="numbers"
                  checked={includeNumbers}
                  onCheckedChange={setIncludeNumbers}
                />
              </div>

              <div className="flex items-center justify-between">
                <Label htmlFor="symbols" className="text-sm text-gray-300">
                  Symbols (!@#$%...)
                </Label>
                <Switch
                  id="symbols"
                  checked={includeSymbols}
                  onCheckedChange={setIncludeSymbols}
                />
              </div>

              <div className="flex items-center justify-between">
                <Label htmlFor="exclude-similar" className="text-sm text-gray-300">
                  Exclude Similar Characters (il1Lo0O)
                </Label>
                <Switch
                  id="exclude-similar"
                  checked={excludeSimilar}
                  onCheckedChange={setExcludeSimilar}
                />
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-black/40 border-red-900/50 backdrop-blur-sm">
        <CardHeader>
          <CardTitle className="text-white">Generated Password</CardTitle>
          <CardDescription className="text-gray-400">
            Your secure password is ready
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-3">
            <div className="relative">
              <Input
                type={showPassword ? "text" : "password"}
                value={generatedPassword}
                readOnly
                className="pr-20 bg-gray-900/50 border-red-900/50 text-white font-mono text-lg"
              />
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setShowPassword(!showPassword)}
                  className="h-8 w-8 p-0 text-gray-400 hover:text-white"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <Label className="text-sm text-gray-300">Strength</Label>
                <Badge variant="outline" className={`${strengthInfo.color} text-white border-0`}>
                  {strengthInfo.label}
                </Badge>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div
                  className={`h-2 rounded-full transition-all duration-300 ${strengthInfo.color}`}
                  style={{ width: `${passwordStrength}%` }}
                />
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex gap-2">
              <Button 
                onClick={generatePassword} 
                className="flex-1 bg-red-600 hover:bg-red-700"
              >
                <RefreshCw className="h-4 w-4 mr-2" />
                Generate New
              </Button>
              <Button 
                onClick={copyToClipboard}
                variant="outline"
                className="flex-1 border-red-600 text-white hover:bg-red-900/30"
              >
                {copied ? (
                  <CheckCircle className="h-4 w-4 mr-2 text-green-500" />
                ) : (
                  <Copy className="h-4 w-4 mr-2" />
                )}
                {copied ? 'Copied!' : 'Copy'}
              </Button>
            </div>
            
            <Dialog open={showSaveDialog} onOpenChange={setShowSaveDialog}>
              <DialogTrigger asChild>
                <Button 
                  className="w-full bg-green-600 hover:bg-green-700"
                  disabled={!generatedPassword}
                >
                  <Plus className="h-4 w-4 mr-2" />
                  Save to Vault
                </Button>
              </DialogTrigger>
              <DialogContent className="bg-black/90 border-red-900/50">
                <DialogHeader>
                  <DialogTitle className="text-white">Save Password to Vault</DialogTitle>
                  <DialogDescription className="text-gray-400">
                    Save your generated password to the secure vault
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4">
                  <Input
                    placeholder="Title (e.g. Gmail, Facebook) *"
                    value={saveData.title}
                    onChange={(e) => setSaveData({...saveData, title: e.target.value})}
                    className="bg-gray-900/50 border-red-900/50 text-white"
                  />
                  <Input
                    placeholder="Username or Email"
                    value={saveData.username}
                    onChange={(e) => setSaveData({...saveData, username: e.target.value})}
                    className="bg-gray-900/50 border-red-900/50 text-white"
                  />
                  <Input
                    placeholder="Website URL (optional)"
                    value={saveData.url}
                    onChange={(e) => setSaveData({...saveData, url: e.target.value})}
                    className="bg-gray-900/50 border-red-900/50 text-white"
                  />
                  <Input
                    placeholder="Notes (optional)"
                    value={saveData.notes}
                    onChange={(e) => setSaveData({...saveData, notes: e.target.value})}
                    className="bg-gray-900/50 border-red-900/50 text-white"
                  />
                  <div className="bg-gray-900/50 border border-red-900/30 rounded-lg p-3">
                    <p className="text-xs text-gray-400 mb-2">Password to save:</p>
                    <p className="text-sm font-mono text-white break-all">{generatedPassword}</p>
                  </div>
                </div>
                <DialogFooter>
                  <Button onClick={handleSaveToVault} className="bg-green-600 hover:bg-green-700">
                    Save to Vault
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>

          <div className="bg-gray-900/50 border border-red-900/30 rounded-lg p-3">
            <p className="text-xs text-gray-400">
              🔒 <span className="font-medium">Security Note:</span> This password is generated locally in your browser. 
              When copied, it will automatically be cleared from your clipboard after 15 seconds.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

const VaultManager = ({ user, token, refreshTrigger }) => {
  const [vaultItems, setVaultItems] = useState([])
  const [searchTerm, setSearchTerm] = useState('')
  const [loading, setLoading] = useState(false)
  const [editingItem, setEditingItem] = useState(null)
  const [showAddDialog, setShowAddDialog] = useState(false)
  const [newItem, setNewItem] = useState({
    title: '',
    username: '',
    password: '',
    url: '',
    notes: ''
  })

  // Encryption key derived from user's password (in real app, use more secure method)
  const encryptionKey = `passkeeper_${user.email}_${user.id.slice(0, 8)}`

  const encryptPassword = (password) => {
    return CryptoJS.AES.encrypt(password, encryptionKey).toString()
  }

  const decryptPassword = (encryptedPassword) => {
    try {
      const bytes = CryptoJS.AES.decrypt(encryptedPassword, encryptionKey)
      return bytes.toString(CryptoJS.enc.Utf8)
    } catch (error) {
      console.error('Decryption error:', error)
      return '[Decryption Error]'
    }
  }

  const fetchVaultItems = async () => {
    setLoading(true)
    try {
      const response = await fetch('/api/vault', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })

      if (response.ok) {
        const items = await response.json()
        setVaultItems(items)
      } else {
        toast.error('Failed to load vault items')
      }
    } catch (error) {
      toast.error('Error loading vault items')
    } finally {
      setLoading(false)
    }
  }

  const saveVaultItem = async () => {
    if (!newItem.title || !newItem.password) {
      toast.error('Title and password are required')
      return
    }

    try {
      const encryptedPassword = encryptPassword(newItem.password)
      
      const response = await fetch('/api/vault', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          ...newItem,
          encryptedPassword
        })
      })

      if (response.ok) {
        toast.success('Password saved to vault!')
        setShowAddDialog(false)
        setNewItem({ title: '', username: '', password: '', url: '', notes: '' })
        fetchVaultItems()
      } else {
        toast.error('Failed to save password')
      }
    } catch (error) {
      toast.error('Error saving password')
    }
  }

  const deleteVaultItem = async (itemId) => {
    try {
      const response = await fetch(`/api/vault/${itemId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })

      if (response.ok) {
        toast.success('Password deleted')
        fetchVaultItems()
      } else {
        toast.error('Failed to delete password')
      }
    } catch (error) {
      toast.error('Error deleting password')
    }
  }

  const copyPassword = async (encryptedPassword) => {
    try {
      const decryptedPassword = decryptPassword(encryptedPassword)
      
      // Try modern clipboard API first
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(decryptedPassword)
      } else {
        // Fallback for older browsers or non-HTTPS
        const textArea = document.createElement('textarea')
        textArea.value = decryptedPassword
        textArea.style.position = 'fixed'
        textArea.style.left = '-999999px'
        textArea.style.top = '-999999px'
        document.body.appendChild(textArea)
        textArea.focus()
        textArea.select()
        document.execCommand('copy')
        textArea.remove()
      }
      
      toast.success('Password copied!')
      
      // Auto-clear clipboard after 15 seconds (only if modern API available)
      setTimeout(() => {
        if (navigator.clipboard && window.isSecureContext) {
          navigator.clipboard.writeText('').catch(() => {})
        }
        toast.info('Clipboard cleared for security')
      }, 15000)
    } catch (error) {
      console.error('Copy error:', error)
      toast.error('Failed to copy password. Please select and copy manually.')
    }
  }

  useEffect(() => {
    fetchVaultItems()
  }, [])

  const filteredItems = vaultItems.filter(item =>
    item.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    item.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
    item.url.toLowerCase().includes(searchTerm.toLowerCase())
  )

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-white">Your Vault</h2>
          <p className="text-gray-400">Securely encrypted password storage</p>
        </div>
        <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
          <DialogTrigger asChild>
            <Button className="bg-red-600 hover:bg-red-700">
              <Plus className="h-4 w-4 mr-2" />
              Add Password
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-black/90 border-red-900/50">
            <DialogHeader>
              <DialogTitle className="text-white">Add New Password</DialogTitle>
              <DialogDescription className="text-gray-400">
                Add a new password to your secure vault
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <Input
                placeholder="Title (e.g. Gmail, Facebook)"
                value={newItem.title}
                onChange={(e) => setNewItem({...newItem, title: e.target.value})}
                className="bg-gray-900/50 border-red-900/50 text-white"
              />
              <Input
                placeholder="Username or Email"
                value={newItem.username}
                onChange={(e) => setNewItem({...newItem, username: e.target.value})}
                className="bg-gray-900/50 border-red-900/50 text-white"
              />
              <Input
                placeholder="Password"
                type="password"
                value={newItem.password}
                onChange={(e) => setNewItem({...newItem, password: e.target.value})}
                className="bg-gray-900/50 border-red-900/50 text-white"
              />
              <Input
                placeholder="Website URL (optional)"
                value={newItem.url}
                onChange={(e) => setNewItem({...newItem, url: e.target.value})}
                className="bg-gray-900/50 border-red-900/50 text-white"
              />
              <Input
                placeholder="Notes (optional)"
                value={newItem.notes}
                onChange={(e) => setNewItem({...newItem, notes: e.target.value})}
                className="bg-gray-900/50 border-red-900/50 text-white"
              />
            </div>
            <DialogFooter>
              <Button onClick={saveVaultItem} className="bg-red-600 hover:bg-red-700">
                Save to Vault
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      <div className="relative">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
        <Input
          placeholder="Search passwords..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="pl-10 bg-gray-900/50 border-red-900/50 text-white"
        />
      </div>

      {loading ? (
        <div className="text-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500 mx-auto"></div>
          <p className="text-gray-400 mt-2">Loading your vault...</p>
        </div>
      ) : (
        <div className="grid gap-4">
          {filteredItems.length === 0 ? (
            <Card className="bg-black/40 border-red-900/50">
              <CardContent className="text-center py-8">
                <Lock className="h-16 w-16 text-red-400 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-white mb-2">No passwords found</h3>
                <p className="text-gray-400">
                  {searchTerm ? 'Try a different search term' : 'Add your first password to get started'}
                </p>
              </CardContent>
            </Card>
          ) : (
            filteredItems.map((item) => (
              <Card key={item.id} className="bg-black/40 border-red-900/50">
                <CardContent className="p-4">
                  <div className="flex justify-between items-start">
                    <div className="flex-1">
                      <h3 className="font-semibold text-white">{item.title}</h3>
                      {item.username && (
                        <p className="text-sm text-gray-400 mt-1">
                          <User className="inline h-3 w-3 mr-1" />
                          {item.username}
                        </p>
                      )}
                      {item.url && (
                        <p className="text-sm text-gray-400">
                          🌐 {item.url}
                        </p>
                      )}
                      {item.notes && (
                        <p className="text-sm text-gray-400 mt-2">{item.notes}</p>
                      )}
                    </div>
                    <div className="flex gap-2 ml-4">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => copyPassword(item.encryptedPassword)}
                        className="border-red-600 text-red-400 hover:bg-red-900/30"
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => deleteVaultItem(item.id)}
                        className="border-red-600 text-red-400 hover:bg-red-900/30"
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>
      )}
    </div>
  )
}

const MainApp = ({ user, token, onLogout }) => {
  const [activeTab, setActiveTab] = useState('generator')
  const [vaultRefreshTrigger, setVaultRefreshTrigger] = useState(0)

  const handleVaultSave = () => {
    setVaultRefreshTrigger(prev => prev + 1)
    setActiveTab('vault') // Switch to vault tab to see the saved password
  }

  return (
    <div className="min-h-screen bg-gradient-primary p-4">
      <div className="max-w-6xl mx-auto py-8">
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div className="flex items-center gap-3">
            <Shield className="h-8 w-8 text-red-400" />
            <div>
              <h1 className="text-3xl font-bold text-white">PassKeeper</h1>
              <p className="text-gray-400">Welcome back, {user.name}</p>
            </div>
          </div>
          <Button 
            onClick={onLogout}
            variant="outline" 
            className="border-red-600 text-red-400 hover:bg-red-900/30"
          >
            <LogOut className="h-4 w-4 mr-2" />
            Logout
          </Button>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-2 bg-black/40 border-red-900/50">
            <TabsTrigger value="generator" className="data-[state=active]:bg-red-600">
              Password Generator
            </TabsTrigger>
            <TabsTrigger value="vault" className="data-[state=active]:bg-red-600">
              Secure Vault
            </TabsTrigger>
          </TabsList>

          <TabsContent value="generator" className="space-y-6">
            <PasswordGenerator 
              user={user} 
              token={token} 
              onSaveToVault={handleVaultSave}
            />
          </TabsContent>

          <TabsContent value="vault" className="space-y-6">
            <VaultManager 
              user={user} 
              token={token} 
              refreshTrigger={vaultRefreshTrigger}
            />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}

const App = () => {
  const [user, setUser] = useState(null)
  const [token, setToken] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Check for existing authentication
    const storedToken = localStorage.getItem('token')
    const storedUser = localStorage.getItem('user')
    
    if (storedToken && storedUser) {
      // Verify token is still valid
      fetch('/api/auth/verify', {
        headers: {
          'Authorization': `Bearer ${storedToken}`
        }
      })
      .then(response => {
        if (response.ok) {
          setToken(storedToken)
          setUser(JSON.parse(storedUser))
        } else {
          localStorage.removeItem('token')
          localStorage.removeItem('user')
        }
      })
      .catch(() => {
        localStorage.removeItem('token')
        localStorage.removeItem('user')
      })
      .finally(() => {
        setLoading(false)
      })
    } else {
      setLoading(false)
    }
  }, [])

  const handleLogin = (userData, userToken) => {
    setUser(userData)
    setToken(userToken)
  }

  const handleLogout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    setUser(null)
    setToken(null)
    toast.success('Logged out successfully')
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-primary flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500 mx-auto mb-4"></div>
          <p className="text-white">Loading PassKeeper...</p>
        </div>
      </div>
    )
  }

  return user && token ? (
    <MainApp user={user} token={token} onLogout={handleLogout} />
  ) : (
    <AuthPage onLogin={handleLogin} />
  )
}

export default App