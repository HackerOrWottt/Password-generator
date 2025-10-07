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
import { Copy, RefreshCw, Shield, Eye, EyeOff, CheckCircle } from 'lucide-react'
import { toast } from 'sonner'

const PasswordGenerator = () => {
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

  // Character sets
  const charsets = {
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lowercase: 'abcdefghijklmnopqrstuvwxyz', 
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
    similar: 'il1Lo0O' // Characters to exclude when excludeSimilar is true
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
    
    let password = ''
    const length = passwordLength[0]
    
    // Ensure at least one character from each selected type
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
    
    // Fill the rest with random characters
    for (let i = guaranteedChars.length; i < length; i++) {
      guaranteedChars.push(charset[Math.floor(Math.random() * charset.length)])
    }
    
    // Shuffle the guaranteed characters
    for (let i = guaranteedChars.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1))
      ;[guaranteedChars[i], guaranteedChars[j]] = [guaranteedChars[j], guaranteedChars[i]]
    }
    
    password = guaranteedChars.join('')
    setGeneratedPassword(password)
    calculateStrength(password)
  }

  const calculateStrength = (password) => {
    let score = 0
    
    // Length scoring
    if (password.length >= 8) score += 20
    if (password.length >= 12) score += 15
    if (password.length >= 16) score += 15
    
    // Character variety scoring
    if (/[a-z]/.test(password)) score += 10
    if (/[A-Z]/.test(password)) score += 10
    if (/[0-9]/.test(password)) score += 10
    if (/[^A-Za-z0-9]/.test(password)) score += 15
    
    // Bonus for complexity
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
      await navigator.clipboard.writeText(generatedPassword)
      setCopied(true)
      toast.success('Password copied to clipboard!')
      
      // Auto-clear after 15 seconds
      setTimeout(() => {
        if (navigator.clipboard) {
          navigator.clipboard.writeText('')
        }
        toast.info('Clipboard cleared for security')
      }, 15000)
      
      // Reset copy status after 2 seconds
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      toast.error('Failed to copy password')
    }
  }

  // Generate initial password
  useEffect(() => {
    generatePassword()
  }, [passwordLength, includeUppercase, includeLowercase, includeNumbers, includeSymbols, excludeSimilar])

  const strengthInfo = getStrengthLabel(passwordStrength)

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-4">
      <div className="max-w-4xl mx-auto py-8">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="h-8 w-8 text-purple-400" />
            <h1 className="text-4xl font-bold text-white">PassKeeper</h1>
          </div>
          <p className="text-lg text-slate-300">Generate secure passwords and manage your vault</p>
        </div>

        <Tabs defaultValue="generator" className="space-y-6">
          <TabsList className="grid w-full grid-cols-2 bg-slate-800 border-slate-700">
            <TabsTrigger value="generator" className="data-[state=active]:bg-purple-600">
              Password Generator
            </TabsTrigger>
            <TabsTrigger value="vault" className="data-[state=active]:bg-purple-600">
              Secure Vault
            </TabsTrigger>
          </TabsList>

          <TabsContent value="generator" className="space-y-6">
            <div className="grid gap-6 lg:grid-cols-2">
              {/* Password Generation Settings */}
              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">Generator Settings</CardTitle>
                  <CardDescription className="text-slate-300">
                    Customize your password requirements
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  {/* Password Length */}
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
                    <div className="flex justify-between text-xs text-slate-400">
                      <span>4</span>
                      <span>128</span>
                    </div>
                  </div>

                  <Separator className="bg-slate-700" />

                  {/* Character Options */}
                  <div className="space-y-4">
                    <Label className="text-sm font-medium text-white">Character Types</Label>
                    
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <Label htmlFor="uppercase" className="text-sm text-slate-300">
                          Uppercase Letters (A-Z)
                        </Label>
                        <Switch
                          id="uppercase"
                          checked={includeUppercase}
                          onCheckedChange={setIncludeUppercase}
                        />
                      </div>

                      <div className="flex items-center justify-between">
                        <Label htmlFor="lowercase" className="text-sm text-slate-300">
                          Lowercase Letters (a-z)
                        </Label>
                        <Switch
                          id="lowercase"
                          checked={includeLowercase}
                          onCheckedChange={setIncludeLowercase}
                        />
                      </div>

                      <div className="flex items-center justify-between">
                        <Label htmlFor="numbers" className="text-sm text-slate-300">
                          Numbers (0-9)
                        </Label>
                        <Switch
                          id="numbers"
                          checked={includeNumbers}
                          onCheckedChange={setIncludeNumbers}
                        />
                      </div>

                      <div className="flex items-center justify-between">
                        <Label htmlFor="symbols" className="text-sm text-slate-300">
                          Symbols (!@#$%...)
                        </Label>
                        <Switch
                          id="symbols"
                          checked={includeSymbols}
                          onCheckedChange={setIncludeSymbols}
                        />
                      </div>

                      <div className="flex items-center justify-between">
                        <Label htmlFor="exclude-similar" className="text-sm text-slate-300">
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

              {/* Generated Password Display */}
              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">Generated Password</CardTitle>
                  <CardDescription className="text-slate-300">
                    Your secure password is ready
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  {/* Password Display */}
                  <div className="space-y-3">
                    <div className="relative">
                      <Input
                        type={showPassword ? "text" : "password"}
                        value={generatedPassword}
                        readOnly
                        className="pr-20 bg-slate-900 border-slate-600 text-white font-mono text-lg"
                      />
                      <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => setShowPassword(!showPassword)}
                          className="h-8 w-8 p-0 text-slate-400 hover:text-white"
                        >
                          {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </Button>
                      </div>
                    </div>

                    {/* Strength Meter */}
                    <div className="space-y-2">
                      <div className="flex justify-between items-center">
                        <Label className="text-sm text-slate-300">Strength</Label>
                        <Badge variant="outline" className={`${strengthInfo.color} text-white border-0`}>
                          {strengthInfo.label}
                        </Badge>
                      </div>
                      <div className="w-full bg-slate-700 rounded-full h-2">
                        <div
                          className={`h-2 rounded-full transition-all duration-300 ${strengthInfo.color}`}
                          style={{ width: `${passwordStrength}%` }}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex gap-2">
                    <Button 
                      onClick={generatePassword} 
                      className="flex-1 bg-purple-600 hover:bg-purple-700"
                    >
                      <RefreshCw className="h-4 w-4 mr-2" />
                      Generate New
                    </Button>
                    <Button 
                      onClick={copyToClipboard}
                      variant="outline"
                      className="flex-1 border-slate-600 text-white hover:bg-slate-700"
                    >
                      {copied ? (
                        <CheckCircle className="h-4 w-4 mr-2 text-green-500" />
                      ) : (
                        <Copy className="h-4 w-4 mr-2" />
                      )}
                      {copied ? 'Copied!' : 'Copy'}
                    </Button>
                  </div>

                  {/* Security Notice */}
                  <div className="bg-slate-900 border border-slate-700 rounded-lg p-3">
                    <p className="text-xs text-slate-400">
                      🔒 <span className="font-medium">Security Note:</span> This password is generated locally in your browser. 
                      When copied, it will automatically be cleared from your clipboard after 15 seconds.
                    </p>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="vault" className="space-y-6">
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Secure Vault</CardTitle>
                <CardDescription className="text-slate-300">
                  Coming soon! Store and manage your passwords with client-side encryption.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-center py-8">
                  <Shield className="h-16 w-16 text-purple-400 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-white mb-2">Vault Under Development</h3>
                  <p className="text-slate-400">
                    Authentication and encrypted storage features will be available soon.
                  </p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}

export default PasswordGenerator