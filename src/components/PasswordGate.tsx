'use client'

import { useState, useEffect } from 'react'
import { Button } from './ui/button'

interface PasswordGateProps {
    password: string
    postId: string
    children: React.ReactNode
}

export default function PasswordGate({
    password,
    postId,
    children,
}: PasswordGateProps) {
    const [inputPassword, setInputPassword] = useState('')
    const [isUnlocked, setIsUnlocked] = useState(false)
    const [error, setError] = useState('')
    const [showPassword, setShowPassword] = useState(false)

    const storageKey = `post-unlocked-${postId}`

    useEffect(() => {
        // Check if post is already unlocked
        const unlocked = sessionStorage.getItem(storageKey)
        if (unlocked === 'true') {
            setIsUnlocked(true)
        }
    }, [postId, storageKey])

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault()

        if (inputPassword === password) {
            setIsUnlocked(true)
            sessionStorage.setItem(storageKey, 'true')
            setError('')
        } else {
            setError('Incorrect password. Please try again.')
            setInputPassword('')
        }
    }

    if (isUnlocked) {
        return <>{children}</>
    }

    return (
        <div className="col-start-2 flex min-h-[400px] items-center justify-center">
            <div className="bg-card text-card-foreground border-border w-full max-w-md rounded-lg border p-8 shadow-lg">
                <div className="mb-6 flex flex-col items-center gap-3">
                    <div className="bg-primary/10 text-primary flex h-16 w-16 items-center justify-center rounded-full">
                        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
                            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                        </svg>
                    </div>
                    <h2 className="text-2xl font-semibold">Password Protected</h2>
                    <p className="text-muted-foreground text-center text-sm">
                        This article is password protected. Please enter the password to
                        continue.
                    </p>
                </div>

                <form onSubmit={handleSubmit} className="space-y-4">
                    <div className="relative">
                        <input
                            type={showPassword ? 'text' : 'password'}
                            value={inputPassword}
                            onChange={(e) => {
                                setInputPassword(e.target.value)
                                setError('')
                            }}
                            placeholder="Enter password"
                            className="border-input bg-background ring-offset-background placeholder:text-muted-foreground focus-visible:ring-ring flex h-10 w-full rounded-md border px-3 py-2 pr-10 text-sm file:border-0 file:bg-transparent file:text-sm file:font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                            autoFocus
                        />
                        <button
                            type="button"
                            onClick={() => setShowPassword(!showPassword)}
                            className="text-muted-foreground hover:text-foreground absolute right-3 top-1/2 -translate-y-1/2 transition-colors"
                            aria-label={showPassword ? 'Hide password' : 'Show password'}
                        >
                            {showPassword ? (
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24" />
                                    <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" />
                                    <path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61" />
                                    <line x1="2" x2="22" y1="2" y2="22" />
                                </svg>
                            ) : (
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" />
                                    <circle cx="12" cy="12" r="3" />
                                </svg>
                            )}
                        </button>
                    </div>

                    {error && (
                        <div className="bg-destructive/10 text-destructive flex items-center gap-2 rounded-md border border-red-200 p-3 text-sm">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="shrink-0">
                                <circle cx="12" cy="12" r="10" />
                                <line x1="12" x2="12" y1="8" y2="12" />
                                <line x1="12" x2="12.01" y1="16" y2="16" />
                            </svg>
                            <span>{error}</span>
                        </div>
                    )}

                    <Button type="submit" className="w-full">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="mr-2">
                            <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
                            <path d="M7 11V7a5 5 0 0 1 9.9-1" />
                        </svg>
                        Unlock Article
                    </Button>
                </form>

                <div className="text-muted-foreground mt-4 text-center text-xs">
                    <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="mr-1 inline-block align-middle">
                        <circle cx="12" cy="12" r="10" />
                        <path d="M12 16v-4" />
                        <path d="M12 8h.01" />
                    </svg>
                    <span className="align-middle">
                        Your password will be remembered for this browser session
                    </span>
                </div>
            </div>
        </div>
    )
}
