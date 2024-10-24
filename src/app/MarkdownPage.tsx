'use client'

import { useState, useEffect } from 'react'
import { ChevronRight, ChevronDown, Menu, X } from 'lucide-react'
import { marked } from 'marked'

import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Skeleton } from '@/components/ui/skeleton'

interface NavItem {
  type: string
  path: string
  markdown?: string
}

export default function DynamicNavigation() {
  const [navItems, setNavItems] = useState<NavItem[]>([])
  const [selectedType, setSelectedType] = useState<string | null>(null)
  const [content, setContent] = useState<string>('')
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [isMobileNavOpen, setIsMobileNavOpen] = useState(false)

  useEffect(() => {
    fetchNavItems()
  }, [])

  const fetchNavItems = async () => {
    try {
      setIsLoading(true)
      const response = await fetch('/markdown.json')
      const data: NavItem[] = await response.json()
      setNavItems(data)
    } catch (error) {
      console.error('Error fetching nav items:', error)
      setError('Failed to load navigation items. Please try again later.')
    } finally {
      setIsLoading(false)
    }
  }

  const fetchContent = async (path: string, markdown: string) => {
    try {
      setIsLoading(true)
      const response = await fetch(`${path}/${markdown}.md`)
      const data = await response.text()
      const htmlContent = marked(data)
      setContent(await htmlContent)
    } catch (error) {
      console.error('Error fetching content:', error)
      setError('Failed to load content. Please try again later.')
    } finally {
      setIsLoading(false)
    }
  }

  const handleTypeClick = (type: string) => {
    setSelectedType(type === selectedType ? null : type)
  }

  const handleSubItemClick = (path: string, markdown: string) => {
    fetchContent(path, markdown)
    setIsMobileNavOpen(false)
  }

  const groupedNavItems = navItems.reduce((acc, item) => {
    if (!acc[item.type]) {
      acc[item.type] = []
    }
    acc[item.type].push(item)
    return acc
  }, {} as Record<string, NavItem[]>)

  return (
    <div className="flex flex-col h-screen bg-white-100 w-100">
      <header className="bg-white-0 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <h1 className="text-2xl font-bold text-gray-900">C?CTF!</h1>
            <Button
              variant="ghost"
              size="icon"
              className="lg:hidden"
              onClick={() => setIsMobileNavOpen(!isMobileNavOpen)}
            >
              {isMobileNavOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
              <span className="sr-only">Toggle navigation menu</span>
            </Button>
          </div>
        </div>
      </header>

      <div className="flex-1 flex overflow-hidden">
        <main className="flex-1 overflow-y-auto p-6">
          <div className="max-w-3xl mx-auto">
            {isLoading ? (
              <div className="space-y-4">
                <Skeleton className="h-8 w-3/4" />
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-5/6" />
                <Skeleton className="h-4 w-4/5" />
              </div>
            ) : error ? (
              <div className="text-center text-red-600">{error}</div>
            ) : content ? (
              <article className="prose max-w-none" dangerouslySetInnerHTML={{ __html: content }} />
            ) : (
              <p className="text-center text-white-500">
                <img src='/logo.png'></img>
              </p>
            )}
          </div>
        </main>

        <nav
          className={`w-64 bg-white-0 shadow-md overflow-y-auto transition-transform duration-300 ease-in-out ${
            isMobileNavOpen ? 'translate-x-0' : 'translate-x-full'
          } lg:translate-x-0`}
        >
          <ScrollArea className="h-full">
            <div className="p-4">
              <h2 className="text-lg font-semibold mb-4 text-gray-900">知识库</h2>
              {isLoading ? (
                <div className="space-y-2">
                  <Skeleton className="h-6 w-full" />
                  <Skeleton className="h-6 w-5/6" />
                  <Skeleton className="h-6 w-4/5" />
                </div>
              ) : (
                <ul className="space-y-2">
                  {Object.entries(groupedNavItems).map(([type, items]) => (
                    <li key={type}>
                      <button
                        className="flex items-center w-full p-2 rounded-md hover:bg-orange-100 transition-colors text-gray-700 font-medium"
                        onClick={() => handleTypeClick(type)}
                        aria-expanded={selectedType === type}
                      >
                        {selectedType === type ? (
                          <ChevronDown className="mr-2 h-4 w-4 text-orange-500" />
                        ) : (
                          <ChevronRight className="mr-2 h-4 w-4 text-orange-500" />
                        )}
                        {type}
                      </button>
                      {selectedType === type && (
                        <ul className="ml-6 mt-2 space-y-1">
                          {items.map((item, index) => {
                            const subItems = item.markdown?.split(',') || []
                            return subItems.map((subItem, subIndex) => (
                              <li key={`${index}-${subIndex}`}>
                                <button
                                  className="flex items-center w-full p-2 rounded-md hover:bg-orange-100 transition-colors text-sm text-gray-600"
                                  onClick={() => handleSubItemClick(item.path, subItem.trim())}
                                >
                                  {subItem.trim()}
                                </button>
                              </li>
                            ))
                          })}
                        </ul>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </ScrollArea>
        </nav>
      </div>
    </div>
  )
}