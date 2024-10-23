'use client'

import { useState } from 'react'
import { Folder } from 'lucide-react'

interface SidebarProps {
  folders: string[]
}

export default function Sidebar({ folders }: SidebarProps) {
  const [activeFolder, setActiveFolder] = useState<string | null>(null)

  return (
    <nav className="w-64 bg-gray-100 p-4">
      <h2 className="text-lg font-semibold mb-4">Folders</h2>
      <ul className="space-y-2">
        {folders.map((folder) => (
          <li key={folder}>
            <button
              className={`flex items-center w-full p-2 rounded-md transition-colors ${
                activeFolder === folder
                  ? 'bg-blue-500 text-white'
                  : 'hover:bg-gray-200'
              }`}
              onClick={() => setActiveFolder(folder)}
            >
              <Folder className="mr-2 h-5 w-5" />
              {folder}
            </button>
          </li>
        ))}
      </ul>
    </nav>
  )
}