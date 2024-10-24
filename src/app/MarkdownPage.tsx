'use client';

import { useState, useEffect } from 'react';
import { ChevronRight, ChevronDown } from 'lucide-react';
import { marked } from 'marked'; // 引入 marked 库

interface NavItem {
  type: string;
  path: string;
  markdown?: string;
}

export default function DynamicNavigation() {
  const [navItems, setNavItems] = useState<NavItem[]>([]);
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [content, setContent] = useState<string>('');

  useEffect(() => {
    fetchNavItems();
  }, []);

  const fetchNavItems = async () => {
    try {
      const response = await fetch('/markdown.json');
      const data: NavItem[] = await response.json();
      console.log(data);
      setNavItems(data);
    } catch (error) {
      console.error('Error fetching nav items:', error);
    }
  };

  const fetchContent = async (path: string, markdown: string) => {
    try {
      const response = fetch(path + markdown);
      const data = (await response).text();
      const htmlContent = marked(await data); // 将 Markdown 转换为 HTML
      setContent(await htmlContent); // 直接设置 htmlContent
    } catch (error) {
      console.error('Error fetching content:', error);
    }
  };
  

  const handleTypeClick = (type: string) => {
    setSelectedType(type === selectedType ? null : type);
  };

  const handleSubItemClick = (path: string, markdown: string) => {
    fetchContent(path, "/" + markdown + ".md");
  };

  const groupedNavItems = navItems.reduce((acc, item) => {
    if (!acc[item.type]) {
      acc[item.type] = [];
    }
    acc[item.type].push(item);
    return acc;
  }, {} as Record<string, NavItem[]>);

  return (
    <div className="flex h-screen">
        <div className='w-64'></div>
        <div className='w-64'></div>
        <div className='w-64'></div>
      <main className="flex-none p-0.00001 overflow-hidden">
        <div className="overflow-y-auto w-full">
          <div className="prose max-w-none">
            {content ? (
              <div dangerouslySetInnerHTML={{ __html: content }} />
            ) : (
              <p>Select a type from the navigation to view content.</p>
            )}
          </div>
        </div>
      </main>
      <div className='w-64'></div>
      <div className='w-64'></div>
      <div className='w-64'></div>
      <div className='w-64'></div>
      <div className='w-64'></div>
      <nav className="w-64 bg-white text-black-600 p-10 overflow-y-auto ml-auto">
        <h2 className="text-lg font-semibold mb-0 text-left">C?CTF!</h2>
        <ul className="space-y-2">
          {Object.entries(groupedNavItems).map(([type, items]) => (
            <li key={type}>
              <button
                className="flex items-center w-full p-2 rounded-md hover:bg-orange-500 transition-colors"
                onClick={() => handleTypeClick(type)}
              >
                {selectedType === type ? (
                  <ChevronDown className="mr-2 h-4 w-4" />
                ) : (
                  <ChevronRight className="mr-2 h-4 w-4" />
                )}
                {type}
              </button>
              {selectedType === type && (
                <ul className="ml-6 mt-2 space-y-1">
                  {items.map((item, index) => {
                    const subItems = item.markdown?.split(',') || [];
                    return subItems.map((subItem, subIndex) => (
                      <li key={`${index}-${subIndex}`}>
                        <button
                          className="flex items-center w-full p-2 rounded-md hover:bg-orange-500 transition-colors text-sm"
                          onClick={() => handleSubItemClick(item.path, subItem.trim())}
                        >
                          {subItem.trim()} {/* 显示子项 */}
                        </button>
                      </li>
                    ));
                  })}
                </ul>
              )}
            </li>
          ))}
        </ul>
      </nav>
    </div>
  );
}
