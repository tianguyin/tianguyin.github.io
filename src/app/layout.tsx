// src/app/layout.tsx
import React from 'react';
import './globals.css'; // 导入全局样式，如果有的话

export const metadata = {
  title: 'CTF.ICU',
};


export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
            <head>
        <link rel="icon" href="logo.png" type="image/png" />
      </head>
      <body>{children}</body>
    </html>
  );
}
