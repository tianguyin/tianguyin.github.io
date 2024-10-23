// src/components/ui/card.tsx
import React from 'react';

interface CardProps {
  children: React.ReactNode;
  className?: string;
}
interface CardTitleProps {
  children: React.ReactNode;
  className?: string; // 添加 className 属性
}


export const Card: React.FC<CardProps> = ({ children, className }) => {
  return <div className={`shadow-lg p-6 bg-white rounded-lg ${className}`}>{children}</div>;
};

export const CardHeader: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return <div className="border-b pb-4 mb-4">{children}</div>;
};

export const CardTitle: React.FC<CardTitleProps> = ({ children, className }) => {
  return <h2 className={`text-xl font-bold ${className}`}>{children}</h2>; // 将 className 添加到 JSX
};


export const CardContent: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return <div>{children}</div>;
};
