"use client"; // 确保这是一个客户端组件

import Link from "next/link"; // 确保导入 Link 组件
import { SetStateAction, useEffect, useState } from "react";
import { Flag } from "lucide-react";
import EventsPage from "./events"; // 导入 EventsPage 组件
import ContactPage from "./contact"; // 导入 ContactPage 组件
import MarkdownPage from "./MarkdownPage";


const slides = [
  {
    text: "欢迎来到 CTF.ICU",
    image: "yunyinctf.png", // 替换为你的图片路径
    link: "/", // 替换为要跳转的链接
  },
  {
    text: "举办比赛需要上云？",
    image: "dkdun.png", // 替换为你的图片路径
    link: "https://www.dkdun.cn/aff/UUPROCNL", // 替换为要跳转的链接
  },
  {
    text: "探索 Capture The Flag 的精彩世界",
    image: "ctf.png", // 替换为你的图片路径
    link: "https://ctficu.tiangucloud.org", // 替换为要跳转的链接
  },
  {
    text: "提升您的网络安全技能",
    image: "tianguyin.png", // 替换为你的图片路径
    link: "https://www.tianguyin.com", // 替换为要跳转的链接
  },
];

export default function Component() {
  const [currentPage, setCurrentPage] = useState("home"); // 管理当前页面状态
  const [animate, setAnimate] = useState(false); // 管理动画状态
  const [currentSlide, setCurrentSlide] = useState(0); // 当前幻灯片索引
  const [intervalId, setIntervalId] = useState<NodeJS.Timeout | null>(null); // 存储定时器 ID

  const handlePageChange = (page: SetStateAction<string>) => {
    setAnimate(true);
    if (intervalId) {
      clearInterval(intervalId); // 清除幻灯片定时器
    }
    
    setTimeout(() => {
      setCurrentPage(page);
      setAnimate(false);

      // 如果返回主页，则重新启动幻灯片播放
      if (page === "home") {
        startSlideShow();
      }
    }, 1000); // 动画持续时间与 CSS 相同
  };

  const startSlideShow = () => {
    const newIntervalId = setInterval(() => {
      setAnimate(true);
      setTimeout(() => {
        setCurrentSlide((prev) => (prev + 1) % slides.length);
        setAnimate(false);
      }, 300); // 动画持续时间
    }, 5000); // 每3秒切换一次

    setIntervalId(newIntervalId); // 保存新的定时器 ID
  };

  const handleImageClick = (link: string) => {
    // 点击图片时跳转
    window.location.href = link; // 使用 window.location.href 跳转
  };

  useEffect(() => {
    // 初始化幻灯片播放
    startSlideShow();
    
    return () => {
      if (intervalId) {
        clearInterval(intervalId); // 清除定时器
      }
    }; // 清除定时器
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-b from-orange-100 to-pink-100 text-gray-800 flex flex-col transition-all duration-300 ease-in-out">
      {/* 导航栏 */}
      <nav className="flex items-center justify-between p-6 bg-white shadow-md">
      <div className="flex items-center">
        <Link href="/" className="flex items-center"> {/* 设置跳转链接 */}
          <img src="logo.png" alt="云音计划 Logo" className="h-12 w-12 mr-2" />
          <span className="text-2xl font-bold text-orange-500">云音计划</span>
        </Link>
        </div>
        <div className="flex space-x-4">
          <a 
            onClick={() => handlePageChange("home")} 
            className="hover:bg-orange-300 transition duration-300 cursor-pointer px-3 py-2 rounded"
          >
            主页
          </a>
          <a 
            onClick={() => handlePageChange("events")} 
            className="hover:bg-orange-300 transition duration-300 cursor-pointer px-3 py-2 rounded"
          >
            比赛列表
          </a>
          <a onClick={() => handlePageChange("markdown")} 
                        className="hover:bg-orange-300 transition duration-300 cursor-pointer px-3 py-2 rounded"
            >知识库
            </a> {/* 添加Markdown页面链接 */}
          <a 
            onClick={() => handlePageChange("contact")} 
            className="hover:bg-orange-300 transition duration-300 cursor-pointer px-3 py-2 rounded"
          >
            联系我们
          </a>
        </div>
      </nav>

      <main className="flex-1 flex flex-col items-center justify-center p-12">
        <header className="py-6 flex items-center justify-center">
          <Flag className="h-10 w-10 text-orange-500" />
          <span className="text-4xl font-bold text-orange-500 ml-2">云音计划</span>
        </header>

        {/* 动画容器 */}
        <div className={`transition-all duration-300 ease-in-out ${animate ? 'transform translate-x-full opacity-0' : 'transform translate-x-0 opacity-100'}`}>
          {/* 根据当前页面状态显示内容 */}
          {currentPage === "home" && (
            <section className="text-center">
              <div className="bg-white rounded-lg shadow-lg p-6 max-w-md mx-auto cursor-pointer" onClick={() => handleImageClick(slides[currentSlide].link)}>
                <h1 className="text-2xl font-bold">{slides[currentSlide].text}</h1>
                <img src={slides[currentSlide].image} alt={slides[currentSlide].text} className="mt-4 w-full h-auto rounded-lg" />
              </div>
            </section>
          )}

          {/* 嵌入 EventsPage 组件 */}
          {currentPage === "events" && <EventsPage />}
          {/* 嵌入 ContactPage 组件 */}
          {currentPage === "contact" && <ContactPage />}
          {currentPage === "markdown" && <MarkdownPage />} {/* 添加Markdown页面的条件渲染 */}
        </div>
      </main>

      <footer className="text-black text-center py-4 mt-6">
        <p className="text-sm">
          © {new Date().getFullYear()} 云音计划委员会 保留所有权利.
        </p>
      </footer>
    </div>
  );
}
