"use client"; // 确保这是一个客户端组件

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import Link from "next/link";

export default function EventsPage() {
  const [eventData, setEventData] = useState<any[]>([]); // 存储比赛数据
  const [currentPage, setCurrentPage] = useState(1); // 当前页
  const eventsPerPage = 6; // 每页显示的比赛数量

  useEffect(() => {
    const fetchEventData = async () => {
      try {
        const response = await fetch("https://raw.githubusercontent.com/ProbiusOfficial/Hello-CTFtime/main/CN.json");
        const res = await response.json();
        if (res.success && res.data && Array.isArray(res.data.result)) {
          setEventData(res.data.result);
        } else {
          console.error("获取的数据中没有有效的结果:", res);
        }
      } catch (error) {
        console.error("获取比赛数据失败:", error);
      }
    };

    fetchEventData();
  }, []);

  // 计算当前页显示的比赛
  const indexOfLastEvent = currentPage * eventsPerPage;
  const indexOfFirstEvent = indexOfLastEvent - eventsPerPage;
  const currentEvents = eventData.slice(indexOfFirstEvent, indexOfLastEvent);

  // 计算页码数量
  const pageCount = Math.ceil(eventData.length / eventsPerPage);

  return (
    <div className="container mx-auto py-12">
      <div className="flex items-end mb-8">
        <h1 className="text-4xl font-bold">比赛列表</h1>
        <h2 className="mb-0 ml-3">数据来源 hello-ctf</h2>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {currentEvents.map((event, index) => (
          <Card key={index} className="bg-white shadow-lg">
            <CardHeader>
              <CardTitle className="text-2xl text-orange-500">{event.name}</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="mb-2"><strong>形式:</strong> {event.type}</p>
              <p className="mb-2"><strong>比赛时间:</strong> {event.comp_time_start} - {event.comp_time_end}</p>
              <p className="mb-2"><strong>报名时间:</strong> {event.reg_time_start} - {event.reg_time_end}</p>
              <p className="mb-2"><strong>比赛状态:</strong> {event.status}</p>
              <Link href={event.link} className="inline-block bg-orange-500 hover:bg-orange-600 text-white font-bold py-2 px-4 rounded transition-colors text-lg">
                参加比赛
              </Link>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* 分页 */}
      <div className="flex justify-center mt-8">
        {Array.from({ length: pageCount }, (_, index) => (
          <button
            key={index + 1}
            onClick={() => setCurrentPage(index + 1)}
            className={`mx-2 py-1 px-3 rounded ${currentPage === index + 1 ? 'bg-orange-500 text-white' : 'bg-white text-orange-500 hover:bg-orange-100'}`}
          >
            {index + 1}
          </button>
        ))}
      </div>
    </div>
  );
}
