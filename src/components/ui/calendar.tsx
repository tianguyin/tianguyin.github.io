"use client"; // 确保这是一个客户端组件

import React, { useEffect, useState } from 'react';

// 获取当前月份的所有日期
const getDaysInMonth = (year: number, month: number) => {
    const date = new Date(year, month, 1);
    const days: Date[] = [];
    while (date.getMonth() === month) {
        days.push(new Date(date));
        date.setDate(date.getDate() + 1);
    }
    return days;
};

// 获取当月的第一天是星期几
const getFirstDayOfMonth = (year: number, month: number) => {
    const date = new Date(year, month, 1);
    return date.getDay(); // 返回0-6（星期日到星期六）
};

export const Calendar: React.FC = () => {
    const today = new Date();
    const [currentDate, setCurrentDate] = useState(new Date());
    const [popupVisible, setPopupVisible] = useState(false);
    const [selectedDate, setSelectedDate] = useState<Date | null>(null);
    const [eventData, setEventData] = useState<any[]>([]);
    const [popupMessage, setPopupMessage] = useState<string>('');

    useEffect(() => {
        const fetchEventData = async () => {
            try {
                const response = await fetch("https://raw.githubusercontent.com/ProbiusOfficial/Hello-CTFtime/main/CN.json");
                const res = await response.json();
                if (res.success && res.data && Array.isArray(res.data.result)) {
                    setEventData(res.data.result);
                } else {
                    console.error("获取的数据中没有有效的结果:", res);
                    setEventData([]);
                }
            } catch (error) {
                console.error("获取比赛数据失败:", error);
                setEventData([]);
            }
        };
    
        fetchEventData();
    }, []);

    const handlePrevMonth = () => {
        const newDate = new Date(currentDate);
        newDate.setMonth(newDate.getMonth() - 1);
        setCurrentDate(newDate);
    };

    const handleNextMonth = () => {
        const newDate = new Date(currentDate);
        newDate.setMonth(newDate.getMonth() + 1);
        setCurrentDate(newDate);
    };

    const daysInMonth = getDaysInMonth(currentDate.getFullYear(), currentDate.getMonth());
    const firstDayOfMonth = getFirstDayOfMonth(currentDate.getFullYear(), currentDate.getMonth());
    const [ongoingEvents, setOngoingEvents] = useState<any[]>([]); // 新增状态管理进行中的比赛
    const handleDateClick = (date: Date) => {
        setSelectedDate(date);

        const ongoingEvents = eventData.filter(event => {
            let compStartTime = event.comp_time_start;
            const regex = /(\d{4})年(\d{2})月(\d{2})日 (\d{2}:\d{2})/;
            const matches = compStartTime.match(regex);
            if (matches) {
                const year = parseInt(matches[1], 10);
                const month = parseInt(matches[2], 10) - 1; // 月份从0开始
                const day = parseInt(matches[3], 10);
                const time = matches[4];
            
                // 创建新的 Date 对象
                compStartTime = new Date(year, month, day, ...time.split(':').map(Number));
            

            } else {
                console.error("日期格式不正确");
            }
            if (date.toDateString() === compStartTime.toDateString()) {
                const even = event; // 取第一个进行中的比赛
                setPopupMessage(''); // 清空消息
                setPopupVisible(true); // 显示弹窗
            } else {
                setPopupMessage('今天没有比赛哦'); // 设置无比赛消息
                setPopupVisible(true); // 显示弹窗
            }
        });

        
    };

    const handleClosePopup = () => {
        setPopupVisible(false); // 隐藏弹窗
    };

    const handleOverlayClick = (event: React.MouseEvent<HTMLDivElement>) => {
        if (event.currentTarget === event.target) {
            handleClosePopup();
        }
    };

    return (
        <div className="calendar">
            <div className="calendar-header">
                <button onClick={handlePrevMonth}>Previous</button>
                <h2>{currentDate.toLocaleString('default', { month: 'long' })} {currentDate.getFullYear()}</h2>
                <button onClick={handleNextMonth}>Next</button>
            </div>
            <div className="calendar-grid">
                {/* 渲染星期标题 */}
                <div className="calendar-weekdays">
                    {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map((day) => (
                        <div key={day} className="calendar-day-name">{day}</div>
                    ))}
                </div>
                {/* 渲染空格 */}
                {Array.from({ length: firstDayOfMonth }).map((_, index) => (
                    <div key={index} className="calendar-day empty"></div>
                ))}
                {/* 渲染日期 */}
                {daysInMonth.map((date) => {
                    const isToday = date.toDateString() === today.toDateString(); // 判断是否是今天
                    const ongoingEventsCount = eventData.filter(event => {
                        const compStartTime = new Date(event.comp_time_start);
                        const compEndTime = new Date(event.comp_time_end);
                        return date >= compStartTime && date <= compEndTime && event.status === "进行中";
                    }).length;

                    return (
                        <div
                            key={date.toString()}
                            className={`calendar-day ${isToday ? 'today' : ''}`}
                            onClick={() => handleDateClick(date)}
                        >
                            {date.getDate()}
                            {ongoingEventsCount > 0 && <span className="event-count">({ongoingEventsCount})</span>} {/* 显示比赛数量 */}
                        </div>
                    );
                })}
            </div>

            {popupVisible && (
                <div className="popup" onClick={handleOverlayClick}>
                    <div className="popup-content">
                        <p>{popupMessage}</p>
                        {selectedDate && ongoingEvents.length > 0 && (
                            <>
                                <h3>{ongoingEvents[0].name}</h3>
                                <p><strong>比赛形式:</strong> {ongoingEvents[0].type}</p>
                                <p><strong>比赛日期:</strong> {ongoingEvents[0].comp_time_start} - {ongoingEvents[0].comp_time_end}</p>
                                <p>
                                    <strong>比赛链接:</strong> <a href={ongoingEvents[0].link} target="_blank" rel="noopener noreferrer">点击打开</a>
                                </p>
                                <p><strong>主办方:</strong> {ongoingEvents[0].organizer || "未提供"}</p>
                                <p><strong>比赛状态:</strong> {ongoingEvents[0].status}</p>
                                <p><strong>更多信息:</strong> {ongoingEvents[0].readmore}</p>
                            </>
                        )}
                        <button onClick={handleClosePopup}>Close</button>
                    </div>
                </div>
            )}
        </div>
    );
};