"use client"; // 确保这是一个客户端组件

export default function ContactPage() {
  return (
    <div className="container mx-auto py-12 px-4">
      <h1 className="text-4xl font-bold mb-6">联系我们</h1>
      <p className="mb-4">如果您有任何想法或建议，欢迎随时联系我们：</p>
      <div className="mb-6">
        <p>
          <strong>站长邮箱:</strong> 
          <a href="mailto:gettianguyin@gmail.com" className="text-orange-500"> gettianguyin@gmail.com</a>
        </p>
        <p>
          <strong>云音计划委员会邮箱:</strong> 
          <a href="mailto:mail@tiangucloud.org" className="text-orange-500"> mail@tiangucloud.org</a>
        </p>
      </div>
      <p className="text-gray-700">
        我们期待与您合作，您的反馈对我们非常重要！
      </p>
    </div>
  );
}
